/*
 * Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <pthread.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <getopt.h>
#include <stdarg.h>

#include <signal.h>
#include "utils.h"
#include <../../../utils/set_dma_buffer.h>

// DOCA

#include <doca_argp.h>
#include <doca_dev.h>
#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_dma.h>
#include <doca_error.h>
#include <doca_log.h>

#include "dma_common.h"

DOCA_LOG_REGISTER(MAIN);


//#define SLEEP_IN_NANOS (10 * 1000)	/* Sample the job every 10 microseconds  */
#define SLEEP_IN_NANOS (100)  		/* Sample the job every 10 nanocroseconds  */
#define RECV_BUF_SIZE 256		/* Buffer which contains config information */


#define WORKQ_DEPTH 1024		/* Work queue depth : MAY CAUSE CRASH IF TOO LOW (be cause we don't wait for termination)
					 * if WORKQ_DEPTH < DESCRIPTOR_NB, too many dma jobs may saturate the queue
					 * /!\ REDEFINITION of value defined in dma_common.h /!\
					 */


#define IP "192.168.100.1"
#define PORT 6660
#define PCIE_ADDR "03:00.0"

// DPDK

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE 1024		/* The size of each RX queue */

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 256			/* Has to be lower than the number of descriptor in the ring */
#define DESCRIPTOR_NB 2048 		/* The number of descriptor in the ring (MAX uint16_t max val or change head-tail type) */
#define NB_PORTS 1

static volatile bool force_quit = false;
static uint32_t nb_core = 2;		/* The number of Core working (max 7) */

pthread_mutex_t mutex;

struct descriptor
{
	volatile uint32_t       ip_src;
        volatile uint32_t       ip_dst;
        volatile uint64_t	timestamp;
	volatile bool           full;
}__attribute((packed))__;

struct arguments
{
	char* 			ring;
	size_t			size;
};

#define MAX_DMA_BUF_SIZE BURST_SIZE*sizeof(struct descriptor)       /* DMA buffer maximum size */

static void
signal_handler(int signum)
{
        if (signum == SIGINT || signum == SIGTERM) {
                printf("\n\nSignal %d received, preparing to exit\n", signum);
                force_quit = true;
        }
}

/*
 * Run DOCA DMA DPU copy sample
 *
 * @export_desc_file_path [in]: Export descriptor file path
 * @buffer_info_file_path [in]: Buffer info file path
 * @pcie_addr [in]: Device PCI address
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static int
nic(void* arg)
{
	// args
	struct arguments* args = (struct arguments*) arg;
	char* remote_ring = args->ring;
	size_t size = args->size;

	// DPDK
	char* ring = malloc(size);
	uint64_t pos = 0;

	// Data
	struct timeval stop, start;
	bool has_received_first_packet = false;

        printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n", rte_lcore_id());

	signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);

        struct descriptor* descriptors = (struct descriptor*) &ring[0];
	struct descriptor* remote_descriptors = (struct descriptor*) &remote_ring[0];

        uint64_t counter = 0;
        uint64_t threshold = 0;
        uint64_t timestamp = 0;
        uint64_t old_pos = 0;
        uint64_t new_pos = 0;

        srand( time( NULL ) );

        /* Main work of application loop */
        for (;;)
	{

		/* Quit the app on Control+C */
		if (force_quit)
		{
			printf("Exiting on core : %d\n", rte_lcore_id());

			printf("\nCore %u pos : %lu counter : %ld\n",
                                        rte_lcore_id(), pos, counter);

        		free(ring);

			return 0;
		}

		if (counter > threshold){
			printf("Core %d, counter : %lu\n", rte_lcore_id(), counter);
			threshold += 100000;
		}

//		uint16_t nb_rx = rand() % BURST_SIZE;
//               uint16_t nb_rx = BURST_SIZE;
		uint16_t nb_rx = 256;

                if (nb_rx == 0)
                        continue;

                old_pos = pos;
                new_pos = (pos + nb_rx - 1) % DESCRIPTOR_NB;

                while (descriptors[new_pos].full){

			if (force_quit)
                	{
				printf("descriptor old : %lu pos : %ld, full : %d\n", descriptors[new_pos].timestamp, new_pos, descriptors[new_pos].full);
				printf("descriptor new: %lu pos : %ld, full : 1\n", timestamp+1, new_pos);
				return 0;
			}

			memcpy(&descriptors[new_pos], &remote_descriptors[new_pos], sizeof(struct descriptor));
                }

                for (int i = 0; i < nb_rx; i++){
                        counter++;
                        timestamp++;

                        descriptors[pos].timestamp = timestamp;
			descriptors[pos].full = 1;
//pthread_mutex_lock(&mutex);
//			memcpy(&remote_descriptors[pos], &descriptors[pos], sizeof(struct descriptor));
//pthread_mutex_unlock(&mutex);
                        pos++;
                        if(pos == DESCRIPTOR_NB)
                                pos = 0;
                }

                /* Write the new descriptors in the dma buffer */
                if (old_pos + nb_rx <= DESCRIPTOR_NB)
                {
pthread_mutex_lock(&mutex);
			memcpy(&remote_descriptors[old_pos],
                                        &descriptors[old_pos], nb_rx * sizeof(struct descriptor));
pthread_mutex_unlock(&mutex);
                }
                else
                {
pthread_mutex_lock(&mutex);
			memcpy(&remote_descriptors[old_pos],
                                        &descriptors[old_pos], (DESCRIPTOR_NB - old_pos) * sizeof(struct descriptor));

			memcpy(&remote_descriptors[0], &descriptors[0],
                                        (old_pos + nb_rx - DESCRIPTOR_NB) * sizeof(struct descriptor));
pthread_mutex_unlock(&mutex);
                }
	}
}

static int
host(void* arg)
{
        // args
        struct arguments* args = (struct arguments*) arg;
        char* ring = args->ring;
        size_t size = args->size;

        int index;
        uint64_t counter = 0;
        uint64_t pos = 0;
        uint64_t timestamp = 0;
	volatile struct descriptor* descriptors = (struct descriptor*) &ring[0];

        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);

        /* Read the buffer */
        for(;;)
        {
                if (force_quit)
                {
                        printf("local timstamp : %ld\n", timestamp);
                        printf("descriptor : %lu pos : %ld, full : %d\n", descriptors[pos].timestamp, pos, descriptors[pos].full);
                        printf("descriptor+1 : %lu pos : %ld, full : %d\n", descriptors[pos +1].timestamp, pos +1 , descriptors[pos+1].full);
                        return 0;
                }
pthread_mutex_lock(&mutex);
                if(descriptors[pos].full == 1){

                        //printf("core %d, timestamp : %lu\n",rte_lcore_id(), descriptors[pos].timestamp);
                        counter++;
                        timestamp++;

                        if (descriptors[pos].timestamp != timestamp)
                        {
                                printf("Core %d : wrong timestamp at pos : %ld, expected : %lu, received : %lu\n",
                                        rte_lcore_id(), pos, timestamp, descriptors[pos].timestamp);

				sleep(1);

				printf("Core %d : wrong timestamp at pos : %ld, expected : %lu, received : %lu\n",
                                        rte_lcore_id(), pos, timestamp, descriptors[pos].timestamp);

                                return 1;
                        }

                        descriptors[pos].full = 0;

                        pos++;
                        if(pos == DESCRIPTOR_NB)
                                pos = 0;
                }
pthread_mutex_unlock(&mutex);
        }

        return 0;
}

/*
 * Sample main function
 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */
int
main(int argc, char **argv)
{
	// args
	struct arguments args[nb_core/2];

	// DOCA
        struct doca_pci_bdf pcie_dev;
        int result;
        char* rings[nb_core/2];
        size_t size = sizeof(struct descriptor) * DESCRIPTOR_NB;

	// DPDK
        uint16_t lcore_id;

pthread_mutex_init(&mutex, NULL);

 	/* DOCA : Allocate the rings */
        for (int i = 0; i < nb_core/2; i++)
        {
                rings[i] = (char *) malloc(size);
                if (rings[i] == NULL)
                {
                        DOCA_LOG_ERR("Ring buffer allocation failed");
                        return EXIT_FAILURE;
                }
                memset(rings[i], 0, size);

		args[i].ring = rings[i];
        	args[i].size = size;
        }

	/* DPDK : Initializion the Environment Abstraction Layer (EAL) */
        result = rte_eal_init(argc, argv);
        if (result < 0)
                rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

        argc -= result;
        argv += result;

	printf("Number of core enabled : %d\n", nb_core);

	/* MAIN : polling each queue on a lcore */
        RTE_LCORE_FOREACH_WORKER(lcore_id)
        {
		if(lcore_id <= nb_core){
			if(lcore_id %2 == 0)
				rte_eal_remote_launch(host, &args[0], lcore_id);
			else
				rte_eal_remote_launch(nic, &args[0], lcore_id);
		}
        }

	rte_eal_mp_wait_lcore();

	/* DPDK : clean up the EAL */
        rte_eal_cleanup();

        return EXIT_SUCCESS;
}
