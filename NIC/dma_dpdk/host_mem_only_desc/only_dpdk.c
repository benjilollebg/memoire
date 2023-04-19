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
#include <../../../utils/port_init.h>
#include <../../../utils/receive_data_from_host.h>

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
static uint32_t nb_core = 7;		/* The number of Core working (max 7) */

struct descriptor
{
	uint32_t                ip_src;
        uint32_t                ip_dst;
	uint64_t 		timestamp;
	bool                    full;
};
//attribute packed
struct arguments
{
	struct doca_pci_bdf*	pcie_addr;
	uint16_t 		port;
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
job(void* arg)
{
	// args
	struct arguments* args = (struct arguments*) arg;
	uint16_t port = args->port;
	int result;

	// RING
	uint64_t pos = 0;
	char* ring;
	size_t size;

	// Data
	struct timeval stop, start;
	bool has_received_first_packet = false;

	signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);

	struct rte_mbuf* rte_mbufs[BURST_SIZE];

	uint64_t counter = 0;
	uint64_t threshold = 0;
	uint64_t timestamp = 0;
	uint64_t old_pos = 0;
	uint64_t new_pos = 0;

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

			return result;
		}

		/* DPDK : Get burst of RX packets from the port */
                const uint16_t nb_rx = rte_eth_rx_burst(port, rte_lcore_id() - 1, rte_mbufs, BURST_SIZE);

                if (nb_rx == 0)
                        continue;

                /* Data : Start the timer */
                if (counter > 0 && !has_received_first_packet)
                {
                        gettimeofday(&start, NULL);
                        has_received_first_packet = true;
                }


		if (counter > threshold){
			printf("Core %d, counter : %lu\n", rte_lcore_id(), counter);
			threshold += 100000;
		}

		for (int i = 0; i < nb_rx; i++){
			counter++;
			timestamp++;

                        /* Free the mbuf */
                        rte_pktmbuf_free(rte_mbufs[i]);
		}
	}
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
	struct arguments args;

	// DOCA
        struct doca_pci_bdf pcie_dev;
        int result;

	// DPDK
	struct rte_mempool *mbuf_pool;
        uint16_t lcore_id;
        uint16_t portid;
        uint16_t port;

	printf("size : %ld\n",  sizeof(struct descriptor));

	/* DPDK : Initializion the Environment Abstraction Layer (EAL) */
        result = rte_eal_init(argc, argv);
        if (result < 0)
                rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

        argc -= result;
        argv += result;

	printf("Number of core enabled : %d\n", nb_core);


	/* DPDK : Initialize the MAC address to read the data (p0) */
        struct rte_ether_addr macAddr1;

        macAddr1.addr_bytes[0]=0x08;
        macAddr1.addr_bytes[1]=0xC0;
        macAddr1.addr_bytes[2]=0xEB;
        macAddr1.addr_bytes[3]=0xD1;
        macAddr1.addr_bytes[4]=0xFB;
        macAddr1.addr_bytes[5]=0x2A;

        /* DPDK : Creates a new mempool in memory to hold the mbufs. */
        mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", nb_core * NUM_MBUFS,
                MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
        if (mbuf_pool == NULL)
                rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

        /* DPDK Initializing the desired port. */
        RTE_ETH_FOREACH_DEV(portid){

                /* Display the port MAC address. */
                struct rte_ether_addr addr;
                int retval = rte_eth_macaddr_get(portid, &addr);
                if (retval != 0)
                        return retval;

                /* Only init the desired port (depending on the specified MAC address) */
                if(memcmp(&addr, &macAddr1, 6) == 0){
                        if (port_init(portid, mbuf_pool, nb_core) != 0)
                                rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",portid);
                        port = portid;
                        printf("Port receiving data : %d\n",port);
                }
        }

	args.port = port;

	/* MAIN : polling each queue on a lcore */
        RTE_LCORE_FOREACH_WORKER(lcore_id)
        {
		if(lcore_id <= nb_core)
			rte_eal_remote_launch(job, &args, lcore_id);
        }

	rte_eal_mp_wait_lcore();

	/* DPDK : clean up the EAL */
        rte_eal_cleanup();

        return EXIT_SUCCESS;
}
