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
static uint32_t nb_core = 7;		/* The number of Core working (max 7) */

struct descriptor
{
        volatile uint32_t                ip_src;
        volatile uint32_t                ip_dst;
        volatile uint64_t       timestamp;
        volatile bool           full;
};

struct arguments
{
	struct doca_pci_bdf*	pcie_addr;
	uint16_t 		port;
};

#define MAX_DMA_BUF_SIZE BURST_SIZE*sizeof(struct descriptor)       /* DMA buffer maximum size */

doca_error_t
write_dma(struct doca_dma_job_memcpy dma_job, struct program_core_objects state, struct timespec ts, struct doca_event event)
{
	doca_error_t result;

	/* DOCA : Enqueue DMA job */
        result = doca_workq_submit(state.workq, &dma_job.base);
        while (result == DOCA_ERROR_NO_MEMORY){
		while ((result = doca_workq_progress_retrieve(state.workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) ==
         	       DOCA_ERROR_AGAIN) {
                	nanosleep(&ts, &ts);
        	}
		result = doca_workq_submit(state.workq, &dma_job.base);
	}
	if (result != DOCA_SUCCESS) {
        	DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(result));
                return result;
        }

	doca_workq_progress_retrieve(state.workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE);

        /* DOCA : Wait for job completion */
/*        while ((result = doca_workq_progress_retrieve(state.workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) ==
                DOCA_ERROR_AGAIN) {
                nanosleep(&ts, &ts);
        }
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to retrieve DMA job: %s", doca_get_error_string(result));
                return result;
        }

        result = (doca_error_t)event.result.u64;
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("DMA job event returned unsuccessfully: %s", doca_get_error_string(result));
                return result;
        }
*/
	return DOCA_SUCCESS;
}

doca_error_t
read_dma(struct doca_dma_job_memcpy dma_job, struct program_core_objects state, struct timespec ts, struct doca_event event)
{
        doca_error_t result;

        /* DOCA : Enqueue DMA job */
        result = doca_workq_submit(state.workq, &dma_job.base);
        while (result == DOCA_ERROR_NO_MEMORY){
                while ((result = doca_workq_progress_retrieve(state.workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) ==
                       DOCA_ERROR_AGAIN) {
                        nanosleep(&ts, &ts);
                }
                result = doca_workq_submit(state.workq, &dma_job.base);
        }
	if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(result));
                return result;
        }

        /* DOCA : Wait for job completion */
        while ((result = doca_workq_progress_retrieve(state.workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) ==
                DOCA_ERROR_AGAIN) {
                nanosleep(&ts, &ts);
        }
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to retrieve DMA job: %s", doca_get_error_string(result));
                return result;
        }

        result = (doca_error_t)event.result.u64;
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("DMA job event returned unsuccessfully: %s", doca_get_error_string(result));
                return result;
        }

        return DOCA_SUCCESS;
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
	struct doca_pci_bdf *pcie_addr = args->pcie_addr;
	uint16_t port = args->port;

	// DOCA
        struct program_core_objects state = {0};
        struct doca_event event = {0};
	struct doca_dma_job_memcpy dma_job_read = {0};
	struct doca_dma_job_memcpy dma_job_write = {0};
        struct doca_dma *dma_ctx;
        struct doca_buf *src_doca_buf;
        struct doca_buf *dst_doca_buf;
        struct doca_mmap *remote_mmap;
        doca_error_t result;
        struct timespec ts = {0};
        uint32_t max_chunks = 2;
        char export_desc[1024] = {0};
        char *remote_addr = NULL;
        size_t remote_addr_len = 0, export_desc_len = 0;

	// DPDK
	uint64_t* tail;
	uint64_t* remote_tail;
	uint64_t head = 0;
	char* ring;
	size_t size;

	// Data
	struct timeval stop, start;
	bool has_received_first_packet = false;


	ts.tv_nsec = SLEEP_IN_NANOS;

	/* DOCA : Create DMA context */
        result = doca_dma_create(&dma_ctx);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Unable to create DMA engine: %s", doca_get_error_string(result));
                return result;
        }
        state.ctx = doca_dma_as_ctx(dma_ctx);

	/* DOCA : Open PCIe device */
        result = open_doca_device_with_pci(pcie_addr, &dma_jobs_is_supported, &state.dev);
        if (result != DOCA_SUCCESS) {
                doca_dma_destroy(dma_ctx);
                return result;
        }

	/* DOCA : Initialize the core */
        result = init_core_objects(&state, DOCA_BUF_EXTENSION_NONE, WORKQ_DEPTH, max_chunks);
        if (result != DOCA_SUCCESS) {
                dma_cleanup(&state, dma_ctx);
                return result;
        }

	/* DOCA : Increase workq depth */
        result = doca_workq_set_depth(state.workq, WORKQ_DEPTH);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to increase the workq depth : %s", doca_get_error_string(result));
                return result;
        }

	/* DOCA : Receive exported data from host */
        result = receive_data_from_host(export_desc, &export_desc_len, &remote_addr, &remote_addr_len);
        if (result != DOCA_SUCCESS) {
                dma_cleanup(&state, dma_ctx);
                return DOCA_ERROR_NOT_CONNECTED;
        }

        /* DOCA : Copy the entire host buffer */
        size = remote_addr_len;
	ring = (char *) malloc(size);
        if (ring == NULL) {
                DOCA_LOG_ERR("Failed to allocate buffer memory");
                dma_cleanup(&state, dma_ctx);
                return DOCA_ERROR_NO_MEMORY;
        }

	/* DOCA : Populate the mmap */
        result = doca_mmap_populate(state.mmap, ring, size, PAGE_SIZE, NULL, NULL);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to populate buffer memory");
		free(ring);
                dma_cleanup(&state, dma_ctx);
                return result;
        }

        /* DOCA : Create a local DOCA mmap from exported data */
        result = doca_mmap_create_from_export(NULL, (const void *)export_desc, export_desc_len, state.dev, &remote_mmap);
        if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create mmap from export");
		free(ring);
                dma_cleanup(&state, dma_ctx);
                return result;
        }

        /* DOCA : Construct DOCA buffer for each address range */
        result = doca_buf_inventory_buf_by_addr(state.buf_inv, remote_mmap, remote_addr, remote_addr_len, &dst_doca_buf);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Unable to acquire DOCA buffer representing remote buffer: %s",
                             doca_get_error_string(result));
                doca_mmap_destroy(remote_mmap);
		free(ring);
                dma_cleanup(&state, dma_ctx);
                return result;
        }

        /* DOCA : Construct DOCA buffer for each address range */
        result = doca_buf_inventory_buf_by_addr(state.buf_inv, state.mmap, ring, size, &src_doca_buf);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Unable to acquire DOCA buffer representing destination buffer: %s",
                             doca_get_error_string(result));
                doca_buf_refcount_rm(src_doca_buf, NULL);
                doca_mmap_destroy(remote_mmap);
                free(ring);
		dma_cleanup(&state, dma_ctx);
                return result;
        }


        printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n", rte_lcore_id());

        /* DOCA : Construct DMA job */
        dma_job_write.base.type = DOCA_DMA_JOB_MEMCPY;
        dma_job_write.base.flags = DOCA_JOB_FLAGS_NONE;
        dma_job_write.base.ctx = state.ctx;
        dma_job_write.dst_buff = dst_doca_buf;
        dma_job_write.src_buff = src_doca_buf;

	dma_job_read.base.type = DOCA_DMA_JOB_MEMCPY;
        dma_job_read.base.flags = DOCA_JOB_FLAGS_NONE;
        dma_job_read.base.ctx = state.ctx;
        dma_job_read.dst_buff = src_doca_buf;
        dma_job_read.src_buff = dst_doca_buf;

//	struct rte_mbuf* bufs[BURST_SIZE];
        struct descriptor* descriptors = (struct descriptor*) &ring[0];
	struct descriptor* remote_descriptors = (struct descriptor*) &remote_addr[0];

	uint64_t counter = 0;
	uint64_t threshold = 0;
	uint64_t timestamp = 0;
	uint64_t old_head = 0;

        /* Main work of application loop */
        for (;;)
	{

		if (timestamp > threshold){
			printf("Core %d, counter : %lu\n", rte_lcore_id(), timestamp);
			threshold += 100000;
		}

                while (descriptors[0].full){
                        set_buf_read(src_doca_buf, dst_doca_buf, &remote_descriptors[0], &descriptors[0], sizeof(struct descriptor));
                        result = read_dma(dma_job_read, state, ts, event);
                        if (result != DOCA_SUCCESS){
                                doca_buf_refcount_rm(dst_doca_buf, NULL);
                                doca_buf_refcount_rm(src_doca_buf, NULL);
                                doca_mmap_destroy(remote_mmap);
                                free(ring);
                                dma_cleanup(&state, dma_ctx);

                                printf("Core %d crashed while readind tail\n", rte_lcore_id());
                                return result;
                        }
                }

		timestamp++;
		descriptors[0].timestamp = timestamp;
		descriptors[0].full = 1;

		set_buf_write(src_doca_buf, dst_doca_buf, &remote_descriptors[0],
					&descriptors[0], sizeof(struct descriptor));

                result = write_dma(dma_job_write, state, ts, event);
                if (result != DOCA_SUCCESS){
                        doca_buf_refcount_rm(dst_doca_buf, NULL);
                        doca_buf_refcount_rm(src_doca_buf, NULL);
                        doca_mmap_destroy(remote_mmap);
                        free(ring);
                        dma_cleanup(&state, dma_ctx);
                        printf("Core %d crashed while writing buffer\n", rte_lcore_id());
                        return result;
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

	printf("size : %d",  sizeof(struct descriptor));

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

	/* DOCA : */
        result = parse_pci_addr(PCIE_ADDR, &pcie_dev);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to parse pci address: %s", doca_get_error_string(result));
                return EXIT_FAILURE;
        }

	args.pcie_addr = &pcie_dev;
	args.port = 0;

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
