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

#include "utils.h"

// DOCA

#include <doca_argp.h>
#include <doca_dev.h>
#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_dma.h>
#include <doca_error.h>
#include <doca_log.h>

#include "dma_common.h"

DOCA_LOG_REGISTER(DMA_WRITE_DPU);

#define SLEEP_IN_NANOS (10 * 1000)	/* Sample the job every 10 microseconds  */
#define MAX_DMA_BUF_SIZE (1024 * 1024)	/* DMA buffer maximum size */
#define RECV_BUF_SIZE 256		/* Buffer which contains config information */

#define IP "192.168.100.1"
#define PORT 6666

// DPDK

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define DESCRIPTOR_NB 256	 	/* The number of descriptor in the ring (MAX 256 or change head-tail to uint16_t) */
#define NUM_PORTS 1

struct descriptor
{
        void*                   buf_addr;
        int	                pkt_len;
        uint16_t                data_len;
};

/*
 * =============================== DOCA =================================
 *
 * Saves export descriptor and buffer information content into memory buffers
 *
 * @export_desc_file_path [in]: Export descriptor file path
 * @buffer_info_file_path [in]: Buffer information file path
 * @export_desc [in]: Export descriptor buffer
 * @export_desc_len [in]: Export descriptor buffer length
 * @remote_addr [in]: Remote buffer address
 * @remote_addr_len [in]: Remote buffer total length
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 *
 * =============================== DOCA =================================
 */

doca_error_t
receive_data_from_host(char *export_desc, size_t *export_desc_len, char **remote_addr, size_t *remote_addr_len)
{
	int sock_fd;
	int result;
	char buffer[RECV_BUF_SIZE];

	struct sockaddr_in servaddr, client;

    	sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    	if (sock_fd == -1) {
        	DOCA_LOG_ERR("socket creation failed...");
        	return DOCA_ERROR_IO_FAILED;
    	}

        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(PORT);

	result = bind(sock_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));
	if (result != 0){
        	DOCA_LOG_INFO("Socket bind failed...");
        	return DOCA_ERROR_IO_FAILED;
    	}

	DOCA_LOG_ERR("Receiving data");

	/* Receive the descriptor on the socket */
	socklen_t client_len = sizeof(client);
	*export_desc_len = recvfrom(sock_fd, export_desc, 1024, 0, (struct sockaddr *) &client, &client_len);
    	if (*export_desc_len <= 0) {
        	DOCA_LOG_ERR("Couldn't receive data from host");
		close(sock_fd);
                return DOCA_ERROR_IO_FAILED;
    	}
	DOCA_LOG_INFO("export_desc : %s", export_desc);
        DOCA_LOG_INFO("export_desc_len : %ld", *export_desc_len);

	/* Receive the buffer address on the socket */
	int bytes_received = recvfrom(sock_fd, buffer, RECV_BUF_SIZE, 0, (struct sockaddr *) &client, &client_len);
        if (bytes_received < 0) {
                DOCA_LOG_ERR("Couldn't receive data from host");
		close(sock_fd);
                return DOCA_ERROR_IO_FAILED;
        }
	*remote_addr = (char*) strtoull(buffer, NULL, 0);
	DOCA_LOG_INFO("remote_addr : %lld", strtoull(buffer, NULL, 0));

        memset(buffer, 0, RECV_BUF_SIZE);

	/* Receive the buffer length on the socket */
	bytes_received = recvfrom(sock_fd, buffer, RECV_BUF_SIZE, 0, (struct sockaddr *) &client, &client_len);
        if (bytes_received < 0) {
                DOCA_LOG_ERR("Couldn't receive data from host");
		close(sock_fd);
                return DOCA_ERROR_IO_FAILED;
        }
	*remote_addr_len = strtoull(buffer, NULL, 0);
	DOCA_LOG_INFO("remote_addr_len : %ld", *remote_addr_len);

	DOCA_LOG_INFO("Exported data was received");

	return DOCA_SUCCESS;
}

/*
 * =============================== DPDK =================================
 *
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 *
 * =============================== DPDK =================================
 */

static int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
        struct rte_eth_conf port_conf;
        const uint16_t rx_rings = 1;
        uint16_t nb_rxd = RX_RING_SIZE;
        int retval;
        uint16_t q;
        struct rte_eth_dev_info dev_info;

        if (!rte_eth_dev_is_valid_port(port))
                return -1;

        memset(&port_conf, 0, sizeof(struct rte_eth_conf));

        retval = rte_eth_dev_info_get(port, &dev_info);
        if (retval != 0) {
                printf("Error during getting device (port %u) info: %s\n",
                                port, strerror(-retval));
                return retval;
        }

        /* Configure the Ethernet device. */
        retval = rte_eth_dev_configure(port, rx_rings, 0, &port_conf);
        if (retval != 0)
                return retval;

        retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, NULL);
        if (retval != 0)
                return retval;

        /* Allocate and set up 1 RX queue per Ethernet port. */
        for (q = 0; q < rx_rings; q++) {
                retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                                rte_eth_dev_socket_id(port), NULL, mbuf_pool);
                if (retval < 0)
                        return retval;
        }

        /* Starting Ethernet port. 8< */
        retval = rte_eth_dev_start(port);
        /* >8 End of starting of ethernet port. */
        if (retval < 0)
                return retval;

        /* Display the port MAC address. */
        struct rte_ether_addr addr;
        retval = rte_eth_macaddr_get(port, &addr);
        if (retval != 0)
                return retval;
/*
        printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
                           " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
                        port, RTE_ETHER_ADDR_BYTES(&addr));
*/
        /* Enable RX in promiscuous mode for the Ethernet device. */
        retval = rte_eth_promiscuous_enable(port);
        /* End of setting RX port in promiscuous mode. */
        if (retval != 0)
                return retval;

        return 0;
}

doca_error_t
read_write(struct doca_dma_job_memcpy dma_job, struct program_core_objects state, struct timespec ts, struct doca_event event)
{
	doca_error_t result;

	/* DOCA : Enqueue DMA job */
        result = doca_workq_submit(state.workq, &dma_job.base);
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

        /* DOCA : event result is valid */
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
doca_error_t
dma_write(struct doca_pci_bdf *pcie_addr, uint16_t port)
{
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
	uint16_t nb_pakt = 0;
	uint8_t head = 0;
	uint8_t tail = 0;
	size_t descriptor_size = sizeof(struct descriptor);
	uint16_t head_pos = descriptor_size * DESCRIPTOR_NB;
	uint16_t tail_pos = descriptor_size * DESCRIPTOR_NB + 1;
	char* ring;
	size_t ring_size;

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

	/* DOCA : Receive exported data from host */
        result = receive_data_from_host(export_desc, &export_desc_len, &remote_addr, &remote_addr_len);
        if (result != DOCA_SUCCESS) {
                dma_cleanup(&state, dma_ctx);
                return DOCA_ERROR_NOT_CONNECTED;
        }

        /* DOCA : Copy the entire host buffer */
        ring_size = remote_addr_len;
	ring = (char *) malloc(ring_size);
        if (ring == NULL) {
                DOCA_LOG_ERR("Failed to allocate buffer memory");
                dma_cleanup(&state, dma_ctx);
                return DOCA_ERROR_NO_MEMORY;
        }

	/* DOCA : Populate the mmap */
        result = doca_mmap_populate(state.mmap, ring, ring_size, PAGE_SIZE, NULL, NULL);
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
        result = doca_buf_inventory_buf_by_addr(state.buf_inv, state.mmap, ring, ring_size, &src_doca_buf);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Unable to acquire DOCA buffer representing destination buffer: %s",
                             doca_get_error_string(result));
                doca_buf_refcount_rm(src_doca_buf, NULL);
                doca_mmap_destroy(remote_mmap);
                free(ring);
		dma_cleanup(&state, dma_ctx);
                return result;
        }

	/* DPDK : Check that the port is on the same NUMA node as the polling thread for best performance. */
        if (rte_eth_dev_socket_id(port) >= 0 && rte_eth_dev_socket_id(port) != (int) rte_socket_id())
                printf("WARNING, port %u is on remote NUMA node to "
                                "polling thread.\n\tPerformance will "
                                "not be optimal.\n", port);


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

        /* DOCA : Set data position in src_buff */
        result = doca_buf_set_data(src_doca_buf, ring, ring_size);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to set data for DOCA src buffer: %s", doca_get_error_string(result));
                return result;
        }

	result = doca_buf_set_data(dst_doca_buf, remote_addr, ring_size);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to set data for DOCA dst buffer: %s", doca_get_error_string(result));
                return result;
        }


	int counter = 0;
        /* Main work of application loop */
        for (;;) {

                /* DPDK : Get burst of RX packets from the port */
                struct rte_mbuf *bufs[BURST_SIZE];
                struct descriptor descriptors[BURST_SIZE];

                const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

		nb_pakt += nb_rx;
		//DOCA_LOG_ERR("Packet received : %u", nb_pakt);
                if (unlikely(nb_rx == 0))
                        continue;

		// read tail
                result = read_write(dma_job_read, state, ts, event);
                if (result != DOCA_SUCCESS){
                        doca_buf_refcount_rm(dst_doca_buf, NULL);
                        doca_buf_refcount_rm(src_doca_buf, NULL);
                        doca_mmap_destroy(remote_mmap);
                        free(ring);
                	dma_cleanup(&state, dma_ctx);
                }
                tail = (uint8_t) ring[tail_pos];

		/* Wait for the tail to not overwrite */
		if (head + nb_rx > DESCRIPTOR_NB){
			while(tail > head || tail <= (head + nb_rx) % DESCRIPTOR_NB){
				// read tail
                                result = read_write(dma_job_read, state, ts, event);
				if (result != DOCA_SUCCESS){
					doca_buf_refcount_rm(dst_doca_buf, NULL);
                			doca_buf_refcount_rm(src_doca_buf, NULL);
                			doca_mmap_destroy(remote_mmap);
                			free(ring);
                			dma_cleanup(&state, dma_ctx);
				}
				tail = (uint8_t) ring[tail_pos];
				DOCA_LOG_ERR("head : %" PRIu8 "tail : %" PRIu8 " head + rx : %d", head, tail, (head + nb_rx) % DESCRIPTOR_NB);
                                sleep(1);
			}
		}
		else {
			while(tail > head && tail <= head + nb_rx){
				// read tail
				result = read_write(dma_job_read, state, ts, event);
                                if (result != DOCA_SUCCESS){
                                        doca_buf_refcount_rm(dst_doca_buf, NULL);
                                        doca_buf_refcount_rm(src_doca_buf, NULL);
                                        doca_mmap_destroy(remote_mmap);
                                        free(ring);
                                        dma_cleanup(&state, dma_ctx);
                                }
				tail = (uint8_t) ring[tail_pos];
				DOCA_LOG_ERR("head : %" PRIu8 "tail : %" PRIu8, head, tail);
				sleep(1);
			}
		}

                /* Modify the descriptor */
                for (int i = 0; i < nb_rx; i++) {
			/* Copy data from mbufs to the modified descriptor */
                        descriptors[i].buf_addr = (void *) bufs[i]->buf_addr;
//                        descriptors[i].pkt_len  = bufs[i]->pkt_len;
			descriptors[i].pkt_len  = counter;
                        descriptors[i].data_len = bufs[i]->data_len;
			counter++;
                	/* Free the mbuf */
                        rte_pktmbuf_free(bufs[i]);

			/* Write the descriptors in the ring */
			memcpy(&ring[head*sizeof(struct descriptor)], (char *) &(descriptors[i]), descriptor_size);
			DOCA_LOG_ERR("ring_desc counter : %d", *((int*) &ring[head*sizeof(struct descriptor)+8]));
			if (head == DESCRIPTOR_NB - 1)
                                head = -1;
			head++;
                }

		/* Set the new head value */
		memcpy(&ring[head_pos], (char *) &head, 1);

                printf("\nPort %u forwarded %u packets via DMA for a total of %u packets\n",
                                port, nb_rx, nb_pakt);

		result = read_write(dma_job_write, state, ts, event);
                if (result != DOCA_SUCCESS){
                	doca_buf_refcount_rm(dst_doca_buf, NULL);
                        doca_buf_refcount_rm(src_doca_buf, NULL);
                        doca_mmap_destroy(remote_mmap);
                        free(ring);
                        dma_cleanup(&state, dma_ctx);
                }
        }

	/* DOCA : Clean allocated memory */
	if (doca_buf_refcount_rm(src_doca_buf, NULL) != DOCA_SUCCESS)
                DOCA_LOG_ERR("Failed to remove DOCA source buffer reference count");
        if (doca_buf_refcount_rm(dst_doca_buf, NULL) != DOCA_SUCCESS)
                DOCA_LOG_ERR("Failed to remove DOCA destination buffer reference count");

        /* DOCA : Destroy remote memory map */
        if (doca_mmap_destroy(remote_mmap) != DOCA_SUCCESS)
                DOCA_LOG_ERR("Failed to destroy remote memory map");

        /* DOCA : Inform host that DMA operation is done */
        DOCA_LOG_INFO("Host sample can be closed, DMA copy ended");

        /* DOCA : Clean and destroy all relevant objects */
        dma_cleanup(&state, dma_ctx);

        //free(dpu_buffer);
	free(ring);

        return result;
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
	// DOCA
        struct doca_pci_bdf pcie_dev;
        int result;

	// DPDK
	struct rte_mempool *mbuf_pool;
        unsigned nb_ports = 1;
        uint16_t portid;
	uint16_t port;
	int ret;

	/* DPDK : Initializion the Environment Abstraction Layer (EAL) */
        ret = rte_eal_init(argc, argv);
        if (ret < 0)
                rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

        argc -= ret;
        argv += ret;

        /* DPDK : Initialize the MAC address to read the data (p0) */
        struct rte_ether_addr macAddr1;

        macAddr1.addr_bytes[0]=0x08;
        macAddr1.addr_bytes[1]=0xC0;
        macAddr1.addr_bytes[2]=0xEB;
        macAddr1.addr_bytes[3]=0xD1;
        macAddr1.addr_bytes[4]=0xFB;
        macAddr1.addr_bytes[5]=0x2A;

        /* DPDK : Creates a new mempool in memory to hold the mbufs. */
        mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
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
                        if (port_init(portid, mbuf_pool) != 0)
                                rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",portid);
			port = portid;
                }
        }

        if (rte_lcore_count() > 1)
                printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* DOCA : */
        result = parse_pci_addr("03:00.0", &pcie_dev);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to parse pci address: %s", doca_get_error_string(result));
                return EXIT_FAILURE;
        }

	/* DOCA : */
	result = dma_write(&pcie_dev, port);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("DMA on DPU function has failed: %s", doca_get_error_string(result));
                return EXIT_FAILURE;
        }

	/* DPDK : clean up the EAL */
        rte_eal_cleanup();

        return EXIT_SUCCESS;
}
