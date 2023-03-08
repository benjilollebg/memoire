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

struct arguments
{
        uint16_t                port;
};

/*
 * =============================== DPDK =================================
 *
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 *
 * =============================== DPDK =================================
 */
/*
struct lcore_queue_conf
{
    unsigned n_rx_port;
    unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
} __rte_cache_aligned;

struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];
*/
static uint32_t nb_core = 1;

static int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
        const uint16_t rx_rings = 3;
        uint16_t nb_rxd = RX_RING_SIZE;
        int retval;
        uint16_t q;
        struct rte_eth_dev_info dev_info;

        if (!rte_eth_dev_is_valid_port(port))
                return -1;

	static struct rte_eth_conf port_conf = {
		.rxmode = {
                        .mq_mode = ETH_MQ_RX_RSS,
                },
                .rx_adv_conf = {
                        .rss_conf = {
                                .rss_key = NULL,
                                .rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP,
                        },
                },
                .txmode = {
                        .mq_mode = ETH_MQ_TX_NONE,
                },
        };

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

        /* Enable RX in promiscuous mode for the Ethernet device. */
        retval = rte_eth_promiscuous_enable(port);
        /* End of setting RX port in promiscuous mode. */
        if (retval != 0)
                return retval;

        return 0;
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

	// DPDK
	uint64_t nb_pakt = 0;
	uint64_t nb_pakt_q0 = 0;
	uint64_t nb_pakt_q1 = 0;

	size_t descriptor_size = sizeof(struct descriptor);


	struct rte_mbuf *bufs[BURST_SIZE];
        struct descriptor descriptors[BURST_SIZE];

        /* Main work of application loop */
        for (;;) {
                /* DPDK : Get burst of RX packets from the port */
                uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

		nb_pakt_q0 += nb_rx;
		nb_pakt += nb_rx;
                if (unlikely(nb_rx == 0))
                        continue;

                /* Modify the descriptor */
                for (int i = 0; i < nb_rx; i++) {
                	/* Free the mbuf */
                        rte_pktmbuf_free(bufs[i]);
                }

                nb_rx = rte_eth_rx_burst(port, 1, bufs, BURST_SIZE);

		nb_pakt_q1 += nb_rx;
                nb_pakt += nb_rx;
                if (unlikely(nb_rx == 0))
                        continue;

                for (int i = 0; i < nb_rx; i++) {
                        rte_pktmbuf_free(bufs[i]);
                }

		nb_rx = rte_eth_rx_burst(port, 2, bufs, BURST_SIZE);

                nb_pakt += nb_rx;
                if (unlikely(nb_rx == 0))
                        continue;

                for (int i = 0; i < nb_rx; i++) {
                        rte_pktmbuf_free(bufs[i]);
                }

		printf("\nCore %u forwarded %u packets via DMA for a total of %lu packets, q0 : %lu, q1 : %lu\n",
                       	        rte_lcore_id(), nb_rx, nb_pakt, nb_pakt_q0, nb_pakt_q1);

//		printf("\nCore %u forwarded %u packets via DMA for a total of %lu packets, q0 : %lu\n",
//                                rte_lcore_id(), nb_rx, nb_pakt, nb_pakt_q0);
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
	// DOCA
        struct doca_pci_bdf pcie_dev;
        int result;

	// args
        struct arguments args;

	// DPDK
	struct rte_mempool *mbuf_pool;
        unsigned nb_ports = 1;
        uint16_t portid;
	uint16_t port;
	int ret;
	uint16_t lcore_id;

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
