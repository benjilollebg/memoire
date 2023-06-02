/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE 512
#define TX_RING_SIZE 512

#define RTE_MBUF_HUGE_SIZE 10000
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 32
#define BURST_SIZE 32
#define NUM_PORTS 2

static volatile bool force_quit = false;
static uint32_t nb_core = 7;            	/* The number of Core working (max 7) */
struct rte_mempool *mbuf_pool;


struct arguments
{
        uint16_t    	port_src;
        uint16_t        port_dst;
};

struct descriptor
{
        volatile uint32_t       ip_src;
        volatile uint32_t       ip_dst;
        volatile uint64_t       timestamp;
	volatile uint32_t	data_len;
};

static void
signal_handler(int signum)
{
        if (signum == SIGINT || signum == SIGTERM) {
                printf("\n\nSignal %d received, preparing to exit\n", signum);
                force_quit = true;
        }
}


/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
        const uint16_t rx_rings = nb_core, tx_rings = nb_core;
        uint16_t nb_rxd = RX_RING_SIZE;
        uint16_t nb_txd = TX_RING_SIZE;
        int retval;
        uint16_t q;
        struct rte_eth_dev_info dev_info;
        struct rte_eth_txconf txconf;

        if (!rte_eth_dev_is_valid_port(port))
                return -1;

	static struct rte_eth_conf port_conf = {
                .rxmode = {
                        .mq_mode = ETH_MQ_RX_RSS,
			//.offloads = DEV_RX_OFFLOAD_SCATTER,
                },
                .rx_adv_conf = {
                        .rss_conf = {
                                .rss_key = NULL,
                                .rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP,
                        },
                },
                .txmode = {
                        .mq_mode = ETH_MQ_TX_NONE,
			.offloads = DEV_TX_OFFLOAD_MULTI_SEGS,
                },
        };

        retval = rte_eth_dev_info_get(port, &dev_info);
        if (retval != 0) {
                printf("Error during getting device (port %u) info: %s\n",
                                port, strerror(-retval));
                return retval;
        }

        /* Configure the Ethernet device. */
        retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
        if (retval != 0)
                return retval;

        retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
        if (retval != 0)
                return retval;

        /* Allocate and set up 1 RX queue per Ethernet port. */
        for (q = 0; q < rx_rings; q++) {
                retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                                SOCKET_ID_ANY, NULL, mbuf_pool);
                if (retval < 0)
                        return retval;
        }

        txconf = dev_info.default_txconf;
        txconf.offloads = port_conf.txmode.offloads;
        /* Allocate and set up 1 TX queue per Ethernet port. */
        for (q = 0; q < tx_rings; q++) {
                retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                SOCKET_ID_ANY, &txconf);
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

        if (retval != 0)
                return retval;

        return 0;
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static int
job(void* arg)
{
	// args
        struct arguments* args = (struct arguments*) arg;
        uint16_t port_src = args->port_src;
        uint16_t port_dst = args->port_dst;

        uint64_t timestamp = 0;
	uint64_t counter = 0;

        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);

        printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n", rte_lcore_id());


	struct rte_mbuf *bufs[BURST_SIZE];
	struct rte_mbuf *pkt;
	int pkt_len = 0;
	int data_len = 0;

        for (;;) {

		/* Quit the app on Control+C */
                if (force_quit)
		{
			if(rte_lcore_id() == 1)
			{
				// Get port stats
                		struct rte_eth_stats new_stats;
                		rte_eth_stats_get(port_src, &new_stats);
                		// Print stats
                		printf("\nNumber of received packets : %ld"
                      		       "\nNumber of missed packets : %ld"
                       		       "\nNumber of queued RX packets : %ld"
                       		       "\nNumber of dropped queued packet : %ld\n\n"
                        		, new_stats.ipackets, new_stats.imissed, new_stats.q_ipackets[0], new_stats.q_errors[0]);
			}
			return 0;
		}

                /* Get burst of RX packets. */
                const uint16_t nb_rx = rte_eth_rx_burst(port_src, rte_lcore_id() - 1, bufs, BURST_SIZE);

                if (unlikely(nb_rx == 0))
                        continue;

		/* Allocate the packet in the mbuf_pool */
		pkt = rte_pktmbuf_alloc(mbuf_pool);
		if (pkt == NULL) {
        		printf("Failed to allocate mbuf\n");
        		return 1;
    		}
		pkt_len = 0;
		data_len = 1;

		/* Setup the number of desc in the payload */
		uint8_t* nb_desc = rte_pktmbuf_mtod(pkt, uint8_t*);
		uint8_t NB_DESC = 0;

		/* set the next field to the first packet */
		rte_pktmbuf_chain(pkt, bufs[0]);
		pkt->nb_segs = 1;

		/* Modify the descriptor */
                for (int i = 0; i < nb_rx; i++) {

			/* Link all the poackets together */
			if (i < nb_rx - 1)
				rte_pktmbuf_chain(bufs[i], bufs[i+1]);
			pkt->nb_segs = pkt->nb_segs + 1;

			NB_DESC++;
			struct descriptor* desc = (struct descriptor*) (rte_pktmbuf_mtod(pkt, char*) + data_len);

			data_len += sizeof(struct descriptor);
			pkt_len  += bufs[i]->data_len;

			desc->data_len = bufs[i]->data_len;
			//desc->timestamp = timestamp;
			//timestamp++;

//			if(pkt_len > 8000 && i != nb_rx-1)
			if(i%32 ==0 && i != nb_rx-1)
			{
				pkt_len += data_len;
                		pkt->data_len = data_len;
                		pkt->pkt_len = pkt_len;

				*nb_desc = (uint8_t) NB_DESC;

				/* Send burst of TX packets, to second port of pair. */
                		const uint16_t nb_tx = rte_eth_tx_burst(port_dst, rte_lcore_id() - 1, &pkt, 1);
                		counter += NB_DESC;
/*
				if(nb_tx == 1)
					printf("\nCore %u forwarded %u packets cause no more room for a total of %lu packets\n",
                                		rte_lcore_id(), NB_DESC, counter);
*/
				if (nb_tx != 1)
                        		rte_pktmbuf_free(pkt);

			 	/* Allocate the packet in the mbuf_pool */
                		pkt = rte_pktmbuf_alloc(mbuf_pool);
                		if (pkt == NULL) {
                        		printf("Failed to allocate mbuf\n");
                        		return 1;
                		}
                		pkt_len = 0;
                		data_len = 1;

                		/* Setup the number of desc in the payload */
                		nb_desc = rte_pktmbuf_mtod(pkt, uint8_t*);
                		NB_DESC = 0;

                		/* set the next field to the first packet */
                		rte_pktmbuf_chain(pkt, bufs[i+1]);
                		pkt->nb_segs = 1;
			}



//printf("desc pos: %ld, timestamp : %d, desc offset : %d, packet len : %d\n",pkt_len-bufs[i]->data_len-sizeof(struct descriptor), timestamp, desc->data_len, pkt_len);

                        /* if this is an IPv4 packet */
/*
                        if (RTE_ETH_IS_IPV4_HDR(bufs[i]->packet_type)) {
                                struct rte_ipv4_hdr *ip_hdr;

                                ip_hdr = rte_pktmbuf_mtod(bufs[i], struct rte_ipv4_hdr *);
				desc->ip_src = rte_be_to_cpu_32(ip_hdr->src_addr);
                        	desc->ip_dst = rte_be_to_cpu_32(ip_hdr->dst_addr);
                        }
                        else{
                                printf("\nCore %d,IP header doesn't match IPV4 type\n", rte_lcore_id());
                        }
*/
                }

		pkt_len += data_len;
		pkt->data_len = data_len;
		pkt->pkt_len = pkt_len;

		*nb_desc = (uint8_t) NB_DESC;
                /* Send burst of TX packets, to second port of pair. */
		const uint16_t nb_tx = rte_eth_tx_burst(port_dst, rte_lcore_id() - 1, &pkt, 1);

                counter += NB_DESC;
//                printf("\nCore %u forwarded %u packets via Port %u for a total of %lu packets\n",
//				rte_lcore_id(), NB_DESC, port_dst, counter);

		if (nb_tx != 1)
			rte_pktmbuf_free(pkt);
        }
}

static int
job_stat(void* arg)
{
        // args
        struct arguments* args = (struct arguments*) arg;
        uint16_t port_src = args->port_src;

        struct rte_eth_stats stats = {0};
        while (1){
                /* Quit the app on Control+C */
                if (force_quit)
                {
                        return 0;
                }

                // Get port stats
                struct rte_eth_stats new_stats;
                rte_eth_stats_get(port_src, &new_stats);
                // Print stats
                printf("\nNumber of received packets : %ld"
                       "\nNumber of missed packets : %ld"
                       "\nNumber of queued RX packets : %ld"
                       "\nNumber of dropped queued packet : %ld\n\n"
                        , new_stats.ipackets, new_stats.imissed, new_stats.q_ipackets[0], new_stats.q_errors[0]);
                // Sleep for 1 second
                sleep(1);
        }
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	// args
        struct arguments args;

        unsigned nb_ports = 2;
        uint16_t portid;
	uint16_t lcore_id;

        uint16_t port_src = 99;
	uint16_t port_dst = 99;

        /* Initializion the Environment Abstraction Layer (EAL). 8< */
        int ret = rte_eal_init(argc, argv);
        if (ret < 0)
                rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
        /* >8 End of initialization the Environment Abstraction Layer (EAL). */

        argc -= ret;
        argv += ret;

        /* Initialize the 2 MAC addresses to exchange data */
        struct rte_ether_addr macAddr1;
        struct rte_ether_addr macAddr2;

        macAddr1.addr_bytes[0]=0x08;
        macAddr1.addr_bytes[1]=0xC0;
        macAddr1.addr_bytes[2]=0xEB;
        macAddr1.addr_bytes[3]=0xD1;
        macAddr1.addr_bytes[4]=0xFB;
        macAddr1.addr_bytes[5]=0x2A;

        macAddr2.addr_bytes[0]=0x4A;
        macAddr2.addr_bytes[1]=0xA9;
        macAddr2.addr_bytes[2]=0x59;
        macAddr2.addr_bytes[3]=0x46;
        macAddr2.addr_bytes[4]=0xC5;
        macAddr2.addr_bytes[5]=0x5C;

        /* Allocates mempool to hold the mbufs. 8< */
        mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
                MBUF_CACHE_SIZE, 0,  RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());


        if (mbuf_pool == NULL)
                rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

        /* Initializing all ports. 8< */
        RTE_ETH_FOREACH_DEV(portid){

                /* Display the port MAC address. */
                struct rte_ether_addr addr;
                int retval = rte_eth_macaddr_get(portid, &addr);
                if (retval != 0)
                        return retval;

                /* Only init the two desired port (depending on the specified MAC address) */
                if(memcmp(&addr, &macAddr1, 6) == 0){
                        if (port_init(portid, mbuf_pool) != 0)
                                rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",portid);
                        port_src = portid;

			char buf[RTE_ETHER_ADDR_FMT_SIZE];
	                rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, &addr);
        	        printf("Port %d source : %s\n", port_src, buf);
                }

                if(memcmp(&addr, &macAddr2, 6) == 0){
                        if (port_init(portid, mbuf_pool) != 0)
                                rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",portid);
                        port_dst = portid;

			char buf[RTE_ETHER_ADDR_FMT_SIZE];
                        rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, &addr);
                        printf("Port %d destination : %s\n", port_dst, buf);
                }
        }
        /* >8 End of initializing all ports. */

        if (rte_lcore_count() > 1)
                printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

        args.port_src = port_src;
        args.port_dst = port_dst;

	/* MAIN : polling each queue on a lcore */
        RTE_LCORE_FOREACH_WORKER(lcore_id)
        {
                if(lcore_id <= nb_core)
                        rte_eal_remote_launch(job, &args, lcore_id);
//                if(lcore_id == 7)
//                        rte_eal_remote_launch(job_stat, &args, lcore_id);
        }

	rte_eal_mp_wait_lcore();

        /* clean up the EAL */
        rte_eal_cleanup();

        return 0;
}
