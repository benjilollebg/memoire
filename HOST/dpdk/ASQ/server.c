/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>
#include <signal.h>

//#include <../../../utils/port_init.h>

#define RX_RING_SIZE 1024

#define RTE_MBUF_HUGE_SIZE 30000
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define NUM_PORTS 1

static volatile bool force_quit = false;

struct descriptor
{
//        char           size[104];
        uint32_t       ip_src;
        uint32_t       ip_dst;
        uint64_t       timestamp;
        uint32_t       data_len;
};

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
        const uint16_t rx_rings = 1;
        uint16_t nb_rxd = RX_RING_SIZE;
        int retval;
        uint16_t q;
        struct rte_eth_dev_info dev_info;

        if (!rte_eth_dev_is_valid_port(port))
                return -1;

        static struct rte_eth_conf port_conf = {
                .rxmode = {
                        .offloads = RTE_ETH_RX_OFFLOAD_SCATTER,
                },
                .txmode = {
                        .offloads = RTE_ETH_TX_OFFLOAD_MULTI_SEGS,
                },
        };


//	static struct rte_eth_conf port_conf;
//        memset(&port_conf, 0, sizeof(struct rte_eth_conf));

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

        retval = rte_eth_dev_set_mtu(port, 9800);
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

static void
signal_handler(int signum)
{
        if (signum == SIGINT || signum == SIGTERM) {
                printf("\n\nSignal %d received, preparing to exit\n", signum);

	        struct rte_eth_stats stats = {0};

                // Get port stats
                struct rte_eth_stats new_stats;
                rte_eth_stats_get(0, &new_stats);
                // Print stats
                printf("\nNumber of received packets : %ld"
                       "\nNumber of missed packets : %ld"
                       "\nNumber of queued RX packets : %ld"
                       "\nNumber of dropped queued packet : %ld\n\n"
                        , new_stats.ipackets, new_stats.imissed, new_stats.q_ipackets[0], new_stats.q_errors[0]);

		force_quit = true;
        }
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

 /* Basic forwarding application lcore.*/
static int
lcore_main(uint16_t port)
{

	FILE *fp;
	fp = fopen("data.csv", "a");
	if(fp == NULL) {
        	printf("file can't be opened\n");
        	return 1;
    	}

        /*
         * Check that the port is on the same NUMA node as the polling thread
         * for best performance.
         */
        if (rte_eth_dev_socket_id(port) >= 0 &&
        		rte_eth_dev_socket_id(port) != (int)rte_socket_id())
                printf("WARNING, port %u is on remote NUMA node to "
                                "polling thread.\n\tPerformance will "
                                "not be optimal.\n", port);


        printf("\nProcessing incoming packets on port : %d. [Ctrl+C to quit]\n", port);

	uint64_t counter = 0;
	uint64_t counter_total = 0;
	uint64_t timestamp = 0;
	uint64_t nb_byte = 0;
	uint64_t index;
	struct descriptor* desc;
	struct rte_mbuf *bufs[BURST_SIZE];

	uint32_t ip_dst = 0;
        uint32_t ip_src = 0;

	uint64_t start = 0;
        uint64_t end = 0;
	uint64_t start_cycle = 0;
        uint64_t end_cycle = 0;
	uint64_t rte_burst = 0;
	uint64_t pkt_analysis = 0;

	int i;

	struct rte_ipv4_hdr *ip_hdr;
	uint8_t* nb_desc;
        uint32_t offset_desc;
        uint32_t offset_data;

        /* Main work of application loop. 8< */
        for (;;) {
		if(force_quit)
		{
			double time_elapsed = (double) (end-start)/rte_get_tsc_hz();
			printf("\nReceived %ld packets for a total of %ld packets in %f seconds : throughput : %fGB/s\n"
				"rte_burst cycle : %ld, pkt_analysis cycle : %ld\n"
				, counter, counter_total, time_elapsed, (nb_byte*8/time_elapsed)/1000000000, rte_burst, pkt_analysis);

			fprintf(fp, "%ld, %ld, %f, %f, %ld, %ld, %f, %f\n"
                                , counter, counter_total, time_elapsed, (nb_byte*8/time_elapsed)/1000000000,
				  rte_burst, pkt_analysis, counter/time_elapsed/1000000, counter_total/time_elapsed/1000000);
			fclose(fp);
			return 0;
		}


		start_cycle = rte_get_tsc_cycles();
                /* Get burst of RX packets, from first port of pair. */
                const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

                if (unlikely(nb_rx == 0))
                        continue;

		end_cycle = rte_get_tsc_cycles();
		rte_burst += (end_cycle-start_cycle);

		if (start == 0)
                        start = rte_get_tsc_cycles();


		start_cycle = rte_get_tsc_cycles();
		/* Do a small job on each descriptor on the ip field */
		for (index = 0; index < nb_rx; index ++)
		{
	                nb_desc = rte_pktmbuf_mtod(bufs[index], uint8_t*);
			offset_desc = 1;
			offset_data = *nb_desc * sizeof(struct descriptor) + 2;

//			printf("%d packets received\n", *nb_desc);

			for(i = 0; i < *nb_desc; i++)
			{
				desc = (struct descriptor*) (rte_pktmbuf_mtod(bufs[index], char*) + offset_desc);

				/* if this is an IPv4 packet */

                 	        if (true) {
                        	        ip_hdr = (struct rte_ipv4_hdr *) (rte_pktmbuf_mtod(bufs[index], void*) + offset_data);
                                	ip_dst = rte_be_to_cpu_32(ip_hdr->dst_addr);
                                	ip_src = rte_be_to_cpu_32(ip_hdr->src_addr);
                        	}
                        	else{
                                	printf("\nIP header doesn't match IPV4 type\n");
                        	}

//				ip_dst = desc->ip_dst;
//				ip_src = desc->ip_src;

				offset_desc += sizeof(struct descriptor);
                                offset_data += desc->data_len;

				nb_byte += desc->data_len;

//				printf("timestamp : %ld, ", desc->timestamp);
//				timestamp++;
//				printf("len : %d, ", desc->data_len);

//				printf("offset : %ld\n", offset);
			}

			counter_total += *nb_desc;
			counter++;

	                /* Free all received packets. */
			rte_pktmbuf_free(bufs[index]);
		}
		end_cycle = rte_get_tsc_cycles();
                pkt_analysis += (end_cycle-start_cycle);

		end = rte_get_tsc_cycles();
//                printf("\nPort %u received %u packets for a total of %lu packets\n", port, nb_rx, counter);
        }
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
        struct rte_mempool *mbuf_pool;
        uint16_t portid;
        uint16_t port = 99;

        /* Initializion the Environment Abstraction Layer (EAL). 8< */
        int ret = rte_eal_init(argc, argv);
        if (ret < 0)
                rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
        /* >8 End of initialization the Environment Abstraction Layer (EAL). */

        argc -= ret;
        argv += ret;

        /* Initialize the MAC addresses to count the incoming number of packets */
        struct rte_ether_addr macAddr1;

        macAddr1.addr_bytes[0]=0x08;
        macAddr1.addr_bytes[1]=0xC0;
        macAddr1.addr_bytes[2]=0xEB;
        macAddr1.addr_bytes[3]=0xD1;
        macAddr1.addr_bytes[4]=0xFB;
        macAddr1.addr_bytes[5]=0x26;

        /* Creates a new mempool in memory to hold the mbufs. */
        mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
                MBUF_CACHE_SIZE, 0, RTE_MBUF_HUGE_SIZE, rte_socket_id());
        if (mbuf_pool == NULL)
                rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

        /* Initializing the desired port. */
        RTE_ETH_FOREACH_DEV(portid){

                /* Display the port MAC address. */
                struct rte_ether_addr addr;
                int retval = rte_eth_macaddr_get(portid, &addr);
                if (retval != 0)
                        return retval;
/*
		char buf[RTE_ETHER_ADDR_FMT_SIZE];
    		rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, &addr);
    		printf("%s\n", buf);
*/

                /* Only init the two desired port (depending on the specified MAC address) */
                if(memcmp(&addr, &macAddr1, 6) == 0){
                        if (port_init(portid, mbuf_pool) != 0)
                                rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",portid);
                        port = portid;

		char buf[RTE_ETHER_ADDR_FMT_SIZE];
                rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, &addr);
                printf("%s\n", buf);
                }
        }

        if (rte_lcore_count() > 1)
                printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	printf("\nListening on port : %d.\n", port);

	/* Handle the Control+C */
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);

        lcore_main(port);

        /* clean up the EAL */
        rte_eal_cleanup();

        return 0;
}
