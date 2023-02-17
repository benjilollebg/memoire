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

#include <../../../utils/port_init.h>

#define RX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define NUM_PORTS 2

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

 /* Basic forwarding application lcore. 8< */
static __rte_noreturn void
lcore_main(uint16_t port)
{
        uint64_t port_stats = 0;

        /*
         * Check that the port is on the same NUMA node as the polling thread
         * for best performance.
         */
        if (rte_eth_dev_socket_id(port) >= 0 &&
        		rte_eth_dev_socket_id(port) != (int)rte_socket_id())
                printf("WARNING, port %u is on remote NUMA node to "
                                "polling thread.\n\tPerformance will "
                                "not be optimal.\n", port);


        printf("\nCore %u counting incoming packets. [Ctrl+C to quit]\n",
                        rte_lcore_id());

        /* Main work of application loop */
        for (;;) {
                /*
                 * Receive packets on a port and forward them on the paired
                 * port. The mapping is 0 -> 1, 1 -> 0, 2 -> 3, 3 -> 2, etc.
                 */

                /* Get burst of RX packets, from first port of pair. */
                struct rte_mbuf *bufs[BURST_SIZE];
                const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
                                bufs, BURST_SIZE);

                if (unlikely(nb_rx == 0))
                         continue;

                port_stats += nb_rx;

                printf("\nPort %u received %u packets for a total of %lu packets\n",
                                port, nb_rx, port_stats);

                /* Free any unsent packets. */
                uint16_t buf;
                for (buf = 0; buf < nb_rx; buf++)
                        rte_pktmbuf_free(bufs[buf]);
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
        unsigned nb_ports = 1;
        uint16_t portid;
        uint16_t port;

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

        /* Allocates mempool to hold the mbufs. 8< */
        mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
                MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
        /* >8 End of allocating mempool to hold mbuf. */

        if (mbuf_pool == NULL)
                rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

        /* Initializing the desired port. */
        RTE_ETH_FOREACH_DEV(portid){

                /* Display the port MAC address. */
                struct rte_ether_addr addr;
                int retval = rte_eth_macaddr_get(portid, &addr);
                if (retval != 0)
                        return retval;

                /* Only init the two desired port (depending on the specified MAC address) */
                if(memcmp(&addr, &macAddr1, 6) == 0){
                        retval = port_init(portid, mbuf_pool);
			if (retval != 0)
                                rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",portid);
                        port = portid;
                }
        }

        if (rte_lcore_count() > 1)
                printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

        /* Call lcore_main on the main core only. Called on single lcore. 8< */
        lcore_main(port);
        /* >8 End of called on single lcore. */

        /* clean up the EAL */
        rte_eal_cleanup();

        return 0;
}
