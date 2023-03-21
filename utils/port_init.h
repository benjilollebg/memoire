#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>

int
port_init(uint16_t port, struct rte_mempool* mbuf_pool, uint8_t nb_core);
