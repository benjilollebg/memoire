#include <stdio.h>
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

// DOCA
#include <doca_argp.h>
#include <doca_dev.h>
#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_dma.h>
#include <doca_error.h>
#include <doca_log.h>

//DPDK
#include <rte_lcore.h>

#define RECV_BUF_SIZE 256               /* Buffer which contains config information */
#define PORT 6660

#include "dma_common.h"

doca_error_t
receive_data_from_host(char *export_desc, size_t *export_desc_len, char **remote_addr, size_t *remote_addr_len);
