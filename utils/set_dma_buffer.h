#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>

#include <doca_argp.h>
#include <doca_dev.h>
#include <doca_dma.h>
#include <doca_error.h>
#include <doca_log.h>
#include <doca_mmap.h>

#include <utils.h>

#include "dma_common.h"

void
set_buf_write(struct doca_buf* src_doca_buf, struct doca_buf* dst_doca_buf, void* src, void* dst, size_t size);

void
set_buf_read(struct doca_buf* src_doca_buf, struct doca_buf* dst_doca_buf, void* src, void* dst, size_t size);
