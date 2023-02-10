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

doca_error_t
send_dma_data(char *export_desc, size_t export_desc_len, char *src_buffer, size_t src_buffer_size, char* ip, int port);


/*
 * Saves export descriptor and buffer information content into memory buffers
 *
 * @export_desc_file_path [in]: Export descriptor file path
 * @buffer_info_file_path [in]: Buffer information file path
 * @export_desc [in]: Export descriptor buffer
 * @export_desc_len [in]: Export descriptor buffer length
 * @remote_addr [in]: Remote buffer address
 * @remote_addr_len [in]: Remote buffer total length
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */

doca_error_t
receive_dma_data(char *export_desc, size_t *export_desc_len, char **remote_addr, size_t *remote_addr_len, int port);
