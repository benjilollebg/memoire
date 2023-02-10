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

DOCA_LOG_REGISTER(DMA_EXCHANGE);

#define RECV_BUF_SIZE 256               /* Buffer which contains config information */

doca_error_t
send_dma_data(char *export_desc, size_t export_desc_len, char *src_buffer, size_t src_buffer_size, char* ip, int port)
{
        struct sockaddr_in addr;
        int sock_fd;
        uint64_t buffer_addr = (uintptr_t)src_buffer;
        uint64_t buffer_len = (uint64_t)src_buffer_size;

        char str_buffer_addr[100], str_buffer_len[100];
        sprintf(str_buffer_addr, "%" PRIu64, (uint64_t)buffer_addr);
        sprintf(str_buffer_len, "%" PRIu64, (uint64_t)buffer_len);

        sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock_fd < 0)
        {
                DOCA_LOG_ERR("Unable to create the socket");
                return DOCA_ERROR_IO_FAILED;
        }

        addr.sin_addr.s_addr = inet_addr(ip);
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        /* Send the descriptor to the DPU */
        int bytes_sent = sendto(sock_fd, export_desc, export_desc_len, 0, (struct sockaddr *) &addr, sizeof(addr));
        if (bytes_sent < 0) {
                close(sock_fd);
                return DOCA_ERROR_IO_FAILED;
        }

        /* Send the buffer data to the DPU */
        bytes_sent = sendto(sock_fd, str_buffer_addr, 100 , 0, (struct sockaddr *) &addr, sizeof(addr));
        if (bytes_sent < 0) {
                DOCA_LOG_ERR("Couldn't receive data from host");
                close(sock_fd);
                return DOCA_ERROR_IO_FAILED;
        }

        /* Send the buffer length to the DPU */
        bytes_sent = sendto(sock_fd, str_buffer_len, 100, 0, (struct sockaddr *) &addr, sizeof(addr));
        if (bytes_sent < 0) {
                DOCA_LOG_ERR("Couldn't receive data from host");
                close(sock_fd);
                return DOCA_ERROR_IO_FAILED;
        }

        DOCA_LOG_INFO("buffer_addr : %ld", buffer_addr);
        DOCA_LOG_INFO("buffer_len : %ld", buffer_len);
        DOCA_LOG_INFO("export_desc : %s", export_desc);
        DOCA_LOG_INFO("export_desc_len : %ld", export_desc_len);

        close(sock_fd);
        return DOCA_SUCCESS;
}


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
receive_dma_data(char *export_desc, size_t *export_desc_len, char **remote_addr, size_t *remote_addr_len, int port)
{
        int sock_fd;
        int result;
        char buffer[RECV_BUF_SIZE];

        struct sockaddr_in servaddr, client;

        sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock_fd == -1) {
                DOCA_LOG_ERR("socket creation failed");
                return DOCA_ERROR_IO_FAILED;
        }

        //servaddr.sin_addr.s_addr = inet_addr("192.168.100.1");
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(port);

        result = bind(sock_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));
        if (result != 0){
                DOCA_LOG_INFO("Socket bind failed");
                return DOCA_ERROR_IO_FAILED;
        }

        DOCA_LOG_ERR("Receiving data");

        /* Receive the descriptor on the socket */
        socklen_t client_len = sizeof(client);
        *export_desc_len = recvfrom(sock_fd, export_desc, 1024, 0, (struct sockaddr *) &client, &client_len);
        if (*export_desc_len < 0) {
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
