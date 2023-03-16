#include "receive_data_from_host.h"

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

DOCA_LOG_REGISTER(RECEIVE_DATA);

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
        servaddr.sin_port = htons(PORT + rte_lcore_id());

        result = bind(sock_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));
        if (result != 0){
                DOCA_LOG_INFO("Socket bind failed...");
                return DOCA_ERROR_IO_FAILED;
        }

        printf("Core %d, receiving data\n", rte_lcore_id());

        /* Receive the descriptor on the socket */
        socklen_t client_len = sizeof(client);
        *export_desc_len = recvfrom(sock_fd, export_desc, 1024, 0, (struct sockaddr *) &client, &client_len);
        if (*export_desc_len <= 0) {
                DOCA_LOG_ERR("Couldn't receive data from host");
                close(sock_fd);
		                return DOCA_ERROR_IO_FAILED;
        }

        /* Receive the buffer address on the socket */
        int bytes_received = recvfrom(sock_fd, buffer, RECV_BUF_SIZE, 0, (struct sockaddr *) &client, &client_len);
        if (bytes_received < 0) {
                DOCA_LOG_ERR("Couldn't receive data from host");
                close(sock_fd);
                return DOCA_ERROR_IO_FAILED;
        }
        *remote_addr = (char*) strtoull(buffer, NULL, 0);

        memset(buffer, 0, RECV_BUF_SIZE);

        /* Receive the buffer length on the socket */
        bytes_received = recvfrom(sock_fd, buffer, RECV_BUF_SIZE, 0, (struct sockaddr *) &client, &client_len);
        if (bytes_received < 0) {
                DOCA_LOG_ERR("Couldn't receive data from host");
                close(sock_fd);
                return DOCA_ERROR_IO_FAILED;
        }
        *remote_addr_len = strtoull(buffer, NULL, 0);

        printf("Core %d, remote_addr : %lld", rte_lcore_id(), strtoull(buffer, NULL, 0));
        printf("Core %d, export_desc : %s\n", rte_lcore_id(), export_desc);
        printf("Core %d, export_desc_len : %ld\n", rte_lcore_id(), *export_desc_len);
        printf("Core %d, remote_addr_len : %ld\n", rte_lcore_id(), *remote_addr_len);
        printf("Core %d, exported data was received\n", rte_lcore_id());
        fflush(stdout);

        return DOCA_SUCCESS;
}
