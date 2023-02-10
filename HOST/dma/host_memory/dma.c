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

#define IP "192.168.100.2"
#define PORT 6666

DOCA_LOG_REGISTER(DMA_READ_HOST);

static doca_error_t
send_data_to_dpu(char *export_desc, size_t export_desc_len, char *src_buffer, size_t src_buffer_size)
{
	struct sockaddr_in addr;
	int sock_fd;
	uint64_t buffer_addr = (uintptr_t)src_buffer;
        uint64_t buffer_len = (uint64_t)src_buffer_size;

	char str_buffer_addr[100], str_buffer_len[100];
	sprintf(str_buffer_addr, "%" PRIu64, (uint64_t)buffer_addr);
	sprintf(str_buffer_len, "%" PRIu64, (uint64_t)buffer_len);

	sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock_fd < 0)
        {
                DOCA_LOG_ERR("Unable to creat the socket");
                return DOCA_ERROR_IO_FAILED;
        }

	addr.sin_addr.s_addr = inet_addr(IP);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);

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

	DOCA_LOG_INFO("str_buffer_addr : %s", str_buffer_addr);
        DOCA_LOG_INFO("str_buffer_len : %s", str_buffer_len);
//	write(1, export_desc, export_desc_len);
	DOCA_LOG_INFO("buffer_addr : %ld", buffer_addr);
        DOCA_LOG_INFO("buffer_len : %ld", buffer_len);
        DOCA_LOG_INFO("export_desc : %s", export_desc);
	DOCA_LOG_INFO("export_desc_len : %ld", export_desc_len);

	close(sock_fd);
	return DOCA_SUCCESS;
}

doca_error_t
dma_read(struct doca_pci_bdf *pcie_addr, char *src_buffer, size_t src_buffer_size)
{
	struct program_core_objects state = {0};
        doca_error_t result;
        char *export_desc;
        size_t export_desc_len = 0;

	/* Open the relevant DOCA device */
        result = open_doca_device_with_pci(pcie_addr, &dma_jobs_is_supported, &state.dev);
        if (result != DOCA_SUCCESS)
                return result;

	/* Init all DOCA core objects */
        result = host_init_core_objects(&state);
        if (result != DOCA_SUCCESS) {
                host_destroy_core_objects(&state);
                return result;
        }

	/* Populate the memory map with the allocated memory */
        result = doca_mmap_populate(state.mmap, src_buffer, src_buffer_size, PAGE_SIZE, NULL, NULL);
        if (result != DOCA_SUCCESS) {
                host_destroy_core_objects(&state);
                return result;
        }

	/* Export DOCA mmap to enable DMA on Host*/
        result = doca_mmap_export(state.mmap, state.dev, (void **)&export_desc, &export_desc_len);
        if (result != DOCA_SUCCESS) {
                host_destroy_core_objects(&state);
                return result;
        }

	/* Send exported string and wait for ack that DMA was done on receiver node */
	result = send_data_to_dpu(export_desc, export_desc_len, src_buffer, src_buffer_size);
	if (result != DOCA_SUCCESS) {
		host_destroy_core_objects(&state);
		free(export_desc);
		return DOCA_ERROR_NOT_CONNECTED;
	}

	/* Read the buffer */
	while(1){
		printf("%s\n",src_buffer);
		sleep(3);
		src_buffer[1] = 'h';
	}

	/* Destroy all relevant DOCA core objects */
        host_destroy_core_objects(&state);

        /* Free API pre-allocated exported string */
        free(export_desc);

        return result;
}

/*
 * Sample main function
10 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */
int
main(int argc, char **argv)
{
        struct doca_pci_bdf pcie_dev;
	size_t src_buffer_size = 3;
        char *src_buffer;
        doca_error_t result;

	/* For the test */
	src_buffer = (char *) malloc(src_buffer_size);
        if (src_buffer == NULL) {
                DOCA_LOG_ERR("Source buffer allocation failed");
                return EXIT_FAILURE;
        }
	memcpy(src_buffer, "00", 3);

        result = parse_pci_addr("01:00.0", &pcie_dev);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to parse pci address: %s", doca_get_error_string(result));
                return EXIT_FAILURE;
        }

        result = dma_read(&pcie_dev, src_buffer, src_buffer_size);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("DMA function has failed: %s", doca_get_error_string(result));
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}
