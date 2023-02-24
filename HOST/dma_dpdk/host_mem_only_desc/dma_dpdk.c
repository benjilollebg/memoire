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
#include <inttypes.h>
#include <utils.h>

/*
 *
 */

#include <doca_argp.h>
#include <doca_dev.h>
#include <doca_dma.h>
#include <doca_error.h>
#include <doca_log.h>
#include <doca_mmap.h>

#include "dma_common.h"

#define IP "192.168.100.2"
#define PORT 6666
#define BUFF_SIZE 1024*1024
#define PCIE_ADDR "01:00.0"

DOCA_LOG_REGISTER(DMA_READ_HOST);


#define RX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define DESCRIPTOR_NB 256		 /* The number of descriptor in the ring (MAX 256 or change head-tail to uint16_t) */

struct descriptor
{
        void*                   buf_addr;
        int	                pkt_len;
        uint16_t                data_len;
};

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

	DOCA_LOG_INFO("buffer_addr : %ld", buffer_addr);
        DOCA_LOG_INFO("buffer_len : %ld", buffer_len);
        DOCA_LOG_INFO("export_desc : %s", export_desc);
	DOCA_LOG_INFO("export_desc_len : %ld", export_desc_len);

	close(sock_fd);
	return DOCA_SUCCESS;
}

doca_error_t
dma_read(struct doca_pci_bdf *pcie_addr, char *ring, size_t ring_size)
{
	// DOCA
	struct program_core_objects state = {0};
        doca_error_t result;
        char *export_desc;
        size_t export_desc_len = 0;

	size_t descriptor_size = sizeof(struct descriptor);
        uint8_t head = 0;
        uint8_t tail = 0;
        uint16_t head_pos = descriptor_size * DESCRIPTOR_NB;
        uint16_t tail_pos = descriptor_size * DESCRIPTOR_NB + sizeof(head);

	uint64_t nb_pakt = 0;

	/* DOCA : Open the relevant DOCA device */
        result = open_doca_device_with_pci(pcie_addr, &dma_jobs_is_supported, &state.dev);
        if (result != DOCA_SUCCESS)
                return result;

	/* DOCA : Init all DOCA core objects */
        result = host_init_core_objects(&state);
        if (result != DOCA_SUCCESS) {
                host_destroy_core_objects(&state);
                return result;
        }

	/* DOCA : Populate the memory map with the allocated memory */
        result = doca_mmap_populate(state.mmap, ring, ring_size, PAGE_SIZE, NULL, NULL);
        if (result != DOCA_SUCCESS) {
                host_destroy_core_objects(&state);
                return result;
        }

	/* DOCA : Export DOCA mmap to enable DMA on Host*/
        result = doca_mmap_export(state.mmap, state.dev, (void **)&export_desc, &export_desc_len);
        if (result != DOCA_SUCCESS) {
                host_destroy_core_objects(&state);
                return result;
        }

	/* DOCA : Send exported string and wait for ack that DMA was done on receiver node */
	result = send_data_to_dpu(export_desc, export_desc_len, ring, ring_size);
	if (result != DOCA_SUCCESS) {
		host_destroy_core_objects(&state);
		free(export_desc);
		return DOCA_ERROR_NOT_CONNECTED;
	}

	struct descriptor *desc = {0};
	int counter = 0;
	/* Read the buffer */
	for(;;){
//		DOCA_LOG_ERR("head : %" PRIu8 "tail : %" PRIu8, head, tail);
		head = (uint16_t) ring[head_pos];
//		printf("tail : %d head : %d\n", tail, head);
		if(tail != head){
			desc = (struct descriptor*) &ring[tail*sizeof(struct descriptor)];
			if(counter != desc->pkt_len)
				return DOCA_ERROR_NOT_CONNECTED;
			counter++;
			nb_pakt++;
			tail++;
			ring[tail_pos] = (char) tail;
			printf("Nombre de packet reçu : %ld\n", nb_pakt);
		}
	}

	/* DOCA : Destroy all relevant DOCA core objects */
        host_destroy_core_objects(&state);

        /* DOCA : Free API pre-allocated exported string */
        free(export_desc);

        return result;
}

/*
 * Sample main function
 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */
int
main(int argc, char **argv)
{
	// DOCA
        struct doca_pci_bdf pcie_dev;
        char *ring;
        doca_error_t result;

	size_t descriptor_size = sizeof(struct descriptor);
	size_t ring_size = descriptor_size * DESCRIPTOR_NB + 2;    /* +2 for the head and tail*/

	/* DOCA : For the test */
	ring = (char *) malloc(ring_size);
        if (ring == NULL) {
                DOCA_LOG_ERR("Ring buffer allocation failed");
                return EXIT_FAILURE;
        }

        result = parse_pci_addr(PCIE_ADDR, &pcie_dev);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to parse pci address: %s", doca_get_error_string(result));
                return EXIT_FAILURE;
        }

        result = dma_read(&pcie_dev, ring, ring_size);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("DMA function has failed: %s", doca_get_error_string(result));
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}
