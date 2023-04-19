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
#include <getopt.h>


#include <doca_argp.h>
#include <doca_dev.h>
#include <doca_dma.h>
#include <doca_error.h>
#include <doca_log.h>
#include <doca_mmap.h>

#include "dma_common.h"
#include <signal.h>
#include <rte_atomic.h>

#define IP "192.168.100.2"
#define PORT 6660
#define PCIE_ADDR "01:00.1"


//#define debug printf
#define debug

DOCA_LOG_REGISTER(MAIN);

#define DESCRIPTOR_NB 512		 /* The number of descriptor in the ring (MAX uint16_t max val or change head-tail to uint16_t) */

/*
 |    0 - 7    |   8    |    9 - 63   |
 |=====================================
 |  timestamp  |  full  |   PADDING   |
 |=====================================
 */
struct __attribute__((aligned(64))) descriptor
{
	volatile uint64_t       timestamp;
	volatile bool           full;
};

/* Enable printing data on Control + C */
static volatile bool force_quit = false;

/* Enable printing data on Control + C */
static void
signal_handler(int signum)
{
        if (signum == SIGINT || signum == SIGTERM) {
                printf("\n\nSignal %d received, preparing to exit\n", signum);
                force_quit = true;
        }
}

/* Communicate with the client on UDP to exchange dma data */
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
                DOCA_LOG_ERR("Unable to create the socket");
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

	printf("buffer_addr : %ld\n", buffer_addr);
        printf("buffer_len : %ld\n", buffer_len);
        printf("export_desc : %s\n", export_desc);
	printf("export_desc_len : %ld\n\n", export_desc_len);

	close(sock_fd);
	return DOCA_SUCCESS;
}

doca_error_t
dma_read(struct doca_pci_bdf *pcie_addr, char *ring, size_t size)
{
	// DOCA
	struct program_core_objects state;
        doca_error_t result;
        char *export_desc;
        size_t export_desc_len = 0;

	uint64_t counter;
        uint64_t pos;
	volatile uint64_t* head;
	volatile uint64_t* tail;
	uint64_t timestamp;
	struct descriptor* descriptors;


	// Init the variable
	counter = 0;
	pos = 0;
	tail = (uint64_t*) ring;
	head = (uint64_t*) (ring + sizeof(uint64_t));
	timestamp = 0;
	descriptors = (struct descriptor*) (ring + 2*sizeof(uint64_t));

	/* DOCA : Open the relevant DOCA device */
       	result = open_doca_device_with_pci(pcie_addr, &dma_jobs_is_supported, &state.dev);
       	if (result != DOCA_SUCCESS){
		printf("Initialisation error\n");
               	return result;
	}

	/* DOCA : Init all DOCA core objects */
       	result = host_init_core_objects(&state);
       	if (result != DOCA_SUCCESS) {
               	host_destroy_core_objects(&state);
               	return result;
       	}

	/* DOCA : Populate the memory map with the allocated memory */
       	result = doca_mmap_populate(state.mmap, ring, size, PAGE_SIZE, NULL, NULL);
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
	result = send_data_to_dpu(export_desc, export_desc_len, ring, size);
	if (result != DOCA_SUCCESS) {
		host_destroy_core_objects(&state);
		free(export_desc);
		return DOCA_ERROR_NOT_CONNECTED;
	}


        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);

	/* Read the buffer */
	for(;;)
	{
		if (force_quit)
                {
			for(int i =0;i<DESCRIPTOR_NB; i++){
				printf("descriptor[%d] timestamp : %ld full : %d\n", i, descriptors[i].timestamp, descriptors[i].full);
			}

			printf("local timstamp : %ld\n", timestamp);
                        printf("descriptor : %lu pos : %ld, full : %d\n", descriptors[pos].timestamp, *tail, descriptors[*tail].full);
                        return 0;
                }

		if(*tail != *head && descriptors[*tail].full){

			rte_io_rmb();

			counter++;
                        timestamp++;

			if (descriptors[*tail].timestamp != timestamp)
			{
				printf("Wrong timestamp, expected : %lu, received : %lu\n", timestamp, descriptors[*tail].timestamp);

				return 1;
			}

			descriptors[pos].full = 0;

			pos++;
                        if(pos == DESCRIPTOR_NB)
       	                        pos = 0;
			*tail = pos;
		}
	}

	/* DOCA : Destroy all relevant DOCA core objects */
	host_destroy_core_objects(&state);


        /* DOCA : Free API pre-allocated exported string */
        free(export_desc);

        return result;
}


int
main(int argc, char **argv)
{
	// DOCA
        struct doca_pci_bdf pcie_dev;
	char* ring;
	size_t size = sizeof(struct descriptor) * DESCRIPTOR_NB + 2*sizeof(uint64_t);
	doca_error_t result;

	/* DOCA : Allocate the rings */
	ring = (char *) malloc(size);
       	if (ring == NULL)
	{
               	DOCA_LOG_ERR("Ring buffer allocation failed");
               	return EXIT_FAILURE;
       	}
	memset(ring, 0, size);

        result = parse_pci_addr(PCIE_ADDR, &pcie_dev);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to parse pci address: %s", doca_get_error_string(result));
                return EXIT_FAILURE;
        }

        result = dma_read(&pcie_dev, ring, size);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("DMA function has failed: %s", doca_get_error_string(result));
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

