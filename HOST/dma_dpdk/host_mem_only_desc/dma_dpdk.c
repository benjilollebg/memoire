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
#include <signal.h>
#include <rte_atomic.h>

#define IP "192.168.100.2"
#define PORT 6660
#define PCIE_ADDR "01:00.1"


//#define debug printf
#define debug

DOCA_LOG_REGISTER(MAIN);

#define DESCRIPTOR_NB 2048		 /* The number of descriptor in the ring (MAX uint16_t max val or change head-tail to uint16_t) */

struct __attribute__((aligned(64))) descriptor
{
	volatile uint32_t       ip_src;
	volatile uint32_t       ip_dst;
	volatile uint64_t       timestamp;
	volatile bool           full;
};

static uint32_t nb_core = 2;            /* The number of Core working on the NIC (max 7) */
static volatile bool force_quit = false;

static void
signal_handler(int signum)
{
        if (signum == SIGINT || signum == SIGTERM) {
                printf("\n\nSignal %d received, preparing to exit\n", signum);
                force_quit = true;
        }
}

static doca_error_t
send_data_to_dpu(char *export_desc, size_t export_desc_len, char *src_buffer, size_t src_buffer_size, int core)
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
	addr.sin_port = htons(PORT + core);

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

	printf("Core %d : buffer_addr : %ld\n", core, buffer_addr);
        printf("Core %d : buffer_len : %ld\n", core, buffer_len);
        printf("Core %d : export_desc : %s\n", core, export_desc);
	printf("Core %d : export_desc_len : %ld\n\n", core, export_desc_len);

	close(sock_fd);
	return DOCA_SUCCESS;
}

doca_error_t
dma_read(struct doca_pci_bdf *pcie_addr, char *rings[], size_t size)
{
	// DOCA
	struct program_core_objects state[nb_core];
        doca_error_t result;
        char *export_desc;
        size_t export_desc_len = 0;

	int index;
	int core = 0;
	uint64_t counter[nb_core];
        uint64_t pos[nb_core];
	uint64_t timestamp[nb_core];
	struct descriptor* descriptors[nb_core];

	for (index = 0; index < nb_core; index++)
        {
		// Init the variable
		counter[index] = 0;
		pos[index] = 0;
		timestamp[index] = 0;
		descriptors[index] = (struct descriptor*) rings[index];

		/* DOCA : Open the relevant DOCA device */
        	result = open_doca_device_with_pci(pcie_addr, &dma_jobs_is_supported, &state[index].dev);
        	if (result != DOCA_SUCCESS){
			printf("Initialisation error\n");
                	return result;
		}

		/* DOCA : Init all DOCA core objects */
        	result = host_init_core_objects(&state[index]);
        	if (result != DOCA_SUCCESS) {
                	host_destroy_core_objects(&state[index]);
                	return result;
        	}

		/* DOCA : Populate the memory map with the allocated memory */
        	result = doca_mmap_populate(state[index].mmap, rings[index], size, PAGE_SIZE, NULL, NULL);
        	if (result != DOCA_SUCCESS) {
                	host_destroy_core_objects(&state[index]);
                	return result;
        	}

		/* DOCA : Export DOCA mmap to enable DMA on Host*/
        	result = doca_mmap_export(state[index].mmap, state[index].dev, (void **)&export_desc, &export_desc_len);
        	if (result != DOCA_SUCCESS) {
                	host_destroy_core_objects(&state[index]);
                	return result;
        	}

		/* DOCA : Send exported string and wait for ack that DMA was done on receiver node */
		result = send_data_to_dpu(export_desc, export_desc_len, rings[index], size, index + 1);
		if (result != DOCA_SUCCESS) {
			host_destroy_core_objects(&state[index]);
			free(export_desc);
			return DOCA_ERROR_NOT_CONNECTED;
		}
	}

        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);

	/* Read the buffer */
	for(;;)
	{
		for (core = 0; core < nb_core; core++)
		{
			if (force_quit)
        	        {
				for(int i =0;i<DESCRIPTOR_NB; i++){
					printf("descriptor[%d] timestamp : %ld full : %d\n", i, descriptors[core][i].timestamp, descriptors[core][i].full);
				}

				printf("local timstamp : %ld\n", timestamp[core]);
                        	printf("descriptor : %lu pos : %ld, full : %d\n", descriptors[core][pos[core]].timestamp, pos[core], descriptors[core][pos[core]].full);
				printf("descriptor+1 : %lu pos : %ld, full : %d\n", descriptors[core][pos[core] +1].timestamp, pos[core] +1 , descriptors[core][pos[core]+1].full);
                        	return 0;
                	}

			if(descriptors[core][pos[core]].full){

				rte_io_rmb();

				counter[core]++;
                                timestamp[core]++;

				if (descriptors[core][pos[core]].timestamp != timestamp[core])
				{
					printf("Core %d : wrong timestamp, expected : %lu, received : %lu\n",
						index+1, timestamp[core], descriptors[core][pos[core]].timestamp);

					return 1;
				}

				descriptors[core][pos[core]].full = 0;

				pos[core]++;
	                        if(pos[core] == DESCRIPTOR_NB)
        	                        pos[core] = 0;
			}
		}
	}

	/* DOCA : Destroy all relevant DOCA core objects */
	for (index = 0; index < nb_core; index++)
		host_destroy_core_objects(&state[index]);


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
	char* rings[nb_core];
	size_t size = sizeof(struct descriptor) * DESCRIPTOR_NB;
	doca_error_t result;

	 /* parse application arguments (after the EAL ones) */
       /* result = parse_args(argc, argv);
        if (result < 0)
                rte_exit(EXIT_FAILURE, "arguments\n");


	/* DOCA : Allocate the rings */
	for (int i = 0; i < nb_core; i++)
	{
		rings[i] = (char *) malloc(size);
        	if (rings[i] == NULL)
		{
                	DOCA_LOG_ERR("Ring buffer allocation failed");
                	return EXIT_FAILURE;
        	}
		memset(rings[i], 0, size);
	}

        result = parse_pci_addr(PCIE_ADDR, &pcie_dev);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to parse pci address: %s", doca_get_error_string(result));
                return EXIT_FAILURE;
        }

        result = dma_read(&pcie_dev, rings, size);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("DMA function has failed: %s", doca_get_error_string(result));
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

