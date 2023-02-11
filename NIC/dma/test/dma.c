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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <doca_argp.h>
#include <doca_dev.h>
#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_dma.h>
#include <doca_error.h>
#include <doca_log.h>

#include <utils.h>

#include "dma_common.h"
#include <../../../utils/dma_exchange.h>

DOCA_LOG_REGISTER(DMA_WRITE_DPU);

#define SLEEP_IN_NANOS (10 * 1000)	/* Sample the job every 10 microseconds  */
#define MAX_DMA_BUF_SIZE (1024 * 1024)	/* DMA buffer maximum size */
#define RECV_BUF_SIZE 256		/* Buffer which contains config information */

#define IP "192.168.100.1"
#define PORT 6666
#define PCIE_ADDR "03:00.0"		/* Setting the pcie addr (you should modify it) */


doca_error_t
read_write(struct doca_dma_job_memcpy dma_job, struct program_core_objects state, struct timespec ts, struct doca_event event)
{
        doca_error_t result;

        /* DOCA : Enqueue DMA job */
        result = doca_workq_submit(state.workq, &dma_job.base);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(result));
                return result;
        }

        /* DOCA : Wait for job completion */
        while ((result = doca_workq_progress_retrieve(state.workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) ==
                DOCA_ERROR_AGAIN) {
                nanosleep(&ts, &ts);
        }
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to retrieve DMA job: %s", doca_get_error_string(result));
                return result;
        }

        /* DOCA : event result is valid */
        result = (doca_error_t)event.result.u64;
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("DMA job event returned unsuccessfully: %s", doca_get_error_string(result));
                return result;
        }

        return DOCA_SUCCESS;
}

/*
 * Run DOCA DMA DPU copy sample
 *
 * @export_desc_file_path [in]: Export descriptor file path
 * @buffer_info_file_path [in]: Buffer info file path
 * @pcie_addr [in]: Device PCI address
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t
dma_write(struct doca_pci_bdf *pcie_addr)
{
        struct program_core_objects state = {0};
        struct doca_event event = {0};
        struct doca_dma_job_memcpy dma_job_write = {0};
	struct doca_dma_job_memcpy dma_job_read = {0};
        struct doca_dma *dma_ctx;
        struct doca_buf *src_doca_buf;
        struct doca_buf *dst_doca_buf;
        struct doca_mmap *remote_mmap;
        doca_error_t result;
        struct timespec ts = {0};
        uint32_t max_chunks = 2;
        char export_desc[1024] = {0};
        char *remote_addr = NULL;
        char *dpu_buffer;
        size_t dst_buffer_size, remote_addr_len = 0, export_desc_len = 0;

	/* Create DMA context */
        result = doca_dma_create(&dma_ctx);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Unable to create DMA engine: %s", doca_get_error_string(result));
                return result;
        }
        state.ctx = doca_dma_as_ctx(dma_ctx);

	/* Open PCIe device */
        result = open_doca_device_with_pci(pcie_addr, &dma_jobs_is_supported, &state.dev);
        if (result != DOCA_SUCCESS) {
                doca_dma_destroy(dma_ctx);
                return result;
        }

	/* Initialize the core */
        result = init_core_objects(&state, DOCA_BUF_EXTENSION_NONE, WORKQ_DEPTH, max_chunks);
        if (result != DOCA_SUCCESS) {
                dma_cleanup(&state, dma_ctx);
                return result;
        }

	/* Receive exported data from host */
        result = receive_dma_data(export_desc, &export_desc_len, &remote_addr, &remote_addr_len, PORT);
        if (result != DOCA_SUCCESS) {
                dma_cleanup(&state, dma_ctx);
                return DOCA_ERROR_NOT_CONNECTED;
        }

        /* Copy the entire host buffer */
        dst_buffer_size = remote_addr_len;
        dpu_buffer = (char *)malloc(dst_buffer_size);
        if (dpu_buffer == NULL) {
                DOCA_LOG_ERR("Failed to allocate buffer memory");
                dma_cleanup(&state, dma_ctx);
                return DOCA_ERROR_NO_MEMORY;
        }

	/* Populate the mmap */
        result = doca_mmap_populate(state.mmap, dpu_buffer, dst_buffer_size, PAGE_SIZE, NULL, NULL);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to populate buffer memory");
		free(dpu_buffer);
                dma_cleanup(&state, dma_ctx);
                return result;
        }

        /* Create a local DOCA mmap from exported data */
        result = doca_mmap_create_from_export(NULL, (const void *)export_desc, export_desc_len, state.dev, &remote_mmap);
        if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create mmap from export");
                free(dpu_buffer);
                dma_cleanup(&state, dma_ctx);
                return result;
        }

        /* Construct DOCA buffer for each address range */
        result = doca_buf_inventory_buf_by_addr(state.buf_inv, remote_mmap, remote_addr, remote_addr_len, &src_doca_buf);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Unable to acquire DOCA buffer representing remote buffer: %s",
                             doca_get_error_string(result));
                doca_mmap_destroy(remote_mmap);
                free(dpu_buffer);
                dma_cleanup(&state, dma_ctx);
                return result;
        }

        /* Construct DOCA buffer for each address range */
        result = doca_buf_inventory_buf_by_addr(state.buf_inv, state.mmap, dpu_buffer, dst_buffer_size, &dst_doca_buf);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Unable to acquire DOCA buffer representing destination buffer: %s",
                             doca_get_error_string(result));
                doca_buf_refcount_rm(src_doca_buf, NULL);
                doca_mmap_destroy(remote_mmap);
                free(dpu_buffer);
                dma_cleanup(&state, dma_ctx);
                return result;
        }

        /* Construct DMA job */
        dma_job_write.base.type = DOCA_DMA_JOB_MEMCPY;
        dma_job_write.base.flags = DOCA_JOB_FLAGS_NONE;
        dma_job_write.base.ctx = state.ctx;
        dma_job_write.dst_buff = src_doca_buf;
        dma_job_write.src_buff = dst_doca_buf;


	/* Construct DMA job */
        dma_job_read.base.type = DOCA_DMA_JOB_MEMCPY;
        dma_job_read.base.flags = DOCA_JOB_FLAGS_NONE;
        dma_job_read.base.ctx = state.ctx;
        dma_job_read.dst_buff = dst_doca_buf;
        dma_job_read.src_buff = src_doca_buf;


	strcpy(dpu_buffer,"__________");
        dpu_buffer[10] = '\0';
        DOCA_LOG_INFO("Buffer init : %s", dpu_buffer);

	/* Set data position in the buffer to manage where to read and write */
        result = doca_buf_set_data(dst_doca_buf, &dpu_buffer[3], 0);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to set data for DOCA buffer: %s", doca_get_error_string(result));
                return result;
        }
        result = doca_buf_set_data(src_doca_buf, remote_addr+5, 3);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to set data for DOCA buffer: %s", doca_get_error_string(result));
                return result;
        }

	result = read_write(dma_job_read, state, ts, event);
        if (result != DOCA_SUCCESS){
                doca_buf_refcount_rm(dst_doca_buf, NULL);
                doca_buf_refcount_rm(src_doca_buf, NULL);
                doca_mmap_destroy(remote_mmap);
                free(dpu_buffer);
                dma_cleanup(&state, dma_ctx);
        }
	DOCA_LOG_INFO("Buffer after read : %s, should be '___567____'", dpu_buffer);
	dpu_buffer[8] = 'N';

	/* Set data position in the buffer to manage where to read and write */
        result = doca_buf_set_data(dst_doca_buf, &dpu_buffer[7], 3);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to set data for DOCA buffer: %s", doca_get_error_string(result));
                return result;
        }
        result = doca_buf_set_data(src_doca_buf, remote_addr, remote_addr_len);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to set data for DOCA buffer: %s", doca_get_error_string(result));
                return result;
        }

	result = read_write(dma_job_write, state, ts, event);
        if (result != DOCA_SUCCESS){
                doca_buf_refcount_rm(dst_doca_buf, NULL);
                doca_buf_refcount_rm(src_doca_buf, NULL);
                doca_mmap_destroy(remote_mmap);
                free(dpu_buffer);
                dma_cleanup(&state, dma_ctx);
        }
	DOCA_LOG_INFO("Buffer after write should be '_N_3456789'");
//		DOCA_LOG_INFO("Memory content: %u", (int) dpu_buffer[0]);


        DOCA_LOG_INFO("Remote DMA copy was done Successfully");
        dpu_buffer[dst_buffer_size - 1] = '\0';
        DOCA_LOG_INFO("Memory content: %s", dpu_buffer);

        if (doca_buf_refcount_rm(src_doca_buf, NULL) != DOCA_SUCCESS)
                DOCA_LOG_ERR("Failed to remove DOCA source buffer reference count");

        if (doca_buf_refcount_rm(dst_doca_buf, NULL) != DOCA_SUCCESS)
                DOCA_LOG_ERR("Failed to remove DOCA destination buffer reference count");

        /* Destroy remote memory map */
        if (doca_mmap_destroy(remote_mmap) != DOCA_SUCCESS)
                DOCA_LOG_ERR("Failed to destroy remote memory map");

        /* Inform host that DMA operation is done */
        DOCA_LOG_INFO("Host sample can be closed, DMA copy ended");

        /* Clean and destroy all relevant objects */
        dma_cleanup(&state, dma_ctx);

        free(dpu_buffer);

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
        struct doca_pci_bdf pcie_dev;
        int result;

        result = parse_pci_addr(PCIE_ADDR, &pcie_dev);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to parse pci address: %s", doca_get_error_string(result));
                return EXIT_FAILURE;
        }
	result = dma_write(&pcie_dev);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("DMA on DPU function has failed: %s", doca_get_error_string(result));
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}
