#include "set_dma_buffer.h"

DOCA_LOG_REGISTER(SET_DMA_BUFFER);

void
set_buf_write(struct doca_buf* src_doca_buf, struct doca_buf* dst_doca_buf, void* dst, void* src, size_t size)
{
	doca_error_t result;

	/* DOCA : Set data position in src_buff */
        result = doca_buf_set_data(dst_doca_buf, dst, size);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to set data for DOCA src buffer: %s", doca_get_error_string(result));
        }

        result = doca_buf_set_data(src_doca_buf, src, size);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to set data for DOCA dst buffer: %s", doca_get_error_string(result));
        }
}

void
set_buf_read(struct doca_buf* src_doca_buf, struct doca_buf* dst_doca_buf, void* src, void* dst, size_t size)
{
	doca_error_t result;

        /* DOCA : Set data position in src_buff */
        result = doca_buf_set_data(src_doca_buf, dst, size);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to set data for DOCA src buffer: %s", doca_get_error_string(result));
        }

        result = doca_buf_set_data(dst_doca_buf, src, size);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to set data for DOCA dst buffer: %s", doca_get_error_string(result));
        }
}
