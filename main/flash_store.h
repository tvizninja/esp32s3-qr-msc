\
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FLASH_STORE_MAX_PAYLOAD 4096

typedef struct {
    uint32_t sequence;
    uint16_t number;
    uint16_t length;
    uint16_t slot;
} flash_record_info_t;

esp_err_t flash_store_init(void);

size_t flash_store_slot_count(void);
size_t flash_store_record_count(void);

/*
 * Erase the complete QR history partition.
 */
esp_err_t flash_store_reset(void);

/*
 * Append a committed QR record.
 *
 * Record commit order:
 *   1. erase 8 KiB physical slot
 *   2. write payload to second 4 KiB sector
 *   3. write header to first sector LAST
 *
 * A power failure before step 3 leaves no valid header.
 */
esp_err_t flash_store_append(
    const uint8_t *data,
    size_t length,
    flash_record_info_t *out_info
);

/*
 * Return up to max_count most recent committed records.
 * exclude_sequence == 0 means no exclusion.
 * Output order is oldest -> newest.
 */
size_t flash_store_get_recent(
    uint32_t exclude_sequence,
    flash_record_info_t *out_records,
    size_t max_count
);

/*
 * Read and CRC-check a complete payload.
 */
esp_err_t flash_store_read(
    const flash_record_info_t *info,
    uint8_t *buffer,
    size_t buffer_capacity,
    size_t *out_length
);

/*
 * Read a range directly from a committed payload.
 * Used by the virtual FAT MSC path so a 4 KiB history file
 * never needs to be copied into RAM.
 */
esp_err_t flash_store_read_range(
    const flash_record_info_t *info,
    size_t payload_offset,
    uint8_t *buffer,
    size_t length
);


/*
 * Analyzer RAW diagnostic storage.
 *
 * The qrstore partition reserves its final 44 physical 8 KiB slots
 * for one 640x480 GRAY8 frame plus one packed 1bpp frame. The visible
 * 500-record policy is unchanged; history still has more than 500 ring slots.
 */
#define FLASH_STORE_RAW_WIDTH   640u
#define FLASH_STORE_RAW_HEIGHT  480u
#define FLASH_STORE_RAW_BYTES   (FLASH_STORE_RAW_WIDTH * FLASH_STORE_RAW_HEIGHT)
#define FLASH_STORE_BINARY_BYTES ((FLASH_STORE_RAW_WIDTH * FLASH_STORE_RAW_HEIGHT) / 8u)

esp_err_t flash_store_raw_begin(void);

esp_err_t flash_store_raw_write(
    size_t offset,
    const uint8_t *data,
    size_t length
);

esp_err_t flash_store_raw_commit(void);

bool flash_store_raw_available(void);

esp_err_t flash_store_raw_read(
    size_t offset,
    uint8_t *buffer,
    size_t length
);

/* Analyzer packed 1bpp diagnostic storage. */
esp_err_t flash_store_binary_begin(void);

esp_err_t flash_store_binary_write(
    size_t offset,
    const uint8_t *data,
    size_t length
);

esp_err_t flash_store_binary_commit(void);

bool flash_store_binary_available(void);

esp_err_t flash_store_binary_read(
    size_t offset,
    uint8_t *buffer,
    size_t length
);

#ifdef __cplusplus
}
#endif
