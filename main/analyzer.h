#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "driver/uart.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ANALYZER_JSON_MAX 32768

esp_err_t analyzer_mode_init(void);
bool analyzer_mode_enabled(void);
esp_err_t analyzer_mode_toggle(void);

esp_err_t analyzer_process_scan_metadata(
    uart_port_t uart_num,
    const uint8_t *payload,
    size_t payload_len,
    bool protocol3_requested,
    bool protocol_write_reply_seen,
    int protocol_write_rid,
    bool protocol_readback_seen,
    int protocol_readback_value,
    const char *protocol_write_reply_hex,
    const char *protocol_readback_hex,
    bool protocol3_detected,
    bool crc_valid,
    uint8_t barcode_count,
    uint16_t code_id,
    const char *length_endian,
    const char *crc_scope,
    const char *crc_endian);

const char *analyzer_result_json(void);
size_t analyzer_result_json_length(void);
bool analyzer_has_result(void);
void analyzer_clear_result(void);


/*
 * Diagnostic breadcrumb support.
 *
 * v2.2.2 diagnostic builds persist Analyzer progress in NVS so the previous
 * failure point can be printed on the next boot, before USB switches to MSC.
 */
void analyzer_diag_mark(
    uint16_t stage,
    int32_t error_code
);

void analyzer_diag_print_last(void);
size_t analyzer_diag_format_last(char *buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif
