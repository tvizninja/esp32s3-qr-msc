#include "analyzer.h"

#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "quirc.h"
#include "zxing_qr_packed.h"
#include "flash_store.h"

static const char *TAG = "ANALYZER";

/*
 * Product UI hook. qrtransfer_msc.c provides the strong implementation.
 */
__attribute__((weak)) void analyzer_progress_hook(void)
{
}

#define ANALYZER_FIRMWARE_VERSION "2.4.6"

#define ANALYZER_NVS_NAMESPACE "qrtransfer"
#define ANALYZER_NVS_MODE_KEY  "an_mode"


#define ANALYZER_DIAG_STAGE_KEY   "ad_stage"
#define ANALYZER_DIAG_ERROR_KEY   "ad_error"
#define ANALYZER_DIAG_FREE_KEY    "ad_free"
#define ANALYZER_DIAG_LARGEST_KEY "ad_largest"

enum
{
    AD_NONE = 0,
    AD_SCAN_COMMITTED = 10,
    AD_ANALYZER_ENTER = 20,
    AD_IDENTITY_DONE = 30,
    AD_BEFORE_QUIRC = 40,
    AD_QUIRC_NEW_OK = 50,
    AD_QUIRC_RESIZE_OK = 60,
    AD_QUIRC_BEGIN_OK = 70,
    AD_BAUD_READ_OK = 80,
    AD_BAUD_128_OK = 90,
    AD_IMAGE_REQUEST_SENT = 100,
    AD_IMAGE_HEADER_OK = 110,
    AD_IMAGE_RX_START = 120,
    AD_IMAGE_RX_DONE = 130,
    AD_BAUD_115_RESTORED = 140,
    AD_QUIRC_END_DONE = 150,
    AD_SYMBOLS_FOUND = 160,
    AD_DECODE_TASK_CREATED = 170,
    AD_DECODE_DONE = 180,
    AD_QUIRC_DESTROYED = 190,
    AD_BINARY_START = 191,
    AD_BINARY_HEAP_SNAPSHOT_OK = 192,
    AD_BINARY_MALLOC_OK = 193,
    AD_BINARY_POSTALLOC_HEAP_OK = 194,
    AD_BINARY_HIST_DONE = 195,
    AD_BINARY_PACK_DONE = 196,
    AD_JSON_BUILT = 200,
    AD_FAT_REBUILD_START = 210,
    AD_FAT_REBUILD_DONE = 220,
    AD_USB_CONNECT_CALLED = 230,
    AD_GUARD_ENTERED = 240,

    AD_FAIL_BASE = 1000
};

#define STATUS_QUERY_TIMEOUT_MS 800
#define STATUS_VALUE_MAX 64

#define ANALYZER_SOURCE_WIDTH   640
#define ANALYZER_SOURCE_HEIGHT  480
#define ANALYZER_SOURCE_BYTES   \
    (ANALYZER_SOURCE_WIDTH * ANALYZER_SOURCE_HEIGHT)

#define ANALYZER_BINARY_ROW_BYTES \
    ((ANALYZER_SOURCE_WIDTH + 7) / 8)
#define ANALYZER_BINARY_BYTES \
    (ANALYZER_BINARY_ROW_BYTES * ANALYZER_SOURCE_HEIGHT)

#define ANALYZER_PASS1_WIDTH   320
#define ANALYZER_PASS1_HEIGHT  240
#define ANALYZER_PASS2_WIDTH   480
#define ANALYZER_PASS2_HEIGHT  360

#define ANALYZER_BAUD_NORMAL 115200
#define ANALYZER_BAUD_IMAGE  115200

#define ANALYZER_UART_RX_GPIO 5
#define ANALYZER_UART_TX_GPIO 6
#define ANALYZER_UART_RX_BUFFER_SIZE 8192

#define IMAGE_HEADER_TIMEOUT_MS 2000
#define IMAGE_BODY_GAP_MS       2000
#define DECODE_TASK_STACK_BYTES 18432
#define DECODE_TASK_TIMEOUT_MS  5000

static bool s_mode_enabled = false;
static char *s_json = NULL;
static size_t s_json_len = 0;

static const uint8_t CMD_IMAGE_RAW_640X480[] = {
    0x60, 0x02, 0x80, 0x01, 0xE0, 0x00, 0x00
};

typedef struct
{
    bool attempted;
    bool image_supported;
    bool image_received;
    bool quirc_detected;
    bool quirc_decoded;

    uint16_t image_width;
    uint16_t image_height;
    uint8_t image_type;
    uint32_t image_bytes;
    int64_t transfer_ms;

    uint16_t analysis_width;
    uint16_t analysis_height;

    int detected_symbols;
    int version;
    int ecc_level;
    int mask;
    int data_type;
    uint32_t eci;
    size_t decoded_payload_len;
    bool payload_match;

    int corners[4][2];
    int corners_analysis[4][2];

    bool native_crop_attempted;
    bool native_crop_used;
    int crop_x;
    int crop_y;
    int crop_width;
    int crop_height;
    int64_t second_transfer_ms;

    size_t heap_before_quirc;
    size_t largest_before_quirc;
    size_t heap_after_quirc;
    size_t largest_after_quirc;
    size_t heap_before_decode;
    size_t largest_before_decode;

    bool binary_probe_attempted;
    bool binary_probe_ready;
    uint8_t binary_otsu_threshold;
    size_t binary_bytes;
    int64_t binary_histogram_ms;
    int64_t binary_pack_ms;
    size_t heap_before_binary;
    size_t largest_before_binary;
    size_t heap_with_binary;
    size_t largest_with_binary;
    uint32_t binary_black_pixels;
    uint32_t binary_checksum;
    int64_t binary_hybrid_ms;
    uint32_t binary_hybrid_black_pixels;
    uint32_t binary_hybrid_checksum;

    bool zxing_attempted;
    bool zxing_decoded;
    bool zxing_payload_match;
    int zxing_finder_patterns;
    int zxing_candidate_sets;
    int zxing_decode_attempts;
    int zxing_version;
    size_t zxing_payload_bytes;
    int64_t zxing_decode_ms;
    size_t zxing_heap_before;
    size_t zxing_largest_before;
    size_t zxing_heap_with_bitmap;
    size_t zxing_largest_with_bitmap;
    size_t zxing_heap_after_decode;
    size_t zxing_largest_after_decode;
    char zxing_ecc[8];
    char zxing_status[32];
    zxing_qr_packed_result_t zxing_meta;

    bool zxing_hybrid_attempted;
    bool zxing_hybrid_decoded;
    bool zxing_hybrid_payload_match;
    int zxing_hybrid_finder_patterns;
    int zxing_hybrid_candidate_sets;
    int zxing_hybrid_decode_attempts;
    int zxing_hybrid_version;
    size_t zxing_hybrid_payload_bytes;
    int64_t zxing_hybrid_decode_ms;
    size_t zxing_hybrid_heap_before;
    size_t zxing_hybrid_largest_before;
    size_t zxing_hybrid_heap_with_bitmap;
    size_t zxing_hybrid_largest_with_bitmap;
    size_t zxing_hybrid_heap_after_decode;
    size_t zxing_hybrid_largest_after_decode;
    UBaseType_t stack_hwm_before_zxing;
    UBaseType_t stack_hwm_after_zxing;
    char zxing_hybrid_ecc[8];
    char zxing_hybrid_status[32];
    zxing_qr_packed_result_t zxing_hybrid_meta;

    char status[64];
    char detail[192];
} image_analysis_t;

typedef struct
{
    struct quirc *q;
    int symbol_count;
    const uint8_t *scanner_payload;
    size_t scanner_payload_len;
    image_analysis_t *result;
    TaskHandle_t notify_task;

    int source_offset_x;
    int source_offset_y;
    int scale_num;
    int scale_den;
} decode_task_ctx_t;

static void decode_task(
    void *arg
);

static esp_err_t analyzer_capture_raw_only(
    uart_port_t uart_num,
    image_analysis_t *result
);

static esp_err_t analyzer_binary_probe(
    image_analysis_t *result
);

static void json_escape_small(const char *src, char *dst, size_t dst_size)
{
    if (!dst || dst_size == 0) return;
    size_t w = 0;
    if (!src) src = "";
    for (size_t i = 0; src[i] != '\0' && w + 1 < dst_size; ++i) {
        unsigned char c = (unsigned char)src[i];
        if ((c == '"' || c == '\\') && w + 2 < dst_size) {
            dst[w++] = '\\';
            dst[w++] = (char)c;
        } else if (c >= 0x20) {
            dst[w++] = (char)c;
        }
    }
    dst[w] = '\0';
}

static void format_zxing_metadata_json(const zxing_qr_packed_result_t *r, char *buf, size_t buf_size)
{
    if (!r || !buf || buf_size == 0) return;
    char eci_json[128] = "[]";
    if (r->has_eci) {
        size_t used = 0;
        used += snprintf(eci_json + used, sizeof(eci_json) - used, "[");
        int n = r->eci_count > ZXING_QR_MAX_ECI_VALUES ? ZXING_QR_MAX_ECI_VALUES : r->eci_count;
        for (int i = 0; i < n && used < sizeof(eci_json); ++i)
            used += snprintf(eci_json + used, sizeof(eci_json) - used, "%s%d", i ? "," : "", r->eci_values[i]);
        if (used < sizeof(eci_json)) snprintf(eci_json + used, sizeof(eci_json) - used, "]");
    }
    char sa_id[48], err_msg[192], err_loc[192], sym_id[32], ctype[32], dtype[32];
    json_escape_small(r->structured_append_id, sa_id, sizeof(sa_id));
    json_escape_small(r->error_message, err_msg, sizeof(err_msg));
    json_escape_small(r->error_location, err_loc, sizeof(err_loc));
    json_escape_small(r->symbology_identifier, sym_id, sizeof(sym_id));
    json_escape_small(r->content_type, ctype, sizeof(ctype));
    json_escape_small(r->data_type, dtype, sizeof(dtype));
    bool sa_present = r->structured_append_index >= 0 && r->structured_append_count > 0;
    snprintf(buf, buf_size,
        "{\n"
        "        \"mask\": %d,\n"
        "        \"format_info\": {\"raw_data\":%d,\"hamming_distance\":%d,\"bits_index\":%d,\"mirrored\":%s},\n"
        "        \"content_type\": \"%s\",\n"
        "        \"data_type\": \"%s\",\n"
        "        \"codec_mode_mask\": \"0x%08lX\",\n"
        "        \"has_eci\": %s,\n"
        "        \"eci_values\": %s,\n"
        "        \"structured_append\": {\"present\":%s,\"index\":%d,\"count\":%d,\"id\":\"%s\"},\n"
        "        \"symbology_identifier\": \"%s\",\n"
        "        \"reader_init\": %s,\n"
        "        \"unused_error_correction_margin\": %.3f,\n"
        "        \"corners\": [[%d,%d],[%d,%d],[%d,%d],[%d,%d]],\n"
        "        \"error\": {\"code\":%d,\"type\":\"%s\",\"message\":\"%s\",\"location\":\"%s\"}\n"
        "      }",
        r->mask, r->format_data_raw, r->format_hamming_distance, r->format_bits_index,
        r->mirrored ? "true" : "false", ctype, dtype, (unsigned long)r->codec_mode_mask,
        r->has_eci ? "true" : "false", eci_json, sa_present ? "true" : "false",
        r->structured_append_index, r->structured_append_count, sa_id, sym_id,
        r->reader_init ? "true" : "false", r->unused_error_correction_margin,
        r->corners[0][0], r->corners[0][1], r->corners[1][0], r->corners[1][1],
        r->corners[2][0], r->corners[2][1], r->corners[3][0], r->corners[3][1],
        r->error_type, r->error_type_name, err_msg, err_loc);
}

static esp_err_t analyzer_zxing_packed_probe(
    const uint8_t *scanner_payload,
    size_t scanner_payload_len,
    image_analysis_t *result,
    bool hybrid
);

static esp_err_t analyzer_binary_hybrid_probe(
    image_analysis_t *result
);

static int uart_read_exact(
    uart_port_t uart_num,
    uint8_t *dst,
    size_t length,
    int timeout_ms)
{
    size_t done = 0;
    int elapsed = 0;

    while (done < length && elapsed < timeout_ms)
    {
        int chunk = uart_read_bytes(
            uart_num,
            dst + done,
            length - done,
            pdMS_TO_TICKS(50)
        );

        if (chunk > 0)
        {
            done += (size_t)chunk;
        }

        elapsed += 50;
    }

    return (int)done;
}

static void uart_send(
    uart_port_t uart_num,
    const uint8_t *data,
    size_t length)
{
    uart_write_bytes(
        uart_num,
        data,
        length
    );

    uart_wait_tx_done(
        uart_num,
        pdMS_TO_TICKS(300)
    );
}

static void log_heap(
    const char *label,
    size_t *free_out,
    size_t *largest_out)
{
    size_t free_8bit =
        heap_caps_get_free_size(
            MALLOC_CAP_8BIT
        );

    size_t largest_8bit =
        heap_caps_get_largest_free_block(
            MALLOC_CAP_8BIT
        );

    ESP_LOGI(
        TAG,
        "%s: free_8bit=%u largest_8bit=%u",
        label,
        (unsigned)free_8bit,
        (unsigned)largest_8bit
    );

    if (free_out != NULL)
    {
        *free_out = free_8bit;
    }

    if (largest_out != NULL)
    {
        *largest_out = largest_8bit;
    }
}


static const char *diag_stage_name(
    uint16_t stage)
{
    uint16_t base =
        stage >= AD_FAIL_BASE
            ? (uint16_t)(stage - AD_FAIL_BASE)
            : stage;

    switch (base)
    {
        case AD_SCAN_COMMITTED:
            return "SCAN_COMMITTED";
        case AD_ANALYZER_ENTER:
            return "ANALYZER_ENTER";
        case AD_IDENTITY_DONE:
            return "IDENTITY_DONE";
        case AD_BEFORE_QUIRC:
            return "BEFORE_QUIRC";
        case AD_QUIRC_NEW_OK:
            return "QUIRC_NEW_OK";
        case AD_QUIRC_RESIZE_OK:
            return "QUIRC_RESIZE_OK";
        case AD_QUIRC_BEGIN_OK:
            return "QUIRC_BEGIN_OK";
        case AD_BAUD_READ_OK:
            return "BAUD_READ_OK";
        case AD_BAUD_128_OK:
            return "BAUD_128_OK";
        case AD_IMAGE_REQUEST_SENT:
            return "IMAGE_REQUEST_SENT";
        case AD_IMAGE_HEADER_OK:
            return "IMAGE_HEADER_OK";
        case AD_IMAGE_RX_START:
            return "IMAGE_RX_START";
        case AD_IMAGE_RX_DONE:
            return "IMAGE_RX_DONE";
        case AD_BAUD_115_RESTORED:
            return "BAUD_115_RESTORED";
        case AD_QUIRC_END_DONE:
            return "QUIRC_END_DONE";
        case AD_SYMBOLS_FOUND:
            return "SYMBOLS_FOUND";
        case AD_DECODE_TASK_CREATED:
            return "DECODE_TASK_CREATED";
        case AD_DECODE_DONE:
            return "DECODE_DONE";
        case AD_QUIRC_DESTROYED:
            return "QUIRC_DESTROYED";
        case AD_BINARY_START:
            return "BINARY_START";
        case AD_BINARY_HEAP_SNAPSHOT_OK:
            return "BINARY_HEAP_SNAPSHOT_OK";
        case AD_BINARY_MALLOC_OK:
            return "BINARY_MALLOC_OK";
        case AD_BINARY_POSTALLOC_HEAP_OK:
            return "BINARY_POSTALLOC_HEAP_OK";
        case AD_BINARY_HIST_DONE:
            return "BINARY_HIST_DONE";
        case AD_BINARY_PACK_DONE:
            return "BINARY_PACK_DONE";
        case AD_JSON_BUILT:
            return "JSON_BUILT";
        case AD_FAT_REBUILD_START:
            return "FAT_REBUILD_START";
        case AD_FAT_REBUILD_DONE:
            return "FAT_REBUILD_DONE";
        case AD_USB_CONNECT_CALLED:
            return "USB_CONNECT_CALLED";
        case AD_GUARD_ENTERED:
            return "GUARD_ENTERED";
        default:
            return "UNKNOWN";
    }
}

void analyzer_diag_mark(
    uint16_t stage,
    int32_t error_code)
{
    size_t free_8bit =
        heap_caps_get_free_size(
            MALLOC_CAP_8BIT
        );

    size_t largest_8bit =
        heap_caps_get_largest_free_block(
            MALLOC_CAP_8BIT
        );

    nvs_handle_t handle;

    esp_err_t err =
        nvs_open(
            ANALYZER_NVS_NAMESPACE,
            NVS_READWRITE,
            &handle
        );

    if (err != ESP_OK)
    {
        ESP_LOGW(
            TAG,
            "diag NVS open failed at stage=%u: %s",
            (unsigned)stage,
            esp_err_to_name(err)
        );

        return;
    }

    nvs_set_u16(
        handle,
        ANALYZER_DIAG_STAGE_KEY,
        stage
    );

    nvs_set_i32(
        handle,
        ANALYZER_DIAG_ERROR_KEY,
        error_code
    );

    nvs_set_u32(
        handle,
        ANALYZER_DIAG_FREE_KEY,
        (uint32_t)free_8bit
    );

    nvs_set_u32(
        handle,
        ANALYZER_DIAG_LARGEST_KEY,
        (uint32_t)largest_8bit
    );

    err =
        nvs_commit(
            handle
        );

    nvs_close(
        handle
    );

    ESP_LOGI(
        TAG,
        "DIAG stage=%u%s name=%s err=%ld free=%u largest=%u persist=%s",
        (unsigned)stage,
        stage >= AD_FAIL_BASE ? "(FAIL)" : "",
        diag_stage_name(stage),
        (long)error_code,
        (unsigned)free_8bit,
        (unsigned)largest_8bit,
        esp_err_to_name(err)
    );
}

size_t analyzer_diag_format_last(
    char *buffer,
    size_t buffer_size)
{
    if (buffer == NULL || buffer_size == 0)
    {
        return 0;
    }

    buffer[0] = '\0';

    nvs_handle_t handle;
    esp_err_t err = nvs_open(
        ANALYZER_NVS_NAMESPACE,
        NVS_READONLY,
        &handle
    );

    if (err != ESP_OK)
    {
        int written = snprintf(
            buffer,
            buffer_size,
            "last_analyzer_diag=NONE\r\n"
            "nvs_open=%s\r\n",
            esp_err_to_name(err)
        );
        return written > 0 ? (size_t)written : 0;
    }

    uint16_t stage = 0;
    int32_t error_code = 0;
    uint32_t free_8bit = 0;
    uint32_t largest_8bit = 0;

    esp_err_t stage_err = nvs_get_u16(
        handle,
        ANALYZER_DIAG_STAGE_KEY,
        &stage
    );
    (void)nvs_get_i32(
        handle,
        ANALYZER_DIAG_ERROR_KEY,
        &error_code
    );
    (void)nvs_get_u32(
        handle,
        ANALYZER_DIAG_FREE_KEY,
        &free_8bit
    );
    (void)nvs_get_u32(
        handle,
        ANALYZER_DIAG_LARGEST_KEY,
        &largest_8bit
    );
    nvs_close(handle);

    if (stage_err == ESP_ERR_NVS_NOT_FOUND)
    {
        int written = snprintf(
            buffer,
            buffer_size,
            "last_analyzer_diag=NONE\r\n"
        );
        return written > 0 ? (size_t)written : 0;
    }

    int written = snprintf(
        buffer,
        buffer_size,
        "last_analyzer_diag=PRESENT\r\n"
        "stage=%u\r\n"
        "stage_name=%s\r\n"
        "failed=%s\r\n"
        "error_code=%ld\r\n"
        "free_8bit=%lu\r\n"
        "largest_8bit=%lu\r\n",
        (unsigned)stage,
        diag_stage_name(stage),
        stage >= AD_FAIL_BASE ? "true" : "false",
        (long)error_code,
        (unsigned long)free_8bit,
        (unsigned long)largest_8bit
    );

    if (written < 0)
    {
        buffer[0] = '\0';
        return 0;
    }

    if ((size_t)written >= buffer_size)
    {
        return buffer_size - 1;
    }

    return (size_t)written;
}

void analyzer_diag_print_last(void)
{
    nvs_handle_t handle;

    esp_err_t err =
        nvs_open(
            ANALYZER_NVS_NAMESPACE,
            NVS_READONLY,
            &handle
        );

    if (err != ESP_OK)
    {
        ESP_LOGI(
            TAG,
            "LAST ANALYZER DIAG: none (NVS open: %s)",
            esp_err_to_name(err)
        );

        return;
    }

    uint16_t stage = 0;
    int32_t error_code = 0;
    uint32_t free_8bit = 0;
    uint32_t largest_8bit = 0;

    esp_err_t stage_err =
        nvs_get_u16(
            handle,
            ANALYZER_DIAG_STAGE_KEY,
            &stage
        );

    nvs_get_i32(
        handle,
        ANALYZER_DIAG_ERROR_KEY,
        &error_code
    );

    nvs_get_u32(
        handle,
        ANALYZER_DIAG_FREE_KEY,
        &free_8bit
    );

    nvs_get_u32(
        handle,
        ANALYZER_DIAG_LARGEST_KEY,
        &largest_8bit
    );

    nvs_close(
        handle
    );

    if (
        stage_err ==
        ESP_ERR_NVS_NOT_FOUND)
    {
        ESP_LOGI(
            TAG,
            "LAST ANALYZER DIAG: none recorded"
        );

        return;
    }

    ESP_LOGW(
        TAG,
        "LAST ANALYZER DIAG: stage=%u%s name=%s err=%ld free=%lu largest=%lu",
        (unsigned)stage,
        stage >= AD_FAIL_BASE ? "(FAIL)" : "",
        diag_stage_name(stage),
        (long)error_code,
        (unsigned long)free_8bit,
        (unsigned long)largest_8bit
    );
}

typedef struct
{
    uint8_t pid;
    uint8_t fid;
    const char *json_key;
} scanner_status_query_t;

static void sanitize_status_value(
    char *dst,
    size_t dst_size,
    const uint8_t *src,
    size_t src_len)
{
    if (dst_size == 0)
    {
        return;
    }

    size_t out = 0;

    for (size_t i = 0;
         i < src_len &&
         out + 1 < dst_size;
         ++i)
    {
        uint8_t c = src[i];

        if (
            c >= 0x20 &&
            c <= 0x7E &&
            c != '"' &&
            c != '\\')
        {
            dst[out++] = (char)c;
        }
        else if (
            c == '"' ||
            c == '\\')
        {
            dst[out++] = '_';
        }
        else
        {
            dst[out++] = '.';
        }
    }

    dst[out] = 0;
}

static void scanner_status_read_string(
    uart_port_t uart_num,
    uint8_t pid,
    uint8_t fid,
    char *value,
    size_t value_size)
{
    const uint8_t command[3] = {
        0x43,
        pid,
        fid
    };

    uint8_t byte = 0;

    if (value_size == 0)
    {
        return;
    }

    value[0] = 0;

    uart_flush_input(
        uart_num
    );

    uart_send(
        uart_num,
        command,
        sizeof(command)
    );

    if (
        uart_read_exact(
            uart_num,
            &byte,
            1,
            STATUS_QUERY_TIMEOUT_MS) != 1)
    {
        snprintf(
            value,
            value_size,
            "TIMEOUT"
        );

        return;
    }

    if (byte != 0x44)
    {
        snprintf(
            value,
            value_size,
            "PROTOCOL_0x%02X",
            byte
        );

        uart_flush_input(
            uart_num
        );

        return;
    }

    if (
        uart_read_exact(
            uart_num,
            &byte,
            1,
            STATUS_QUERY_TIMEOUT_MS) != 1)
    {
        snprintf(
            value,
            value_size,
            "HEADER_TIMEOUT"
        );

        return;
    }

    if (byte == 0x00)
    {
        snprintf(
            value,
            value_size,
            "UNSUPPORTED"
        );

        return;
    }

    if (byte != pid)
    {
        snprintf(
            value,
            value_size,
            "PID_MISMATCH_%02X",
            byte
        );

        uart_flush_input(
            uart_num
        );

        return;
    }

    uint8_t tail[3] = {0};

    if (
        uart_read_exact(
            uart_num,
            tail,
            sizeof(tail),
            STATUS_QUERY_TIMEOUT_MS) !=
        (int)sizeof(tail))
    {
        snprintf(
            value,
            value_size,
            "HEADER_TIMEOUT"
        );

        return;
    }

    if (tail[0] != fid)
    {
        snprintf(
            value,
            value_size,
            "FID_MISMATCH_%02X",
            tail[0]
        );

        uart_flush_input(
            uart_num
        );

        return;
    }

    uint16_t length =
        ((uint16_t)tail[1] << 8) |
        tail[2];

    if (length == 0)
    {
        snprintf(
            value,
            value_size,
            "EMPTY"
        );

        return;
    }

    if (length > STATUS_VALUE_MAX)
    {
        snprintf(
            value,
            value_size,
            "TOO_LONG_%u",
            (unsigned)length
        );

        uart_flush_input(
            uart_num
        );

        return;
    }

    uint8_t raw[STATUS_VALUE_MAX];

    int got =
        uart_read_exact(
            uart_num,
            raw,
            length,
            STATUS_QUERY_TIMEOUT_MS
        );

    if (got != (int)length)
    {
        snprintf(
            value,
            value_size,
            "DATA_TIMEOUT_%d_OF_%u",
            got,
            (unsigned)length
        );

        uart_flush_input(
            uart_num
        );

        return;
    }

    sanitize_status_value(
        value,
        value_size,
        raw,
        length
    );
}

static void scanner_identity_query(
    uart_port_t uart_num,
    char *identity_json,
    size_t identity_json_size)
{
    static const scanner_status_query_t queries[] = {
        {
            0x02,
            0xC1,
            "firmware_version"
        },
        {
            0x02,
            0xC2,
            "software_version"
        },
        {
            0x02,
            0xC4,
            "hardware_version"
        },
        {
            0x02,
            0xC5,
            "serial_number"
        },
        {
            0x02,
            0xC6,
            "production_date"
        },
        {
            0x02,
            0xC7,
            "hardware_model"
        },
        {
            0x02,
            0xC8,
            "hardware_specification"
        },
    };

    char values[
        sizeof(queries) /
        sizeof(queries[0])
    ][STATUS_VALUE_MAX + 24];

    for (
        size_t i = 0;
        i <
        sizeof(queries) /
        sizeof(queries[0]);
        ++i)
    {
        scanner_status_read_string(
            uart_num,
            queries[i].pid,
            queries[i].fid,
            values[i],
            sizeof(values[i])
        );

        ESP_LOGI(
            TAG,
            "scanner identity %s=%s",
            queries[i].json_key,
            values[i]
        );
    }

    snprintf(
        identity_json,
        identity_json_size,
        "{"
        "\"firmware_version\":\"%s\","
        "\"software_version\":\"%s\","
        "\"hardware_version\":\"%s\","
        "\"serial_number\":\"%s\","
        "\"production_date\":\"%s\","
        "\"hardware_model\":\"%s\","
        "\"hardware_specification\":\"%s\""
        "}",
        values[0],
        values[1],
        values[2],
        values[3],
        values[4],
        values[5],
        values[6]
    );
}

static const char *observed_symbology_name(
    uint16_t code_id)
{
    if (code_id == 0x0057)
    {
        return "QR_CODE";
    }

    return "UNKNOWN";
}

static const char *observed_symbology_mapping_source(
    uint16_t code_id)
{
    if (code_id == 0x0057)
    {
        return "OBSERVED_ATOMIC_QRCODE2";
    }

    return "UNMAPPED";
}

static const char *ecc_name(
    int ecc)
{
    switch (ecc)
    {
        case 0:
            return "M";

        case 1:
            return "L";

        case 2:
            return "H";

        case 3:
            return "Q";

        default:
            return "UNKNOWN";
    }
}

static const char *data_type_name(
    int data_type)
{
    switch (data_type)
    {
        case 1:
            return "NUMERIC";

        case 2:
            return "ALPHANUMERIC";

        case 4:
            return "BYTE";

        case 8:
            return "KANJI";

        default:
            return "UNKNOWN_OR_MIXED";
    }
}

static esp_err_t analyzer_uart_install(
    uart_port_t uart_num)
{
    uart_config_t config = {
        .baud_rate = ANALYZER_BAUD_NORMAL,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT
    };

    esp_err_t err =
        uart_driver_install(
            uart_num,
            ANALYZER_UART_RX_BUFFER_SIZE,
            0,
            0,
            NULL,
            0
        );

    if (err != ESP_OK)
    {
        return err;
    }

    err =
        uart_param_config(
            uart_num,
            &config
        );

    if (err != ESP_OK)
    {
        uart_driver_delete(
            uart_num
        );
        return err;
    }

    err =
        uart_set_pin(
            uart_num,
            ANALYZER_UART_TX_GPIO,
            ANALYZER_UART_RX_GPIO,
            UART_PIN_NO_CHANGE,
            UART_PIN_NO_CHANGE
        );

    if (err != ESP_OK)
    {
        uart_driver_delete(
            uart_num
        );
        return err;
    }

    return ESP_OK;
}


static bool receive_image_native_crop(
    uart_port_t uart_num,
    uint8_t *crop_image,
    int crop_x,
    int crop_y,
    int crop_width,
    int crop_height)
{
    if (
        crop_image == NULL ||
        crop_x < 0 ||
        crop_y < 0 ||
        crop_width <= 0 ||
        crop_height <= 0 ||
        crop_x + crop_width > ANALYZER_SOURCE_WIDTH ||
        crop_y + crop_height > ANALYZER_SOURCE_HEIGHT)
    {
        return false;
    }

    uint8_t *src_row =
        heap_caps_malloc(
            ANALYZER_SOURCE_WIDTH,
            MALLOC_CAP_8BIT
        );

    if (src_row == NULL)
    {
        return false;
    }

    bool ok = true;

    for (
        int src_y = 0;
        src_y < ANALYZER_SOURCE_HEIGHT;
        ++src_y)
    {
        int got =
            uart_read_exact(
                uart_num,
                src_row,
                ANALYZER_SOURCE_WIDTH,
                IMAGE_BODY_GAP_MS
            );

        if (
            got != ANALYZER_SOURCE_WIDTH)
        {
            ok = false;
            break;
        }

        if (
            src_y >= crop_y &&
            src_y < crop_y + crop_height)
        {
            memcpy(
                crop_image +
                    (size_t)(src_y - crop_y) *
                    (size_t)crop_width,
                src_row + crop_x,
                (size_t)crop_width
            );
        }
    }

    heap_caps_free(
        src_row
    );

    return ok;
}

static bool request_native_raw_header(
    uart_port_t uart_num)
{
    uart_flush_input(
        uart_num
    );

    uart_send(
        uart_num,
        CMD_IMAGE_RAW_640X480,
        sizeof(CMD_IMAGE_RAW_640X480)
    );

    uint8_t command = 0;

    if (
        uart_read_exact(
            uart_num,
            &command,
            1,
            IMAGE_HEADER_TIMEOUT_MS) != 1 ||
        command != 0x61)
    {
        return false;
    }

    uint8_t header[10] = {0};

    if (
        uart_read_exact(
            uart_num,
            header,
            sizeof(header),
            IMAGE_HEADER_TIMEOUT_MS) !=
        (int)sizeof(header))
    {
        return false;
    }

    if (header[0] == 0x00)
    {
        return false;
    }

    uint16_t width =
        ((uint16_t)header[0] << 8) |
        header[1];

    uint16_t height =
        ((uint16_t)header[2] << 8) |
        header[3];

    uint8_t type =
        header[4];

    uint32_t bytes =
        ((uint32_t)header[6] << 24) |
        ((uint32_t)header[7] << 16) |
        ((uint32_t)header[8] << 8) |
        header[9];

    return
        width == ANALYZER_SOURCE_WIDTH &&
        height == ANALYZER_SOURCE_HEIGHT &&
        (type & 0x0F) == 0 &&
        bytes == ANALYZER_SOURCE_BYTES;
}

static bool compute_native_crop(
    image_analysis_t *result)
{
    int min_x = ANALYZER_SOURCE_WIDTH - 1;
    int min_y = ANALYZER_SOURCE_HEIGHT - 1;
    int max_x = 0;
    int max_y = 0;

    for (int i = 0; i < 4; ++i)
    {
        int x = result->corners[i][0];
        int y = result->corners[i][1];

        if (x < min_x) min_x = x;
        if (x > max_x) max_x = x;
        if (y < min_y) min_y = y;
        if (y > max_y) max_y = y;
    }

    int qr_w = max_x - min_x + 1;
    int qr_h = max_y - min_y + 1;

    if (qr_w < 16 || qr_h < 16)
    {
        return false;
    }

    /*
     * Preserve a generous quiet-zone/background margin around the detected
     * symbol. Use 25% of the larger dimension, at least 24 native pixels.
     */
    int max_dim =
        qr_w > qr_h ? qr_w : qr_h;

    int margin =
        max_dim / 4;

    if (margin < 24)
    {
        margin = 24;
    }

    int x0 = min_x - margin;
    int y0 = min_y - margin;
    int x1 = max_x + margin;
    int y1 = max_y + margin;

    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 >= ANALYZER_SOURCE_WIDTH) x1 = ANALYZER_SOURCE_WIDTH - 1;
    if (y1 >= ANALYZER_SOURCE_HEIGHT) y1 = ANALYZER_SOURCE_HEIGHT - 1;

    int width = x1 - x0 + 1;
    int height = y1 - y0 + 1;

    /*
     * The integrated product measured largest contiguous blocks around
     * 270 KiB. Keep crop allocation below 240 KiB for operating margin.
     */
    const int max_crop_bytes = 240 * 1024;

    if (width * height > max_crop_bytes)
    {
        return false;
    }

    result->crop_x = x0;
    result->crop_y = y0;
    result->crop_width = width;
    result->crop_height = height;

    return true;
}

static esp_err_t run_native_crop_decode(
    uart_port_t uart_num,
    const uint8_t *payload,
    size_t payload_len,
    image_analysis_t *result)
{
    result->native_crop_attempted = true;

    if (!compute_native_crop(result))
    {
        bool have_geometry = false;

        for (int i = 0; i < 4; ++i)
        {
            if (
                result->corners[i][0] != 0 ||
                result->corners[i][1] != 0)
            {
                have_geometry = true;
                break;
            }
        }

        snprintf(
            result->status,
            sizeof(result->status),
            have_geometry
                ? "NATIVE_CROP_TOO_LARGE"
                : "NATIVE_CROP_NO_GEOMETRY"
        );

        snprintf(
            result->detail,
            sizeof(result->detail),
            have_geometry
                ? "Detected QR crop cannot fit safely in contiguous RAM"
                : "QR was detected but corner geometry was unavailable"
        );

        ESP_LOGW(
            TAG,
            "native crop rejected: corners=[(%d,%d),(%d,%d),(%d,%d),(%d,%d)]",
            result->corners[0][0], result->corners[0][1],
            result->corners[1][0], result->corners[1][1],
            result->corners[2][0], result->corners[2][1],
            result->corners[3][0], result->corners[3][1]
        );

        return have_geometry ? ESP_ERR_NO_MEM : ESP_ERR_INVALID_STATE;
    }

    ESP_LOGI(
        TAG,
        "native crop retry: x=%d y=%d w=%d h=%d bytes=%d",
        result->crop_x,
        result->crop_y,
        result->crop_width,
        result->crop_height,
        result->crop_width * result->crop_height
    );

    struct quirc *q =
        quirc_new();

    if (q == NULL)
    {
        return ESP_ERR_NO_MEM;
    }

    if (
        quirc_resize(
            q,
            result->crop_width,
            result->crop_height) < 0)
    {
        quirc_destroy(q);
        return ESP_ERR_NO_MEM;
    }

    int w = 0;
    int h = 0;

    uint8_t *image =
        quirc_begin(
            q,
            &w,
            &h
        );

    if (
        image == NULL ||
        w != result->crop_width ||
        h != result->crop_height)
    {
        quirc_destroy(q);
        return ESP_FAIL;
    }

    if (!request_native_raw_header(uart_num))
    {
        quirc_destroy(q);
        return ESP_ERR_INVALID_RESPONSE;
    }

    int64_t start_us =
        esp_timer_get_time();

    if (
        !receive_image_native_crop(
            uart_num,
            image,
            result->crop_x,
            result->crop_y,
            result->crop_width,
            result->crop_height))
    {
        quirc_destroy(q);
        return ESP_ERR_TIMEOUT;
    }

    result->second_transfer_ms =
        (esp_timer_get_time() - start_us) /
        1000;

    quirc_end(q);

    int count =
        quirc_count(q);

    if (count <= 0)
    {
        quirc_destroy(q);

        snprintf(
            result->status,
            sizeof(result->status),
            "NATIVE_CROP_NO_SYMBOL"
        );

        snprintf(
            result->detail,
            sizeof(result->detail),
            "Native-resolution crop received but quirc found no symbol"
        );

        return ESP_ERR_NOT_FOUND;
    }

    decode_task_ctx_t context = {
        .q = q,
        .symbol_count = count,
        .scanner_payload = payload,
        .scanner_payload_len = payload_len,
        .result = result,
        .notify_task = xTaskGetCurrentTaskHandle(),
        .source_offset_x = result->crop_x,
        .source_offset_y = result->crop_y,
        .scale_num = 1,
        .scale_den = 1
    };

    BaseType_t created =
        xTaskCreate(
            decode_task,
            "qrt_crop_decode",
            DECODE_TASK_STACK_BYTES,
            &context,
            5,
            NULL
        );

    if (created != pdPASS)
    {
        quirc_destroy(q);
        return ESP_ERR_NO_MEM;
    }

    uint32_t notified =
        ulTaskNotifyTake(
            pdTRUE,
            pdMS_TO_TICKS(
                DECODE_TASK_TIMEOUT_MS
            )
        );

    if (notified == 0)
    {
        return ESP_ERR_TIMEOUT;
    }

    if (result->quirc_decoded)
    {
        result->native_crop_used = true;

        snprintf(
            result->status,
            sizeof(result->status),
            "QUIRC_OK"
        );

        snprintf(
            result->detail,
            sizeof(result->detail),
            "First pass detected QR at 480x360; second native-resolution crop decoded with quirc"
        );
    }

    quirc_destroy(q);

    return
        result->quirc_decoded
            ? ESP_OK
            : ESP_FAIL;
}


static void decode_task(
    void *arg)
{
    decode_task_ctx_t *ctx =
        (decode_task_ctx_t *)arg;

    image_analysis_t *result =
        ctx->result;

    /*
     * Allocate quirc_code first.  The first-pass 600x480 quirc image leaves
     * very little contiguous heap after the decode task stack is allocated.
     * Detector geometry is needed for the native-crop retry even if the much
     * larger quirc_data allocation cannot be satisfied.  Therefore do not
     * allocate quirc_data until after quirc_extract() has copied the corners
     * into result.
     */
    struct quirc_code *code =
        heap_caps_malloc(
            sizeof(struct quirc_code),
            MALLOC_CAP_8BIT
        );

    struct quirc_data *data = NULL;

    if (code == NULL)
    {
        snprintf(
            result->status,
            sizeof(result->status),
            "DECODE_CODE_OOM"
        );

        snprintf(
            result->detail,
            sizeof(result->detail),
            "Unable to allocate quirc_code; detector geometry unavailable"
        );

        xTaskNotifyGive(
            ctx->notify_task
        );

        vTaskDelete(
            NULL
        );

        return;
    }

    ESP_LOGI(
        TAG,
        "decoder objects: code=%u data=%u",
        (unsigned)sizeof(struct quirc_code),
        (unsigned)sizeof(struct quirc_data)
    );

    bool any_decode_ok = false;

    for (
        int i = 0;
        i < ctx->symbol_count;
        ++i)
    {
        quirc_extract(
            ctx->q,
            i,
            code
        );

        /*
         * Always retain detector geometry, even when RS/payload decode fails.
         * This is used by the native-crop second pass.
         */
        for (
            int corner = 0;
            corner < 4;
            ++corner)
        {
            result->corners_analysis[corner][0] =
                code->corners[corner].x;

            result->corners_analysis[corner][1] =
                code->corners[corner].y;

            result->corners[corner][0] =
                ctx->source_offset_x +
                (code->corners[corner].x *
                    ctx->scale_num +
                    ctx->scale_den / 2) /
                    ctx->scale_den;

            result->corners[corner][1] =
                ctx->source_offset_y +
                (code->corners[corner].y *
                    ctx->scale_num +
                    ctx->scale_den / 2) /
                    ctx->scale_den;
        }

        if (data == NULL)
        {
            data =
                heap_caps_malloc(
                    sizeof(struct quirc_data),
                    MALLOC_CAP_8BIT
                );

            if (data == NULL)
            {
                ESP_LOGW(
                    TAG,
                    "quirc_data allocation failed after geometry extraction; native crop retry can still proceed"
                );

                snprintf(
                    result->status,
                    sizeof(result->status),
                    "DECODE_DATA_OOM"
                );

                snprintf(
                    result->detail,
                    sizeof(result->detail),
                    "QR geometry captured but quirc_data allocation failed; retrying native crop"
                );

                break;
            }
        }

        quirc_decode_error_t err =
            quirc_decode(
                code,
                data
            );

        ESP_LOGI(
            TAG,
            "symbol[%d] size=%d corners=[(%d,%d),(%d,%d),(%d,%d),(%d,%d)] decode=%s",
            i,
            code->size,
            code->corners[0].x,
            code->corners[0].y,
            code->corners[1].x,
            code->corners[1].y,
            code->corners[2].x,
            code->corners[2].y,
            code->corners[3].x,
            code->corners[3].y,
            quirc_strerror(err)
        );

        if (
            err !=
            QUIRC_SUCCESS)
        {
            continue;
        }

        bool payload_match =
            data->payload_len ==
                ctx->scanner_payload_len &&
            memcmp(
                data->payload,
                ctx->scanner_payload,
                ctx->scanner_payload_len
            ) == 0;

        /*
         * The product scanner supports a single barcode in this path.
         * Prefer the successfully decoded symbol that matches the scanner
         * payload. If only one symbol is present, accept it even if the
         * comparison differs so diagnostics remain useful.
         */
        if (
            !payload_match &&
            ctx->symbol_count > 1)
        {
            continue;
        }

        any_decode_ok = true;

        result->quirc_decoded =
            true;

        result->version =
            data->version;

        result->ecc_level =
            data->ecc_level;

        result->mask =
            data->mask;

        result->data_type =
            data->data_type;

        result->eci =
            data->eci;

        result->decoded_payload_len =
            data->payload_len;

        result->payload_match =
            payload_match;

        snprintf(
            result->status,
            sizeof(result->status),
            "QUIRC_OK"
        );

        snprintf(
            result->detail,
            sizeof(result->detail),
            "640x480 RAW center-cropped to 600x480 with no resampling; native pixel pitch quirc decode"
        );

        break;
    }

    if (
        !any_decode_ok &&
        data != NULL)
    {
        snprintf(
            result->status,
            sizeof(result->status),
            "QUIRC_DECODE_FAILED"
        );

        snprintf(
            result->detail,
            sizeof(result->detail),
            "QR symbol detected but quirc decode failed"
        );
    }

    if (data != NULL)
    {
        heap_caps_free(
            data
        );
    }

    heap_caps_free(
        code
    );

    xTaskNotifyGive(
        ctx->notify_task
    );

    vTaskDelete(
        NULL
    );
}


/*
 * Analyzer-only binary diagnostic.
 *
 * The scanner RAW frame is already committed to Flash. Read it twice in
 * 640-byte rows: first to build a 256-bin histogram and derive an Otsu
 * threshold, then to pack the full 640x480 image into 1 bit/pixel. The
 * packed image remains a diagnostic artifact only; QR detection and decode
 * are performed by stock quirc on downscaled grayscale images.
 */
static uint8_t analyzer_otsu_threshold(
    const uint32_t histogram[256],
    uint32_t total_pixels)
{
    uint64_t sum_all = 0;
    for (int i = 0; i < 256; ++i)
    {
        sum_all += (uint64_t)i * histogram[i];
    }

    uint64_t sum_background = 0;
    uint32_t weight_background = 0;
    double best_variance = -1.0;
    uint8_t best_threshold = 0;

    for (int t = 0; t < 256; ++t)
    {
        weight_background += histogram[t];
        if (weight_background == 0)
        {
            continue;
        }

        uint32_t weight_foreground =
            total_pixels - weight_background;
        if (weight_foreground == 0)
        {
            break;
        }

        sum_background +=
            (uint64_t)t * histogram[t];

        double mean_background =
            (double)sum_background /
            (double)weight_background;
        double mean_foreground =
            (double)(sum_all - sum_background) /
            (double)weight_foreground;
        double delta =
            mean_background - mean_foreground;
        double variance =
            (double)weight_background *
            (double)weight_foreground *
            delta * delta;

        if (variance > best_variance)
        {
            best_variance = variance;
            best_threshold = (uint8_t)t;
        }
    }

    return best_threshold;
}

static esp_err_t analyzer_capture_raw_only(
    uart_port_t uart_num,
    image_analysis_t *result)
{
    esp_err_t err = flash_store_raw_begin();
    if (err != ESP_OK)
    {
        return err;
    }

    uart_flush_input(uart_num);
    uart_send(uart_num, CMD_IMAGE_RAW_640X480, sizeof(CMD_IMAGE_RAW_640X480));
    analyzer_diag_mark(AD_IMAGE_REQUEST_SENT, 0);

    uint8_t command = 0;
    if (uart_read_exact(uart_num, &command, 1, IMAGE_HEADER_TIMEOUT_MS) != 1 || command != 0x61)
    {
        return ESP_ERR_TIMEOUT;
    }

    uint8_t first = 0;
    if (uart_read_exact(uart_num, &first, 1, IMAGE_HEADER_TIMEOUT_MS) != 1)
    {
        return ESP_ERR_TIMEOUT;
    }
    if (first == 0x00)
    {
        return ESP_ERR_NOT_SUPPORTED;
    }

    uint8_t header[10] = {0};
    header[0] = first;
    if (uart_read_exact(uart_num, &header[1], 9, IMAGE_HEADER_TIMEOUT_MS) != 9)
    {
        return ESP_ERR_TIMEOUT;
    }

    result->image_width = ((uint16_t)header[0] << 8) | header[1];
    result->image_height = ((uint16_t)header[2] << 8) | header[3];
    result->image_type = header[4];
    result->image_bytes = ((uint32_t)header[6] << 24) |
                          ((uint32_t)header[7] << 16) |
                          ((uint32_t)header[8] << 8) |
                          header[9];

    if (result->image_width != ANALYZER_SOURCE_WIDTH ||
        result->image_height != ANALYZER_SOURCE_HEIGHT ||
        (result->image_type & 0x0F) != 0 ||
        result->image_bytes != ANALYZER_SOURCE_BYTES)
    {
        return ESP_ERR_INVALID_RESPONSE;
    }

    result->image_supported = true;
    analyzer_diag_mark(AD_IMAGE_HEADER_OK, (int32_t)result->image_bytes);

    uint8_t *row = heap_caps_malloc(ANALYZER_SOURCE_WIDTH, MALLOC_CAP_8BIT);
    if (row == NULL)
    {
        return ESP_ERR_NO_MEM;
    }

    int64_t start_us = esp_timer_get_time();
    analyzer_diag_mark(AD_IMAGE_RX_START, 0);
    for (int y = 0; y < ANALYZER_SOURCE_HEIGHT; ++y)
    {
        if (uart_read_exact(uart_num, row, ANALYZER_SOURCE_WIDTH, IMAGE_BODY_GAP_MS) != ANALYZER_SOURCE_WIDTH)
        {
            heap_caps_free(row);
            return ESP_ERR_TIMEOUT;
        }
        err = flash_store_raw_write((size_t)y * ANALYZER_SOURCE_WIDTH, row, ANALYZER_SOURCE_WIDTH);
        if (err != ESP_OK)
        {
            heap_caps_free(row);
            return err;
        }
        if ((y & 15) == 15)
        {
            taskYIELD();
        }
    }
    heap_caps_free(row);
    result->transfer_ms = (esp_timer_get_time() - start_us) / 1000;

    err = flash_store_raw_commit();
    if (err != ESP_OK)
    {
        return err;
    }
    analyzer_diag_mark(AD_IMAGE_RX_DONE, (int32_t)result->transfer_ms);
    return ESP_OK;
}

static esp_err_t analyzer_binary_probe(
    image_analysis_t *result)
{
    if (result == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    result->binary_probe_attempted = true;
    result->binary_bytes = ANALYZER_BINARY_BYTES;

    analyzer_diag_mark(AD_BINARY_START, 0);

    static uint32_t histogram[256];
    static uint8_t row[ANALYZER_SOURCE_WIDTH];
    static uint8_t packed_row[ANALYZER_BINARY_ROW_BYTES];

    memset(histogram, 0, sizeof(histogram));

    int64_t histogram_start = esp_timer_get_time();

    for (size_t y = 0; y < ANALYZER_SOURCE_HEIGHT; ++y)
    {
        esp_err_t err = flash_store_raw_read(
            y * ANALYZER_SOURCE_WIDTH, row, sizeof(row));
        if (err != ESP_OK) return err;

        for (size_t x = 0; x < ANALYZER_SOURCE_WIDTH; ++x)
        {
            ++histogram[row[x]];
        }

        if ((y & 0x0Fu) == 0x0Fu)
        {
            analyzer_progress_hook();
            vTaskDelay(pdMS_TO_TICKS(1));
        }
    }

    result->binary_histogram_ms =
        (esp_timer_get_time() - histogram_start) / 1000;
    result->binary_otsu_threshold =
        analyzer_otsu_threshold(histogram, ANALYZER_SOURCE_BYTES);

    analyzer_diag_mark(AD_BINARY_HIST_DONE, 0);

    int64_t pack_start = esp_timer_get_time();
    uint32_t black_pixels = 0;
    uint32_t checksum = 2166136261u;

    for (size_t y = 0; y < ANALYZER_SOURCE_HEIGHT; ++y)
    {
        esp_err_t err = flash_store_raw_read(
            y * ANALYZER_SOURCE_WIDTH, row, sizeof(row));
        if (err != ESP_OK) return err;

        memset(packed_row, 0, sizeof(packed_row));

        for (size_t x = 0; x < ANALYZER_SOURCE_WIDTH; ++x)
        {
            if (row[x] <= result->binary_otsu_threshold)
            {
                packed_row[x >> 3] |= (uint8_t)(0x80u >> (x & 7));
                ++black_pixels;
            }
        }

        for (size_t i = 0; i < ANALYZER_BINARY_ROW_BYTES; ++i)
        {
            checksum ^= packed_row[i];
            checksum *= 16777619u;
        }

        err = flash_store_binary_write(
            y * ANALYZER_BINARY_ROW_BYTES, packed_row, sizeof(packed_row));
        if (err != ESP_OK) return err;

        if ((y & 0x0Fu) == 0x0Fu)
        {
            analyzer_progress_hook();
            vTaskDelay(pdMS_TO_TICKS(1));
        }
    }

    esp_err_t commit_err = flash_store_binary_commit();
    if (commit_err != ESP_OK) return commit_err;

    result->binary_pack_ms =
        (esp_timer_get_time() - pack_start) / 1000;
    result->binary_black_pixels = black_pixels;
    result->binary_checksum = checksum;
    result->binary_probe_ready = true;

    result->heap_before_binary = 0;
    result->largest_before_binary = 0;
    result->heap_with_binary = 0;
    result->largest_with_binary = 0;

    analyzer_diag_mark(AD_BINARY_PACK_DONE, 0);

    ESP_LOGI(
        TAG,
        "Flash-backed compact 1bpp ready: threshold=%u bytes=%u black=%u hist=%lldms pack=%lldms checksum=%08lX",
        (unsigned)result->binary_otsu_threshold,
        (unsigned)result->binary_bytes,
        (unsigned)result->binary_black_pixels,
        (long long)result->binary_histogram_ms,
        (long long)result->binary_pack_ms,
        (unsigned long)result->binary_checksum
    );

    return ESP_OK;
}



/* Compact Hybrid binarizer derived from ZXing-C++ HybridBinarizer. */
static esp_err_t analyzer_binary_hybrid_probe(image_analysis_t *result)
{
    enum { BLOCK = 8, SUB_W = ANALYZER_SOURCE_WIDTH / BLOCK,
           SUB_H = ANALYZER_SOURCE_HEIGHT / BLOCK, RANGE = 24, R = 2 };

    static uint8_t thresholds[SUB_W * SUB_H];
    static uint8_t smooth[SUB_W * SUB_H];
    static uint8_t rows[BLOCK][ANALYZER_SOURCE_WIDTH];
    static uint8_t packed_rows[BLOCK][ANALYZER_BINARY_ROW_BYTES];

    if (!result) return ESP_ERR_INVALID_ARG;

    int64_t t0 = esp_timer_get_time();
    memset(thresholds, 0, sizeof(thresholds));
    memset(smooth, 0, sizeof(smooth));

    for (int by = 0; by < SUB_H; ++by) {
        size_t y0 = (size_t)by * BLOCK;
        for (int yy = 0; yy < BLOCK; ++yy) {
            esp_err_t err = flash_store_raw_read((y0 + yy) * ANALYZER_SOURCE_WIDTH,
                                                 rows[yy], ANALYZER_SOURCE_WIDTH);
            if (err != ESP_OK) return err;
        }
        for (int bx = 0; bx < SUB_W; ++bx) {
            uint8_t mn = 255, mx = 0;
            int x0 = bx * BLOCK;
            for (int yy = 0; yy < BLOCK; ++yy) {
                for (int xx = 0; xx < BLOCK; ++xx) {
                    uint8_t v = rows[yy][x0 + xx];
                    if (v < mn) mn = v;
                    if (v > mx) mx = v;
                }
            }
            thresholds[by * SUB_W + bx] =
                ((int)mx - (int)mn > RANGE) ? (uint8_t)(((int)mx + mn) / 2) : 0;
        }
        if ((by & 7) == 7) {
            analyzer_progress_hook();
            taskYIELD();
        }
    }

    for (int by = 0; by < SUB_H; ++by) {
        for (int bx = 0; bx < SUB_W; ++bx) {
            int left = bx < R ? R : (bx > SUB_W - R - 1 ? SUB_W - R - 1 : bx);
            int top = by < R ? R : (by > SUB_H - R - 1 ? SUB_H - R - 1 : by);
            int center = thresholds[by * SUB_W + bx];
            int sum = center * 2;
            int n = center > 0 ? 2 : 0;
            for (int dy = -R; dy <= R; ++dy) {
                for (int dx = -R; dx <= R; ++dx) {
                    int v = thresholds[(top + dy) * SUB_W + (left + dx)];
                    sum += v;
                    n += v > 0;
                }
            }
            smooth[by * SUB_W + bx] = n > 0 ? (uint8_t)(sum / n) : 0;
        }
    }

    int last = -1;
    const int count = SUB_W * SUB_H;
    for (int i = 0; i < count; ++i) {
        if (smooth[i] != 0) {
            if (last + 1 < i)
                memset(&smooth[last + 1], smooth[i], (size_t)(i - last - 1));
            last = i;
        }
    }
    if (last >= 0 && last + 1 < count)
        memset(&smooth[last + 1], smooth[last], (size_t)(count - last - 1));

    const bool global_fallback = last < 0;

    esp_err_t begin_err = flash_store_binary_begin();
    if (begin_err != ESP_OK) return begin_err;

    uint32_t black = 0;
    uint32_t checksum = 2166136261u;
    for (int by = 0; by < SUB_H; ++by) {
        size_t y0 = (size_t)by * BLOCK;
        for (int yy = 0; yy < BLOCK; ++yy) {
            esp_err_t err = flash_store_raw_read((y0 + yy) * ANALYZER_SOURCE_WIDTH,
                                                 rows[yy], ANALYZER_SOURCE_WIDTH);
            if (err != ESP_OK) return err;
            memset(packed_rows[yy], 0, ANALYZER_BINARY_ROW_BYTES);
        }
        for (int bx = 0; bx < SUB_W; ++bx) {
            uint8_t threshold = global_fallback
                ? result->binary_otsu_threshold
                : smooth[by * SUB_W + bx];
            int x0 = bx * BLOCK;
            for (int yy = 0; yy < BLOCK; ++yy) {
                for (int xx = 0; xx < BLOCK; ++xx) {
                    int x = x0 + xx;
                    if (rows[yy][x] <= threshold) {
                        packed_rows[yy][x >> 3] |= (uint8_t)(0x80u >> (x & 7));
                        ++black;
                    }
                }
            }
        }
        for (int yy = 0; yy < BLOCK; ++yy) {
            for (size_t i = 0; i < ANALYZER_BINARY_ROW_BYTES; ++i) {
                checksum ^= packed_rows[yy][i];
                checksum *= 16777619u;
            }
            esp_err_t err = flash_store_binary_write((y0 + yy) * ANALYZER_BINARY_ROW_BYTES,
                                                     packed_rows[yy], ANALYZER_BINARY_ROW_BYTES);
            if (err != ESP_OK) return err;
        }
        if ((by & 7) == 7) {
            analyzer_progress_hook();
            taskYIELD();
        }
    }

    esp_err_t commit_err = flash_store_binary_commit();
    if (commit_err != ESP_OK) return commit_err;

    result->binary_hybrid_ms = (esp_timer_get_time() - t0) / 1000;
    result->binary_hybrid_black_pixels = black;
    result->binary_hybrid_checksum = checksum;
    return ESP_OK;
}

static esp_err_t analyzer_zxing_packed_probe(
    const uint8_t *scanner_payload,
    size_t scanner_payload_len,
    image_analysis_t *result,
    bool hybrid)
{
    if (!result) return ESP_ERR_INVALID_ARG;

    bool *attempted = hybrid ? &result->zxing_hybrid_attempted : &result->zxing_attempted;
    bool *decoded = hybrid ? &result->zxing_hybrid_decoded : &result->zxing_decoded;
    bool *payload_match = hybrid ? &result->zxing_hybrid_payload_match : &result->zxing_payload_match;
    int *finder_patterns = hybrid ? &result->zxing_hybrid_finder_patterns : &result->zxing_finder_patterns;
    int *candidate_sets = hybrid ? &result->zxing_hybrid_candidate_sets : &result->zxing_candidate_sets;
    int *decode_attempts = hybrid ? &result->zxing_hybrid_decode_attempts : &result->zxing_decode_attempts;
    int *version = hybrid ? &result->zxing_hybrid_version : &result->zxing_version;
    size_t *payload_bytes = hybrid ? &result->zxing_hybrid_payload_bytes : &result->zxing_payload_bytes;
    int64_t *decode_ms = hybrid ? &result->zxing_hybrid_decode_ms : &result->zxing_decode_ms;
    size_t *heap_before = hybrid ? &result->zxing_hybrid_heap_before : &result->zxing_heap_before;
    size_t *largest_before = hybrid ? &result->zxing_hybrid_largest_before : &result->zxing_largest_before;
    size_t *heap_with_bitmap = hybrid ? &result->zxing_hybrid_heap_with_bitmap : &result->zxing_heap_with_bitmap;
    size_t *largest_with_bitmap = hybrid ? &result->zxing_hybrid_largest_with_bitmap : &result->zxing_largest_with_bitmap;
    size_t *heap_after_decode = hybrid ? &result->zxing_hybrid_heap_after_decode : &result->zxing_heap_after_decode;
    size_t *largest_after_decode = hybrid ? &result->zxing_hybrid_largest_after_decode : &result->zxing_largest_after_decode;
    char *ecc = hybrid ? result->zxing_hybrid_ecc : result->zxing_ecc;
    size_t ecc_size = hybrid ? sizeof(result->zxing_hybrid_ecc) : sizeof(result->zxing_ecc);
    char *status = hybrid ? result->zxing_hybrid_status : result->zxing_status;
    size_t status_size = hybrid ? sizeof(result->zxing_hybrid_status) : sizeof(result->zxing_status);

    *attempted = true;
    snprintf(status, status_size, "STARTING");

    if (!flash_store_binary_available()) {
        snprintf(status, status_size, "NO_1BPP");
        return ESP_ERR_NOT_FOUND;
    }

    log_heap(hybrid ? "before ZXing Hybrid packed bitmap" : "before ZXing Otsu packed bitmap",
             heap_before, largest_before);

    uint8_t *packed = heap_caps_malloc(ANALYZER_BINARY_BYTES, MALLOC_CAP_8BIT);
    if (!packed) {
        snprintf(status, status_size, "BITMAP_OOM");
        return ESP_ERR_NO_MEM;
    }

    esp_err_t read_err = flash_store_binary_read(0, packed, ANALYZER_BINARY_BYTES);
    if (read_err != ESP_OK) {
        heap_caps_free(packed);
        snprintf(status, status_size, "BITMAP_READ_FAIL");
        return read_err;
    }

    log_heap(hybrid ? "with ZXing Hybrid packed bitmap" : "with ZXing Otsu packed bitmap",
             heap_with_bitmap, largest_with_bitmap);

    zxing_qr_packed_result_t zr = {0};
    int64_t t0 = esp_timer_get_time();
    int zrc = zxing_qr_decode_packed(
        packed,
        ANALYZER_SOURCE_WIDTH,
        ANALYZER_SOURCE_HEIGHT,
        ANALYZER_BINARY_ROW_BYTES,
        scanner_payload,
        scanner_payload_len,
        &zr);
    *decode_ms = (esp_timer_get_time() - t0) / 1000;

    if (hybrid) result->zxing_hybrid_meta = zr;
    else result->zxing_meta = zr;

    *decoded = zr.decoded;
    *payload_match = zr.payload_match;
    *finder_patterns = zr.finder_patterns;
    *candidate_sets = zr.candidate_sets;
    *decode_attempts = zr.decode_attempts;
    *version = zr.version;
    *payload_bytes = zr.payload_bytes;
    snprintf(ecc, ecc_size, "%s", zr.ecc);
    snprintf(status, status_size, "%s", zr.status);

    log_heap(hybrid ? "after ZXing Hybrid packed decode" : "after ZXing Otsu packed decode",
             heap_after_decode, largest_after_decode);

    heap_caps_free(packed);

    ESP_LOGI(TAG,
             "ZXing %s packed: rc=%d status=%s decoded=%d match=%d finders=%d sets=%d attempts=%d v=%d bytes=%u ms=%lld",
             hybrid ? "Hybrid" : "Otsu", zrc, status, *decoded, *payload_match,
             *finder_patterns, *candidate_sets, *decode_attempts, *version,
             (unsigned)*payload_bytes, (long long)*decode_ms);

    return *decoded ? ESP_OK : ESP_FAIL;
}

static esp_err_t fill_quirc_image_from_raw_flash(
    uint8_t *dst,
    int dst_width,
    int dst_height)
{
    if (dst == NULL || dst_width <= 0 || dst_height <= 0)
        return ESP_ERR_INVALID_ARG;

    uint8_t *row = heap_caps_malloc(ANALYZER_SOURCE_WIDTH, MALLOC_CAP_8BIT);
    if (row == NULL)
        return ESP_ERR_NO_MEM;

    int cached_sy = -1;
    for (int y = 0; y < dst_height; ++y)
    {
        int sy = (y * ANALYZER_SOURCE_HEIGHT) / dst_height;
        if (sy >= ANALYZER_SOURCE_HEIGHT)
            sy = ANALYZER_SOURCE_HEIGHT - 1;

        if (sy != cached_sy)
        {
            esp_err_t err = flash_store_raw_read(
                (size_t)sy * ANALYZER_SOURCE_WIDTH,
                row,
                ANALYZER_SOURCE_WIDTH);
            if (err != ESP_OK)
            {
                heap_caps_free(row);
                return err;
            }
            cached_sy = sy;
        }

        uint8_t *out = dst + (size_t)y * dst_width;
        for (int x = 0; x < dst_width; ++x)
        {
            int sx = (x * ANALYZER_SOURCE_WIDTH) / dst_width;
            if (sx >= ANALYZER_SOURCE_WIDTH)
                sx = ANALYZER_SOURCE_WIDTH - 1;
            out[x] = row[sx];
        }

        if ((y & 31) == 31)
        {
            analyzer_progress_hook();
            taskYIELD();
        }
    }

    heap_caps_free(row);
    return ESP_OK;
}

static esp_err_t run_quirc_flash_pass(
    int width,
    int height,
    int scale_num,
    int scale_den,
    const uint8_t *payload,
    size_t payload_len,
    image_analysis_t *result)
{
    struct quirc *q = quirc_new();
    if (q == NULL)
        return ESP_ERR_NO_MEM;

    if (quirc_resize(q, width, height) < 0)
    {
        quirc_destroy(q);
        return ESP_ERR_NO_MEM;
    }

    int image_w = 0;
    int image_h = 0;
    uint8_t *image = quirc_begin(q, &image_w, &image_h);
    if (image == NULL || image_w != width || image_h != height)
    {
        quirc_destroy(q);
        return ESP_FAIL;
    }

    esp_err_t fill_err = fill_quirc_image_from_raw_flash(image, width, height);
    if (fill_err != ESP_OK)
    {
        quirc_destroy(q);
        return fill_err;
    }

    quirc_end(q);

    result->analysis_width = (uint16_t)width;
    result->analysis_height = (uint16_t)height;
    result->detected_symbols = quirc_count(q);
    result->quirc_detected = result->detected_symbols > 0;

    if (result->detected_symbols <= 0)
    {
        quirc_destroy(q);
        return ESP_ERR_NOT_FOUND;
    }

    log_heap(
        "before quirc ladder decode task",
        &result->heap_before_decode,
        &result->largest_before_decode);

    decode_task_ctx_t context = {
        .q = q,
        .symbol_count = result->detected_symbols,
        .scanner_payload = payload,
        .scanner_payload_len = payload_len,
        .result = result,
        .notify_task = xTaskGetCurrentTaskHandle(),
        .source_offset_x = 0,
        .source_offset_y = 0,
        .scale_num = scale_num,
        .scale_den = scale_den
    };

    BaseType_t created = xTaskCreate(
        decode_task,
        "qrt_ladder_decode",
        DECODE_TASK_STACK_BYTES,
        &context,
        5,
        NULL);

    if (created != pdPASS)
    {
        quirc_destroy(q);
        return ESP_ERR_NO_MEM;
    }

    uint32_t notified = ulTaskNotifyTake(
        pdTRUE,
        pdMS_TO_TICKS(DECODE_TASK_TIMEOUT_MS));

    if (notified == 0)
    {
        /* Do not destroy q if the decode task might still be using it. */
        return ESP_ERR_TIMEOUT;
    }

    quirc_destroy(q);
    return result->quirc_decoded ? ESP_OK : ESP_FAIL;
}

static esp_err_t analyze_image(
    uart_port_t uart_num,
    const uint8_t *payload,
    size_t payload_len,
    image_analysis_t *result)
{
    memset(result, 0, sizeof(*result));
    result->attempted = true;
    result->version = -1;
    result->ecc_level = -1;
    result->mask = -1;
    result->data_type = -1;
    snprintf(result->status, sizeof(result->status), "STARTING");

    analyzer_diag_mark(AD_BEFORE_QUIRC, 0);

    /*
     * Capture the scanner-native image first and commit it to Flash.  QR
     * decoding then works from Flash so the UART RX ring and a large quirc
     * image never have to coexist during the 27 s transfer.
     */
    esp_err_t capture_err = analyzer_capture_raw_only(uart_num, result);
    if (capture_err != ESP_OK)
    {
        snprintf(result->status, sizeof(result->status), "RAW_CAPTURE_FAILED");
        snprintf(result->detail, sizeof(result->detail),
                 "Unable to capture native 640x480 GRAY8 image: %s",
                 esp_err_to_name(capture_err));
        return capture_err;
    }
    result->image_received = true;

    /* Keep the 1bpp diagnostic path, but do not use it for QR logic. */
    esp_err_t binary_err = analyzer_binary_probe(result);
    if (binary_err != ESP_OK)
    {
        ESP_LOGW(TAG, "1bpp diagnostic generation failed: %s",
                 esp_err_to_name(binary_err));
    }

    /* Release the UART ring before allocating quirc's analysis image. */
    esp_err_t uart_delete_err = uart_driver_delete(uart_num);
    if (uart_delete_err != ESP_OK)
    {
        snprintf(result->status, sizeof(result->status), "UART_RELEASE_FAILED");
        return uart_delete_err;
    }

    /* Compare stock ZXing QR on two compact 1bpp preprocessors. */
    result->stack_hwm_before_zxing = uxTaskGetStackHighWaterMark(NULL);

    esp_err_t zxing_err = analyzer_zxing_packed_probe(payload, payload_len, result, false);
    if (zxing_err != ESP_OK)
        ESP_LOGW(TAG, "ZXing Otsu packed QR probe did not decode: %s", result->zxing_status);

    esp_err_t hybrid_err = analyzer_binary_hybrid_probe(result);
    if (hybrid_err == ESP_OK) {
        esp_err_t zxing_hybrid_err = analyzer_zxing_packed_probe(payload, payload_len, result, true);
        if (zxing_hybrid_err != ESP_OK)
            ESP_LOGW(TAG, "ZXing Hybrid packed QR probe did not decode: %s", result->zxing_hybrid_status);
    } else {
        snprintf(result->zxing_hybrid_status, sizeof(result->zxing_hybrid_status), "BINARIZE_FAIL");
        ESP_LOGW(TAG, "Compact Hybrid binarization failed: %s", esp_err_to_name(hybrid_err));
    }

    result->stack_hwm_after_zxing = uxTaskGetStackHighWaterMark(NULL);

    log_heap("before quirc resolution ladder",
             &result->heap_before_quirc,
             &result->largest_before_quirc);

    esp_err_t pass1 = run_quirc_flash_pass(
        ANALYZER_PASS1_WIDTH,
        ANALYZER_PASS1_HEIGHT,
        2,
        1,
        payload,
        payload_len,
        result);

    if (pass1 == ESP_OK && result->quirc_decoded)
    {
        snprintf(result->status, sizeof(result->status), "QUIRC_OK");
        snprintf(result->detail, sizeof(result->detail),
                 "Flash RAW decoded by stock quirc at 320x240");
        log_heap("after quirc pass1", &result->heap_after_quirc,
                 &result->largest_after_quirc);
        (void)analyzer_uart_install(uart_num);
        return ESP_OK;
    }

    /* Reset pass-local decode flags before the higher-resolution retry. */
    result->quirc_decoded = false;
    result->payload_match = false;
    result->decoded_payload_len = 0;
    result->detected_symbols = 0;
    result->quirc_detected = false;

    esp_err_t pass2 = run_quirc_flash_pass(
        ANALYZER_PASS2_WIDTH,
        ANALYZER_PASS2_HEIGHT,
        4,
        3,
        payload,
        payload_len,
        result);

    log_heap("after quirc pass2", &result->heap_after_quirc,
             &result->largest_after_quirc);

    esp_err_t reinstall_err = analyzer_uart_install(uart_num);
    if (reinstall_err != ESP_OK)
    {
        snprintf(result->status, sizeof(result->status), "UART_REINSTALL_FAILED");
        return reinstall_err;
    }

    if (pass2 == ESP_OK && result->quirc_decoded)
    {
        snprintf(result->status, sizeof(result->status), "QUIRC_OK");
        snprintf(result->detail, sizeof(result->detail),
                 "Flash RAW decoded by stock quirc at 480x360 after 320x240 retry");
        return ESP_OK;
    }

    /*
     * quirc found geometry but could not decode at 480x360: let the same
     * mature library retry only the QR neighborhood at scanner-native
     * resolution.  No custom Finder/alignment/perspective code is used.
     */
    if (result->quirc_detected)
    {
        esp_err_t crop_err = run_native_crop_decode(
            uart_num, payload, payload_len, result);
        if (crop_err == ESP_OK && result->quirc_decoded)
        {
            snprintf(result->detail, sizeof(result->detail),
                     "Stock quirc detected at 480x360 and decoded a native-resolution crop");
            return ESP_OK;
        }
    }

    if (pass2 == ESP_ERR_NO_MEM)
    {
        snprintf(result->status, sizeof(result->status), "QUIRC_480_OOM");
        snprintf(result->detail, sizeof(result->detail),
                 "320x240 did not decode and stock quirc could not allocate 480x360");
        return ESP_ERR_NO_MEM;
    }

    snprintf(result->status, sizeof(result->status),
             result->quirc_detected ? "QUIRC_DECODE_FAILED" : "QUIRC_NO_SYMBOL");
    snprintf(result->detail, sizeof(result->detail),
             result->quirc_detected
                 ? "Stock quirc detected QR geometry but decode remained inconclusive"
                 : "Stock quirc found no QR at 320x240 or 480x360");
    return result->quirc_detected ? ESP_FAIL : ESP_ERR_NOT_FOUND;
}

esp_err_t analyzer_mode_init(void)
{
    esp_err_t err =
        nvs_flash_init();

    if (
        err ==
            ESP_ERR_NVS_NO_FREE_PAGES ||
        err ==
            ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        err =
            nvs_flash_erase();

        if (err != ESP_OK)
        {
            return err;
        }

        err =
            nvs_flash_init();
    }

    if (err != ESP_OK)
    {
        s_mode_enabled =
            false;

        return err;
    }

    analyzer_diag_print_last();

    nvs_handle_t handle;

    err =
        nvs_open(
            ANALYZER_NVS_NAMESPACE,
            NVS_READWRITE,
            &handle
        );

    if (err != ESP_OK)
    {
        s_mode_enabled =
            false;

        return err;
    }

    uint8_t value = 0;

    err =
        nvs_get_u8(
            handle,
            ANALYZER_NVS_MODE_KEY,
            &value
        );

    if (
        err ==
        ESP_ERR_NVS_NOT_FOUND)
    {
        value = 0;
        err = ESP_OK;
    }

    nvs_close(
        handle
    );

    if (err == ESP_OK)
    {
        s_mode_enabled =
            (value != 0);
    }
    else
    {
        s_mode_enabled =
            false;
    }

    return err;
}

bool analyzer_mode_enabled(void)
{
    return s_mode_enabled;
}

esp_err_t analyzer_mode_toggle(void)
{
    nvs_handle_t handle;

    esp_err_t err =
        nvs_open(
            ANALYZER_NVS_NAMESPACE,
            NVS_READWRITE,
            &handle
        );

    if (err != ESP_OK)
    {
        return err;
    }

    uint8_t value =
        s_mode_enabled
            ? 0
            : 1;

    err =
        nvs_set_u8(
            handle,
            ANALYZER_NVS_MODE_KEY,
            value
        );

    if (err == ESP_OK)
    {
        err =
            nvs_commit(
                handle
            );
    }

    nvs_close(
        handle
    );

    if (err == ESP_OK)
    {
        s_mode_enabled =
            (value != 0);

        analyzer_clear_result();
    }

    return err;
}

const char *analyzer_result_json(void)
{
    return s_json != NULL
        ? s_json
        : "";
}

size_t analyzer_result_json_length(void)
{
    return s_json_len;
}

static void bytes_to_hex_compact(const uint8_t *data, size_t len, char *out, size_t out_size)
{
    static const char hex[] = "0123456789ABCDEF";
    if (out == NULL || out_size == 0) return;
    out[0] = '\0';
    if (data == NULL) return;
    if (len > (out_size - 1) / 2) len = (out_size - 1) / 2;
    for (size_t i = 0; i < len; ++i) {
        out[i * 2] = hex[data[i] >> 4];
        out[i * 2 + 1] = hex[data[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

bool analyzer_has_result(void)
{
    return
        s_json != NULL &&
        s_json_len > 0;
}

void analyzer_clear_result(void)
{
    if (s_json != NULL)
    {
        heap_caps_free(
            s_json
        );
        s_json = NULL;
    }

    s_json_len = 0;
}

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
    const char *crc_endian)
{
    if (!s_mode_enabled)
    {
        return ESP_ERR_INVALID_STATE;
    }

    analyzer_clear_result();

    analyzer_diag_mark(
        AD_ANALYZER_ENTER,
        0
    );

    const char *protocol_status;

    if (!protocol3_requested)
    {
        protocol_status =
            "PROTOCOL_FORMAT3_REQUEST_FAILED";
    }
    else if (
        protocol_write_reply_seen &&
        protocol_write_rid != 0)
    {
        protocol_status =
            "PROTOCOL_FORMAT3_WRITE_REJECTED";
    }
    else if (
        protocol_readback_seen &&
        protocol_readback_value != 3)
    {
        protocol_status =
            "PROTOCOL_FORMAT3_READBACK_MISMATCH";
    }
    else if (!protocol3_detected)
    {
        protocol_status =
            "PROTOCOL_FORMAT3_NOT_OBSERVED";
    }
    else if (!crc_valid)
    {
        protocol_status =
            "PROTOCOL_FORMAT3_CRC_UNVERIFIED";
    }
    else
    {
        protocol_status =
            "PROTOCOL_FORMAT3_OK";
    }

    image_analysis_t image_result;

    esp_err_t image_err =
        analyze_image(
            uart_num,
            payload,
            payload_len,
            &image_result
        );

    ESP_LOGI(
        TAG,
        "image analyzer status=%s err=%s",
        image_result.status,
        esp_err_to_name(
            image_err
        )
    );

    char *scanner_identity_json =
        heap_caps_malloc(
            768,
            MALLOC_CAP_8BIT
        );

    if (scanner_identity_json == NULL)
    {
        return ESP_ERR_NO_MEM;
    }

    snprintf(
        scanner_identity_json,
        768,
        "{}"
    );

    scanner_identity_query(
        uart_num,
        scanner_identity_json,
        768
    );

    analyzer_diag_mark(
        AD_IDENTITY_DONE,
        0
    );

    char *zxing_meta_json = heap_caps_malloc(4096, MALLOC_CAP_8BIT);
    if (zxing_meta_json == NULL)
    {
        heap_caps_free(scanner_identity_json);
        return ESP_ERR_NO_MEM;
    }
    char *zxing_hybrid_meta_json = zxing_meta_json + 2048;
    format_zxing_metadata_json(&image_result.zxing_meta, zxing_meta_json, 2048);
    format_zxing_metadata_json(&image_result.zxing_hybrid_meta, zxing_hybrid_meta_json, 2048);

    if (payload_len > (SIZE_MAX - 1) / 2) {
        heap_caps_free(zxing_meta_json);
        heap_caps_free(scanner_identity_json);
        return ESP_ERR_INVALID_SIZE;
    }
    size_t payload_hex_size = payload_len * 2 + 1;
    char *payload_hex = heap_caps_malloc(payload_hex_size, MALLOC_CAP_8BIT);
    if (payload_hex == NULL) {
        heap_caps_free(zxing_meta_json);
        heap_caps_free(scanner_identity_json);
        return ESP_ERR_NO_MEM;
    }
    bytes_to_hex_compact(payload, payload_len, payload_hex, payload_hex_size);

    s_json =
        heap_caps_malloc(
            ANALYZER_JSON_MAX,
            MALLOC_CAP_8BIT
        );

    if (s_json == NULL)
    {
        heap_caps_free(payload_hex);
        heap_caps_free(zxing_meta_json);
        heap_caps_free(
            scanner_identity_json
        );
        return ESP_ERR_NO_MEM;
    }

    int n =
        snprintf(
            s_json,
            ANALYZER_JSON_MAX,
            "{\n"
            "  \"firmware_version\": \"%s\",\n"
            "  \"mode\": \"ANALYZER\",\n"
            "  \"scanner_identity\": %s,\n"
            "  \"analysis_status\": \"%s\",\n"
            "  \"scanner_metadata\": {\n"
            "    \"protocol_format_requested\": 3,\n"
            "    \"protocol_format_request_sent\": %s,\n"
            "    \"write_reply_seen\": %s,\n"
            "    \"write_rid\": %d,\n"
            "    \"write_reply_hex\": \"%s\",\n"
            "    \"readback_seen\": %s,\n"
            "    \"readback_value\": %d,\n"
            "    \"readback_hex\": \"%s\",\n"
            "    \"protocol_format3_detected\": %s,\n"
            "    \"crc_valid\": %s,\n"
            "    \"payload_bytes\": %u,\n"
            "    \"payload_hex\": \"%s\",\n"
            "    \"barcode_count\": %u,\n"
            "    \"code_id\": %u,\n"
            "    \"code_id_hex\": \"0x%04X\",\n"
            "    \"symbology\": \"%s\",\n"
            "    \"symbology_mapping\": \"%s\",\n"
            "    \"length_endian\": \"%s\",\n"
            "    \"crc_scope\": \"%s\",\n"
            "    \"crc_endian\": \"%s\"\n"
            "  },\n"
            "  \"scanner_capabilities\": {\n"
            "    \"protocol_format3\": \"SUPPORTED\",\n"
            "    \"image_read\": \"%s\",\n"
            "    \"image_read_native\": \"640x480_RAW_GRAY8\",\n"
            "    \"image_read_baud\": 115200,\n"
            "    \"image_read_jpeg\": \"UNAVAILABLE_ON_TESTED_FIRMWARE\",\n"
            "    \"image_read_scaling\": \"UNAVAILABLE_ON_TESTED_FIRMWARE\"\n"
            "  },\n"
            "  \"qr_metadata\": {\n"
            "    \"status\": \"%s\",\n"
            "    \"image_width\": %u,\n"
            "    \"image_height\": %u,\n"
            "    \"image_type\": %u,\n"
            "    \"image_bytes\": %lu,\n"
            "    \"analysis_width\": %u,\n"
            "    \"analysis_height\": %u,\n"
            "    \"downsample\": \"QUIRC_320X240_THEN_480X360\",\n"
            "    \"native_crop_attempted\": %s,\n"
            "    \"native_crop_used\": %s,\n"
            "    \"crop\": [%d,%d,%d,%d],\n"
            "    \"transfer_ms\": %lld,\n"
            "    \"second_transfer_ms\": %lld,\n"
            "    \"detected_symbols\": %d,\n"
            "    \"version\": %d,\n"
            "    \"ecc\": \"%s\",\n"
            "    \"ecc_value\": %d,\n"
            "    \"mask\": %d,\n"
            "    \"data_type\": \"%s\",\n"
            "    \"data_type_value\": %d,\n"
            "    \"eci\": %lu,\n"
            "    \"decoded_payload_bytes\": %u,\n"
            "    \"payload_match_scanner\": %s,\n"
            "    \"payload_hex\": \"%s\",\n"
            "    \"payload_hex_source\": \"%s\",\n"
            "    \"corners\": [[%d,%d],[%d,%d],[%d,%d],[%d,%d]],\n"
            "    \"corners_analysis\": [[%d,%d],[%d,%d],[%d,%d],[%d,%d]],\n"
            "    \"heap_before_quirc\": %u,\n"
            "    \"largest_before_quirc\": %u,\n"
            "    \"heap_after_quirc\": %u,\n"
            "    \"largest_after_quirc\": %u,\n"
            "    \"heap_before_decode\": %u,\n"
            "    \"largest_before_decode\": %u,\n"
            "    \"binary_probe\": {\n"
            "      \"attempted\": %s,\n"
            "      \"ready\": %s,\n"
            "      \"format\": \"PACKED_1BPP_MSB_FIRST\",\n"
            "      \"otsu_threshold\": %u,\n"
            "      \"bytes\": %u,\n"
            "      \"histogram_ms\": %lld,\n"
            "      \"pack_ms\": %lld,\n"
            "      \"black_pixels\": %lu,\n"
            "      \"checksum_fnv1a32\": \"%08lX\",\n"
            "      \"hybrid_ms\": %lld,\n"
            "      \"hybrid_black_pixels\": %lu,\n"
            "      \"hybrid_checksum_fnv1a32\": \"%08lX\",\n"
            "      \"heap_before\": %u,\n"
            "      \"largest_before\": %u,\n"
            "      \"heap_with_bitmap\": %u,\n"
            "      \"largest_with_bitmap\": %u\n"
            "    },\n"
            "    \"zxing_otsu\": {\n"
            "      \"attempted\": %s,\n"
            "      \"decoded\": %s,\n"
            "      \"status\": \"%s\",\n"
            "      \"decode_ms\": %lld,\n"
            "      \"finder_patterns\": %d,\n"
            "      \"candidate_sets\": %d,\n"
            "      \"decode_attempts\": %d,\n"
            "      \"version\": %d,\n"
            "      \"ecc\": \"%s\",\n"
            "      \"decoded_payload_bytes\": %u,\n"
            "      \"payload_match_scanner\": %s,\n"
            "      \"payload_hex\": \"%s\",\n"
            "      \"payload_hex_source\": \"%s\",\n"
            "      \"metadata\": %s,\n"
            "      \"heap_before\": %u,\n"
            "      \"largest_before\": %u,\n"
            "      \"heap_with_bitmap\": %u,\n"
            "      \"largest_with_bitmap\": %u,\n"
            "      \"heap_after_decode\": %u,\n"
            "      \"largest_after_decode\": %u\n"
            "    },\n"
            "    \"zxing_hybrid\": {\n"
            "      \"attempted\": %s,\n"
            "      \"decoded\": %s,\n"
            "      \"status\": \"%s\",\n"
            "      \"decode_ms\": %lld,\n"
            "      \"finder_patterns\": %d,\n"
            "      \"candidate_sets\": %d,\n"
            "      \"decode_attempts\": %d,\n"
            "      \"version\": %d,\n"
            "      \"ecc\": \"%s\",\n"
            "      \"decoded_payload_bytes\": %u,\n"
            "      \"payload_match_scanner\": %s,\n"
            "      \"payload_hex\": \"%s\",\n"
            "      \"payload_hex_source\": \"%s\",\n"
            "      \"metadata\": %s,\n"
            "      \"heap_before\": %u,\n"
            "      \"largest_before\": %u,\n"
            "      \"heap_with_bitmap\": %u,\n"
            "      \"largest_with_bitmap\": %u,\n"
            "      \"heap_after_decode\": %u,\n"
            "      \"largest_after_decode\": %u\n"
            "    },\n"
            "    \"analyzer_stack_hwm_before_zxing\": %u,\n"
            "    \"analyzer_stack_hwm_after_zxing\": %u,\n"
            "    \"detail\": \"%s\"\n"
            "  }\n"
            "}\n",
            ANALYZER_FIRMWARE_VERSION,
            scanner_identity_json,
            protocol_status,
            protocol3_requested
                ? "true"
                : "false",
            protocol_write_reply_seen
                ? "true"
                : "false",
            protocol_write_rid,
            protocol_write_reply_hex != NULL
                ? protocol_write_reply_hex
                : "",
            protocol_readback_seen
                ? "true"
                : "false",
            protocol_readback_value,
            protocol_readback_hex != NULL
                ? protocol_readback_hex
                : "",
            protocol3_detected
                ? "true"
                : "false",
            crc_valid
                ? "true"
                : "false",
            (unsigned)payload_len,
            payload_hex,
            (unsigned)barcode_count,
            (unsigned)code_id,
            (unsigned)code_id,
            observed_symbology_name(
                code_id
            ),
            observed_symbology_mapping_source(
                code_id
            ),
            length_endian != NULL
                ? length_endian
                : "UNKNOWN",
            crc_scope != NULL
                ? crc_scope
                : "UNVERIFIED",
            crc_endian != NULL
                ? crc_endian
                : "UNKNOWN",
            image_result.image_supported
                ? "SUPPORTED_640X480_RAW"
                : "NOT_CONFIRMED_THIS_SCAN",
            image_result.status,
            (unsigned)image_result.image_width,
            (unsigned)image_result.image_height,
            (unsigned)image_result.image_type,
            (unsigned long)image_result.image_bytes,
            (unsigned)image_result.analysis_width,
            (unsigned)image_result.analysis_height,
            image_result.native_crop_attempted
                ? "true"
                : "false",
            image_result.native_crop_used
                ? "true"
                : "false",
            image_result.crop_x,
            image_result.crop_y,
            image_result.crop_width,
            image_result.crop_height,
            (long long)image_result.transfer_ms,
            (long long)image_result.second_transfer_ms,
            image_result.detected_symbols,
            image_result.version,
            ecc_name(
                image_result.ecc_level
            ),
            image_result.ecc_level,
            image_result.mask,
            data_type_name(
                image_result.data_type
            ),
            image_result.data_type,
            (unsigned long)image_result.eci,
            (unsigned)image_result.decoded_payload_len,
            image_result.payload_match
                ? "true"
                : "false",
            image_result.payload_match ? payload_hex : "",
            image_result.payload_match ? "SCANNER_MATCH" : "UNAVAILABLE_ON_MISMATCH",
            image_result.corners[0][0],
            image_result.corners[0][1],
            image_result.corners[1][0],
            image_result.corners[1][1],
            image_result.corners[2][0],
            image_result.corners[2][1],
            image_result.corners[3][0],
            image_result.corners[3][1],
            image_result.corners_analysis[0][0],
            image_result.corners_analysis[0][1],
            image_result.corners_analysis[1][0],
            image_result.corners_analysis[1][1],
            image_result.corners_analysis[2][0],
            image_result.corners_analysis[2][1],
            image_result.corners_analysis[3][0],
            image_result.corners_analysis[3][1],
            (unsigned)image_result.heap_before_quirc,
            (unsigned)image_result.largest_before_quirc,
            (unsigned)image_result.heap_after_quirc,
            (unsigned)image_result.largest_after_quirc,
            (unsigned)image_result.heap_before_decode,
            (unsigned)image_result.largest_before_decode,
            image_result.binary_probe_attempted
                ? "true"
                : "false",
            image_result.binary_probe_ready
                ? "true"
                : "false",
            (unsigned)image_result.binary_otsu_threshold,
            (unsigned)image_result.binary_bytes,
            (long long)image_result.binary_histogram_ms,
            (long long)image_result.binary_pack_ms,
            (unsigned long)image_result.binary_black_pixels,
            (unsigned long)image_result.binary_checksum,
            (long long)image_result.binary_hybrid_ms,
            (unsigned long)image_result.binary_hybrid_black_pixels,
            (unsigned long)image_result.binary_hybrid_checksum,
            (unsigned)image_result.heap_before_binary,
            (unsigned)image_result.largest_before_binary,
            (unsigned)image_result.heap_with_binary,
            (unsigned)image_result.largest_with_binary,
            image_result.zxing_attempted ? "true" : "false",
            image_result.zxing_decoded ? "true" : "false",
            image_result.zxing_status,
            (long long)image_result.zxing_decode_ms,
            image_result.zxing_finder_patterns,
            image_result.zxing_candidate_sets,
            image_result.zxing_decode_attempts,
            image_result.zxing_version,
            image_result.zxing_ecc,
            (unsigned)image_result.zxing_payload_bytes,
            image_result.zxing_payload_match ? "true" : "false",
            image_result.zxing_payload_match ? payload_hex : "",
            image_result.zxing_payload_match ? "SCANNER_MATCH" : "UNAVAILABLE_ON_MISMATCH",
            zxing_meta_json,
            (unsigned)image_result.zxing_heap_before,
            (unsigned)image_result.zxing_largest_before,
            (unsigned)image_result.zxing_heap_with_bitmap,
            (unsigned)image_result.zxing_largest_with_bitmap,
            (unsigned)image_result.zxing_heap_after_decode,
            (unsigned)image_result.zxing_largest_after_decode,
            image_result.zxing_hybrid_attempted ? "true" : "false",
            image_result.zxing_hybrid_decoded ? "true" : "false",
            image_result.zxing_hybrid_status,
            (long long)image_result.zxing_hybrid_decode_ms,
            image_result.zxing_hybrid_finder_patterns,
            image_result.zxing_hybrid_candidate_sets,
            image_result.zxing_hybrid_decode_attempts,
            image_result.zxing_hybrid_version,
            image_result.zxing_hybrid_ecc,
            (unsigned)image_result.zxing_hybrid_payload_bytes,
            image_result.zxing_hybrid_payload_match ? "true" : "false",
            image_result.zxing_hybrid_payload_match ? payload_hex : "",
            image_result.zxing_hybrid_payload_match ? "SCANNER_MATCH" : "UNAVAILABLE_ON_MISMATCH",
            zxing_hybrid_meta_json,
            (unsigned)image_result.zxing_hybrid_heap_before,
            (unsigned)image_result.zxing_hybrid_largest_before,
            (unsigned)image_result.zxing_hybrid_heap_with_bitmap,
            (unsigned)image_result.zxing_hybrid_largest_with_bitmap,
            (unsigned)image_result.zxing_hybrid_heap_after_decode,
            (unsigned)image_result.zxing_hybrid_largest_after_decode,
            (unsigned)image_result.stack_hwm_before_zxing,
            (unsigned)image_result.stack_hwm_after_zxing,
            image_result.detail
        );

    if (n < 0)
    {
        analyzer_clear_result();

        return ESP_FAIL;
    }

    if ((size_t)n >= ANALYZER_JSON_MAX)
    {
        /*
         * Never expose a syntactically truncated JSON document.  If the
         * detailed report outgrows the fixed Analyzer buffer, replace it
         * with a small valid diagnostic object so the host can distinguish
         * capacity exhaustion from filesystem corruption.
         */
        int fallback_n = snprintf(
            s_json,
            ANALYZER_JSON_MAX,
            "{\n"
            "  \"firmware_version\": \"%s\",\n"
            "  \"mode\": \"ANALYZER\",\n"
            "  \"analysis_status\": \"JSON_CAPACITY_EXCEEDED\",\n"
            "  \"required_bytes\": %u,\n"
            "  \"capacity_bytes\": %u\n"
            "}\n",
            ANALYZER_FIRMWARE_VERSION,
            (unsigned)((size_t)n + 1u),
            (unsigned)ANALYZER_JSON_MAX
        );

        if (fallback_n < 0 || (size_t)fallback_n >= ANALYZER_JSON_MAX)
        {
            analyzer_clear_result();
            heap_caps_free(payload_hex);
            heap_caps_free(zxing_meta_json);
            heap_caps_free(scanner_identity_json);
            return ESP_ERR_INVALID_SIZE;
        }

        s_json_len = (size_t)fallback_n;
    }
    else
    {
        s_json_len = (size_t)n;
    }

    heap_caps_free(payload_hex);
    heap_caps_free(zxing_meta_json);

    heap_caps_free(
        scanner_identity_json
    );

    /*
     * Protocol Format 3 integrity remains mandatory. Image analysis itself
     * is best-effort: payload/history were already safely persisted before
     * Analyzer is called, so an Analyzer OOM must not invalidate the scan.
     */
    analyzer_diag_mark(
        AD_JSON_BUILT,
        (int32_t)image_err
    );

    if (
        strcmp(
            protocol_status,
            "PROTOCOL_FORMAT3_OK") != 0)
    {
        return ESP_FAIL;
    }

    return ESP_OK;
}
