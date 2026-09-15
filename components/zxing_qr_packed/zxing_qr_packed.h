#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZXING_QR_MAX_ECI_VALUES 8

typedef struct {
    bool attempted;
    bool decoded;
    bool payload_match;
    int finder_patterns;
    int candidate_sets;
    int decode_attempts;
    int version;
    int mask;
    int format_hamming_distance;
    int format_bits_index;
    int format_data_raw;
    bool mirrored;
    bool reader_init;
    size_t payload_bytes;
    char ecc[8];
    char status[32];

    char content_type[20];
    uint32_t codec_mode_mask;
    char data_type[24];

    bool has_eci;
    int eci_count;
    int eci_values[ZXING_QR_MAX_ECI_VALUES];

    int structured_append_index;
    int structured_append_count;
    char structured_append_id[24];
    char symbology_identifier[16];

    double unused_error_correction_margin;

    int corners[4][2];

    int error_type;
    char error_type_name[16];
    char error_message[96];
    char error_location[96];
} zxing_qr_packed_result_t;

/*
 * Decode an MSB-first packed 1bpp image without expanding it to 1 byte/pixel.
 * The ZXing QR detector, perspective sampler, Reed-Solomon and payload decoder
 * are stock upstream algorithms. The packed input view is the only behavioral
 * modification in the vendored ZXing subset.
 */
int zxing_qr_decode_packed(
    const uint8_t *packed,
    int width,
    int height,
    int stride_bytes,
    const uint8_t *expected_payload,
    size_t expected_payload_len,
    zxing_qr_packed_result_t *out_result
);

#ifdef __cplusplus
}
#endif
