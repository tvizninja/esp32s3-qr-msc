/*
 * QRTransfer adapter for ZXing-C++ packed 1bpp QR decoding.
 *
 * This adapter is original QRTransfer integration code. Vendored ZXing-C++
 * sources remain under Apache License 2.0; see LICENSE in this component.
 */
#include "zxing_qr_packed.h"

#include "BitMatrix.h"
#include "DecoderResult.h"
#include "DetectorResult.h"
#include "ContentType.h"
#include "JSON.h"
#include "qrcode/QRBitMatrixParser.h"
#include "qrcode/QRDecoder.h"
#include "qrcode/QRDetector.h"
#include "qrcode/QRFormatInformation.h"

#include <algorithm>
#include <cstring>
#include <exception>

using namespace ZXing;

static void set_status(zxing_qr_packed_result_t *r, const char *s)
{
    std::strncpy(r->status, s, sizeof(r->status) - 1);
    r->status[sizeof(r->status) - 1] = '\0';
}

static void copy_text(char *dst, size_t dst_size, const std::string& src)
{
    if (!dst || dst_size == 0) return;
    std::strncpy(dst, src.c_str(), dst_size - 1);
    dst[dst_size - 1] = '\0';
}

static const char *error_type_name(Error::Type type)
{
    switch (type) {
        case Error::Type::None: return "NONE";
        case Error::Type::Format: return "FORMAT";
        case Error::Type::Checksum: return "CHECKSUM";
        case Error::Type::Unsupported: return "UNSUPPORTED";
    }
    return "UNKNOWN";
}

static const char *data_type_from_mode_mask(uint32_t mask)
{
    constexpr uint32_t NUMERIC = 1u << 1;
    constexpr uint32_t ALPHANUMERIC = 1u << 2;
    constexpr uint32_t BYTE = 1u << 4;
    constexpr uint32_t KANJI = 1u << 8;
    constexpr uint32_t HANZI = 1u << 13;
    const uint32_t payload = mask & (NUMERIC | ALPHANUMERIC | BYTE | KANJI | HANZI);
    if (payload == NUMERIC) return "NUMERIC";
    if (payload == ALPHANUMERIC) return "ALPHANUMERIC";
    if (payload == BYTE) return "BYTE";
    if (payload == KANJI) return "KANJI";
    if (payload == HANZI) return "HANZI";
    if (payload != 0 && (payload & (payload - 1)) != 0) return "MIXED";
    return "UNKNOWN";
}

static void fill_decode_metadata(
    zxing_qr_packed_result_t *r,
    const DetectorResult& sampled,
    const DecoderResult& decoded)
{
    const auto formatInfo = QRCode::ReadFormatInformation(sampled.bits());
    if (formatInfo.isValid()) {
        r->mask = formatInfo.dataMask;
        r->format_hamming_distance = formatInfo.hammingDistance;
        r->format_bits_index = formatInfo.bitsIndex;
        r->format_data_raw = formatInfo.data;
    } else {
        r->mask = -1;
        r->format_hamming_distance = -1;
        r->format_bits_index = -1;
        r->format_data_raw = -1;
    }

    r->mirrored = decoded.isMirrored();
    r->reader_init = decoded.readerInit();

    const auto& pos = sampled.position();
    for (int i = 0; i < 4; ++i) {
        r->corners[i][0] = pos[i].x;
        r->corners[i][1] = pos[i].y;
    }

    copy_text(r->content_type, sizeof(r->content_type), ToString(decoded.content().type()));
    r->codec_mode_mask = JsonGet<uint32_t>(decoded.json(), "CodecModeMask").value_or(0);
    copy_text(r->data_type, sizeof(r->data_type), data_type_from_mode_mask(r->codec_mode_mask));

    r->has_eci = decoded.content().hasECI;
    r->eci_count = r->has_eci ? static_cast<int>(decoded.content().encodings.size()) : 0;
    for (int i = 0; i < std::min<int>(r->eci_count, ZXING_QR_MAX_ECI_VALUES); ++i)
        r->eci_values[i] = ToInt(decoded.content().encodings[i].eci);

    const auto& sa = decoded.structuredAppend();
    r->structured_append_index = sa.index;
    r->structured_append_count = sa.count;
    copy_text(r->structured_append_id, sizeof(r->structured_append_id), sa.id);
    copy_text(r->symbology_identifier, sizeof(r->symbology_identifier), decoded.symbologyIdentifier());

    r->unused_error_correction_margin = JsonGet<double>(decoded.json(), "UEC").value_or(-1.0);

    const auto& err = decoded.error();
    r->error_type = static_cast<int>(err.type());
    copy_text(r->error_type_name, sizeof(r->error_type_name), error_type_name(err.type()));
    copy_text(r->error_message, sizeof(r->error_message), err.msg());
    copy_text(r->error_location, sizeof(r->error_location), err.location());
}

extern "C" int zxing_qr_decode_packed(
    const uint8_t *packed,
    int width,
    int height,
    int stride_bytes,
    const uint8_t *expected_payload,
    size_t expected_payload_len,
    zxing_qr_packed_result_t *out_result)
{
    if (!out_result)
        return -1;

    std::memset(out_result, 0, sizeof(*out_result));
    out_result->attempted = true;
    out_result->mask = -1;
    out_result->format_hamming_distance = -1;
    out_result->format_bits_index = -1;
    out_result->format_data_raw = -1;
    out_result->structured_append_index = -1;
    out_result->structured_append_count = -1;
    out_result->unused_error_correction_margin = -1.0;
    set_status(out_result, "STARTED");

    if (!packed || width <= 0 || height <= 0 || stride_bytes < (width + 7) / 8) {
        set_status(out_result, "BAD_INPUT");
        return -2;
    }

    try {
        auto image = BitMatrix::FromPackedView(width, height, packed, stride_bytes);
        auto finders = QRCode::FindFinderPatterns(image, false);
        out_result->finder_patterns = static_cast<int>(finders.size());
        auto sets = QRCode::GenerateFinderPatternSets(finders);
        out_result->candidate_sets = static_cast<int>(sets.size());

        for (const auto& set : sets) {
            for (auto&& sampled : QRCode::SampleQR(image, set)) {
                ++out_result->decode_attempts;
                auto decoded = QRCode::Decode(sampled.bits());
                fill_decode_metadata(out_result, sampled, decoded);
                if (!decoded.isValid())
                    continue;

                const auto& bytes = decoded.content().bytes;
                out_result->decoded = true;
                out_result->version = decoded.versionNumber();
                out_result->payload_bytes = bytes.size();
                std::strncpy(out_result->ecc, decoded.ecLevel().c_str(), sizeof(out_result->ecc) - 1);
                out_result->ecc[sizeof(out_result->ecc) - 1] = '\0';
                out_result->payload_match =
                    expected_payload != nullptr &&
                    expected_payload_len == bytes.size() &&
                    std::memcmp(expected_payload, bytes.data(), bytes.size()) == 0;
                set_status(out_result, "OK");
                return 0;
            }
        }

        set_status(out_result, finders.empty() ? "NO_FINDER" : "NO_DECODE");
        return 1;
    } catch (const std::exception&) {
        set_status(out_result, "EXCEPTION");
        return -3;
    } catch (...) {
        set_status(out_result, "UNKNOWN_EXCEPTION");
        return -4;
    }
}
