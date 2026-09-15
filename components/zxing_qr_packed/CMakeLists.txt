set(ZXING_SRC "${CMAKE_CURRENT_LIST_DIR}/zxing/core/src")

set(ZXING_QR_SOURCES
    "zxing_qr_packed.cpp"
    "${ZXING_SRC}/BitMatrix.cpp"
    "${ZXING_SRC}/BitSource.cpp"
    "${ZXING_SRC}/ConcentricFinder.cpp"
    "${ZXING_SRC}/Content.cpp"
    "${ZXING_SRC}/ECI.cpp"
    "${ZXING_SRC}/Error.cpp"
    "${ZXING_SRC}/Utf.cpp"
    "${ZXING_SRC}/GridSampler.cpp"
    "${ZXING_SRC}/JSON.cpp"
    "${ZXING_SRC}/PerspectiveTransform.cpp"
    "${ZXING_SRC}/ReedSolomon.cpp"
    "${ZXING_SRC}/qrcode/QRBitMatrixParser.cpp"
    "${ZXING_SRC}/qrcode/QRCodecMode.cpp"
    "${ZXING_SRC}/qrcode/QRDataBlock.cpp"
    "${ZXING_SRC}/qrcode/QRDecoder.cpp"
    "${ZXING_SRC}/qrcode/QRDetector.cpp"
    "${ZXING_SRC}/qrcode/QRErrorCorrectionLevel.cpp"
    "${ZXING_SRC}/qrcode/QRFormatInformation.cpp"
    "${ZXING_SRC}/qrcode/QRVersion.cpp"
)

idf_component_register(
    SRCS ${ZXING_QR_SOURCES}
    INCLUDE_DIRS "." "${ZXING_SRC}"
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE ZXING_INTERNAL)
target_compile_options(${COMPONENT_LIB} PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-std=gnu++20>
    $<$<COMPILE_LANGUAGE:CXX>:-fexceptions>
)
