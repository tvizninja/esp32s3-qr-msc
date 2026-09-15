idf_component_register(
    SRCS
        "qrtransfer_msc.c"
        "flash_store.c"
        "analyzer.c"
    INCLUDE_DIRS "."
    REQUIRES
        esp_driver_uart
        esp_driver_gpio
        esp_timer
        esp_partition
        nvs_flash
        zxing_qr_packed
)
