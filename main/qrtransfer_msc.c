
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "driver/gpio.h"
#include "driver/uart.h"

#include "esp_err.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_system.h"

#include "tinyusb.h"
#include "tusb.h"

#include "flash_store.h"
#include "analyzer.h"

#include "led_strip.h"


static const char *TAG = "QRTRANSFER";


static const char *reset_reason_name(esp_reset_reason_t reason)
{
    switch (reason)
    {
        case ESP_RST_POWERON: return "POWERON";
        case ESP_RST_EXT: return "EXT";
        case ESP_RST_SW: return "SW";
        case ESP_RST_PANIC: return "PANIC";
        case ESP_RST_INT_WDT: return "INT_WDT";
        case ESP_RST_TASK_WDT: return "TASK_WDT";
        case ESP_RST_WDT: return "WDT";
        case ESP_RST_DEEPSLEEP: return "DEEPSLEEP";
        case ESP_RST_BROWNOUT: return "BROWNOUT";
        case ESP_RST_SDIO: return "SDIO";
        default: return "UNKNOWN";
    }
}


// ============================================================
// Button / gestures
// ============================================================

#define BUTTON_GPIO               GPIO_NUM_41
#define BUTTON_DEBOUNCE_MS        50
#define DOUBLE_TAP_MS             250

// Hold the button from power-on/USB connection for this long
// to erase all QR history.
#define BOOT_CLEAR_MIN_HOLD_MS    3000
#define BOOT_MODE_TOGGLE_HOLD_MS  10000


// ============================================================
// AtomS3 Lite status RGB LED
//
// Official AtomS3 Lite schematic:
//   WS2812 SK_DIN -> GPIO35
//
// Keep brightness deliberately low for a status indicator.
// ============================================================

#define STATUS_LED_GPIO           GPIO_NUM_35
#define STATUS_LED_COUNT          1
#define STATUS_LED_RMT_RES_HZ     (10 * 1000 * 1000)

#define STATUS_DIM                12
#define STATUS_MEDIUM             20

static led_strip_handle_t status_led = NULL;


// ============================================================
// QRCode2 UART
// ============================================================

#define QR_UART                   UART_NUM_1
#define QR_UART_RX_GPIO           GPIO_NUM_5
#define QR_UART_TX_GPIO           GPIO_NUM_6
#define QR_UART_BAUD              115200
#define QR_UART_RX_BUFFER_SIZE    8192

#define MAX_QR_BYTES              4096
#define QR_INTERBYTE_TIMEOUT_MS   80
#define QR_SCAN_TIMEOUT_MS        10000


// ============================================================
// USB reconnect
// ============================================================

#define USB_DISCONNECT_MS         250
#define RECONNECT_GUARD_MS        2000


// ============================================================
// User-visible history policy
// ============================================================

#define LOG_MAX_ENTRIES           500


// ============================================================
// Virtual FAT12 geometry
//
// We use 1024-byte clusters (2 x 512-byte sectors).
// This allows 500 files x up to 4099 bytes while remaining
// comfortably inside FAT12's cluster-count limit.
//
// Layout:
//
// sector 0         Boot
// sectors 1..8    FAT12
// sectors 9..10   Root directory
// sector 11+      Data
//
// Cluster 2..17       LOG directory (16 clusters / 32 sectors)
// Cluster 18..22      LATEST.TXT   (5 clusters)
// Cluster 23 onward   500 LOG slots x 5 clusters
// ============================================================

#define SECTOR_SIZE               512u
#define SECTORS_PER_CLUSTER       2u
#define CLUSTER_SIZE              (SECTOR_SIZE * SECTORS_PER_CLUSTER)

#define RESERVED_SECTORS          1u
#define FAT_SECTORS               9u
#define ROOT_ENTRY_COUNT          32u
#define ROOT_SECTORS              2u

#define FAT_START_SECTOR          RESERVED_SECTORS
#define ROOT_START_SECTOR         (FAT_START_SECTOR + FAT_SECTORS)
#define DATA_START_SECTOR         (ROOT_START_SECTOR + ROOT_SECTORS)

#define LOG_DIR_FIRST_CLUSTER     2u
#define LOG_DIR_CLUSTER_COUNT     16u

#define LATEST_FIRST_CLUSTER      \
    (LOG_DIR_FIRST_CLUSTER + LOG_DIR_CLUSTER_COUNT)

#define FILE_CLUSTER_COUNT        5u

#define HISTORY_FIRST_CLUSTER     \
    (LATEST_FIRST_CLUSTER + FILE_CLUSTER_COUNT)

#define HISTORY_DATA_CLUSTERS     \
    (LOG_MAX_ENTRIES * FILE_CLUSTER_COUNT)

// Analyzer metadata is appended after all history slots so existing
// history cluster mapping remains unchanged. In Normal mode these
// clusters remain unused/free.
#define ANALYSIS_FIRST_CLUSTER    \
    (HISTORY_FIRST_CLUSTER + HISTORY_DATA_CLUSTERS)

#define ANALYSIS_CLUSTER_COUNT    4u

// Analyzer image is exposed as an uncompressed 8-bit grayscale BMP.
// BITMAPFILEHEADER (14) + BITMAPINFOHEADER (40) + 256-entry BGRA palette.
// Height is negative so the scanner's top-to-bottom GRAY8 bytes can be
// exposed verbatim without row reversal or any lossy conversion.
#define RAW_BMP_HEADER_SIZE       (14u + 40u + 256u * 4u)
#define RAW_BMP_FILE_SIZE         (RAW_BMP_HEADER_SIZE + FLASH_STORE_RAW_BYTES)
#define RAW_FIRST_CLUSTER         (ANALYSIS_FIRST_CLUSTER + ANALYSIS_CLUSTER_COUNT)
#define RAW_CLUSTER_COUNT         ((RAW_BMP_FILE_SIZE + CLUSTER_SIZE - 1u) / CLUSTER_SIZE)

// DEBUG.TXT is generated at boot from reset reason + the last persistent
// Analyzer breadcrumb. It remains available even when the previous Analyzer
// run reset before QRINFO.TXT could be completed.
#define DEBUG_FIRST_CLUSTER       (RAW_FIRST_CLUSTER + RAW_CLUSTER_COUNT)
#define DEBUG_CLUSTER_COUNT       2u
#define DEBUG_TEXT_MAX            (DEBUG_CLUSTER_COUNT * CLUSTER_SIZE)

#define DATA_CLUSTER_COUNT        \
    (LOG_DIR_CLUSTER_COUNT + FILE_CLUSTER_COUNT + HISTORY_DATA_CLUSTERS + \
     ANALYSIS_CLUSTER_COUNT + RAW_CLUSTER_COUNT + DEBUG_CLUSTER_COUNT)

#define TOTAL_SECTORS             \
    (DATA_START_SECTOR + DATA_CLUSTER_COUNT * SECTORS_PER_CLUSTER)


// ============================================================
// Virtual FAT metadata RAM
// ============================================================

#define BOOT_CACHE_BYTES           SECTOR_SIZE
#define FAT_CACHE_BYTES            (FAT_SECTORS * SECTOR_SIZE)
#define ROOT_CACHE_BYTES           (ROOT_SECTORS * SECTOR_SIZE)
#define LOG_DIR_CACHE_BYTES        (LOG_DIR_CLUSTER_COUNT * CLUSTER_SIZE)
#define LATEST_CACHE_BYTES         MAX_QR_BYTES
#define VISIBLE_LOG_CACHE_BYTES    (LOG_MAX_ENTRIES * sizeof(flash_record_info_t))

#define VIRTUAL_DISK_CACHE_BYTES   \
    (BOOT_CACHE_BYTES + FAT_CACHE_BYTES + ROOT_CACHE_BYTES + \
     LOG_DIR_CACHE_BYTES + LATEST_CACHE_BYTES + VISIBLE_LOG_CACHE_BYTES)

static uint8_t *virtual_disk_cache = NULL;
static uint8_t *boot_sector = NULL;
static uint8_t *fat_table = NULL;
static uint8_t *root_directory = NULL;
static uint8_t *log_directory = NULL;


// ============================================================
// UTF-8 BOM
// ============================================================

static const uint8_t utf8_bom[] = {
    0xEF, 0xBB, 0xBF
};

#define UTF8_BOM_SIZE sizeof(utf8_bom)


// ============================================================
// LATEST.TXT
// ============================================================

static uint8_t *latest_payload = NULL;
static size_t latest_payload_length = 1;

// Boot-generated crash/debug report exposed as DEBUG.TXT in Analyzer mode.
static char debug_text[DEBUG_TEXT_MAX];
static size_t debug_text_length = 0;


// ============================================================
// LOG records currently exposed to Windows
//
// Oldest -> newest.
// Payloads stay in Flash; only this metadata stays in RAM.
// ============================================================

static flash_record_info_t *visible_log = NULL;

static uint16_t visible_log_count = 0;


// ============================================================
// Current session's LATEST record.
//
// 0 on boot:
//   LATEST is blank and all persisted records belong to LOG.
//
// after successful scan:
//   newest record is LATEST and is excluded from LOG.
// ============================================================

static uint32_t current_record_sequence = 0;


// ============================================================
// USB identity
// ============================================================

static const char usb_lang_id[] = {
    0x09, 0x04
};

static const char *usb_string_descriptors[] = {
    usb_lang_id,
    "QRTransfer",
    "QR Transfer MSC",
    "QRTFIXED",
    "QR MSC"
};

static tusb_desc_device_t usb_device_descriptor = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0200,
    .bDeviceClass = 0x00,
    .bDeviceSubClass = 0x00,
    .bDeviceProtocol = 0x00,
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor = 0x303A,
    .idProduct = 0x4002,
    .bcdDevice = 0x0000,
    .iManufacturer = 0x01,
    .iProduct = 0x02,
    .iSerialNumber = 0x03,
    .bNumConfigurations = 0x01
};

// ============================================================
// USB bcdDevice cache-refresh generation
//
// TEST BUILD:
// Alternate between two fixed BCD revisions only.
// This avoids unbounded/incrementing revision values while still
// forcing Windows to observe a descriptor revision change.
//
// Values:
//   0x0101 <-> 0x0102
// ============================================================

static bool bcd_toggle_state = false;


// ============================================================
// Device state
// ============================================================

typedef enum
{
    STATE_IDLE = 0,
    STATE_SCANNING,
    STATE_UPDATING,
    STATE_GUARD,
    STATE_ERROR

} device_state_t;

static volatile device_state_t device_state =
    STATE_IDLE;


// ============================================================
// Timing / gestures
// ============================================================

static int64_t scan_started_ms = 0;
static int64_t guard_started_ms = 0;

static bool tap_pending = false;
static int64_t first_tap_ms = 0;

static bool fill_light_enabled = false;


// ============================================================
// QR RX
// ============================================================

static uint8_t qr_buffer[MAX_QR_BYTES];

static size_t qr_length = 0;
static bool qr_receiving = false;
static int64_t qr_last_byte_ms = 0;


// ============================================================
// Status LED
// ============================================================

static esp_err_t status_led_init(void)
{
    led_strip_config_t strip_config = {
        .strip_gpio_num =
            STATUS_LED_GPIO,

        .max_leds =
            STATUS_LED_COUNT,

        .led_model =
            LED_MODEL_WS2812,

        .color_component_format =
            LED_STRIP_COLOR_COMPONENT_FMT_GRB,

        .flags = {
            .invert_out = false
        }
    };


    led_strip_rmt_config_t rmt_config = {
        .clk_src =
            RMT_CLK_SRC_DEFAULT,

        .resolution_hz =
            STATUS_LED_RMT_RES_HZ,

        .mem_block_symbols =
            0,

        .flags = {
            .with_dma = false
        }
    };


    esp_err_t err =
        led_strip_new_rmt_device(
            &strip_config,
            &rmt_config,
            &status_led
        );

    if (err != ESP_OK)
    {
        return err;
    }


    return
        led_strip_clear(
            status_led
        );
}


static void status_led_rgb(
    uint8_t red,
    uint8_t green,
    uint8_t blue)
{
    if (status_led == NULL)
    {
        return;
    }


    if (
        led_strip_set_pixel(
            status_led,
            0,
            red,
            green,
            blue
        ) != ESP_OK
    )
    {
        return;
    }


    (void)
        led_strip_refresh(
            status_led
        );
}


static void status_led_off(void)
{
    if (status_led == NULL)
    {
        return;
    }

    (void)
        led_strip_clear(
            status_led
        );
}


static void status_idle(void)
{
    status_led_off();
}


static void status_scanning(void)
{
    status_led_rgb(
        0,
        0,
        STATUS_MEDIUM
    );
}


static void status_success(void)
{
    status_led_rgb(
        0,
        STATUS_MEDIUM,
        0
    );
}


// ============================================================
// Fill-light toggle feedback
//
// ON  : cyan flash
// OFF : white flash
//
// The feedback is intentionally brief and returns to idle.
// ============================================================

static void status_fill_light_feedback(
    bool enabled)
{
    if (enabled)
    {
        // Cyan = fill light enabled.
        status_led_rgb(
            0,
            STATUS_DIM,
            STATUS_MEDIUM
        );
    }
    else
    {
        // White = fill light disabled.
        status_led_rgb(
            STATUS_DIM,
            STATUS_DIM,
            STATUS_DIM
        );
    }

    vTaskDelay(
        pdMS_TO_TICKS(180)
    );

    status_idle();
}


static void status_timeout(void)
{
    status_led_rgb(
        STATUS_MEDIUM,
        STATUS_DIM,
        0
    );
}


static void status_error(void)
{
    status_led_rgb(
        STATUS_MEDIUM,
        0,
        0
    );
}


// ============================================================
// Error UX
//
// Startup/fatal patterns repeat forever:
//
//   1 red blink : QRCode2 initialization failure
//   2 red blinks: Flash/history initialization failure
//
// Recoverable runtime error:
//
//   3 red blinks: current scan could not be accepted/saved
//
// Blink counting is intentionally small and slow enough to be
// recognized without documentation in hand.
// ============================================================

typedef enum
{
    ERROR_UX_QR_INIT = 1,
    ERROR_UX_FLASH = 2,
    ERROR_UX_SCAN_SAVE = 3

} error_ux_code_t;


static void status_red_blinks(
    unsigned count,
    unsigned on_ms,
    unsigned off_ms)
{
    for (unsigned i = 0; i < count; ++i)
    {
        status_error();

        vTaskDelay(
            pdMS_TO_TICKS(on_ms)
        );

        status_led_off();

        vTaskDelay(
            pdMS_TO_TICKS(off_ms)
        );
    }
}


static void status_recoverable_error(
    error_ux_code_t code)
{
    status_red_blinks(
        (unsigned)code,
        140,
        120
    );

    // Leave a short visual gap before returning to idle.
    vTaskDelay(
        pdMS_TO_TICKS(250)
    );

    status_idle();
}


static void fatal_error_loop(
    error_ux_code_t code,
    const char *reason)
{
    ESP_LOGE(
        TAG,
        "Fatal error UX code=%u: %s",
        (unsigned)code,
        reason != NULL ? reason : "unknown"
    );

    while (true)
    {
        status_red_blinks(
            (unsigned)code,
            180,
            180
        );

        // Long gap separates one code group from the next.
        vTaskDelay(
            pdMS_TO_TICKS(900)
        );
    }
}


static void status_analyzing(void)
{
    // Purple is reserved for Analyzer mode/activity.
    status_led_rgb(
        STATUS_DIM,
        0,
        STATUS_MEDIUM
    );
}


// ============================================================
// Analyzer activity indication
//
// During the long RAW transfer / decode phase, alternate:
//   purple 1 s -> green 1 s -> repeat
// so the user can distinguish active work from a stuck solid LED.
// ============================================================

static bool analyzer_progress_purple = true;


static void analyzer_activity_start(void)
{
    analyzer_progress_purple = true;
    status_analyzing();
}


void analyzer_progress_hook(void)
{
    if (analyzer_progress_purple)
    {
        status_success();
    }
    else
    {
        status_analyzing();
    }

    analyzer_progress_purple =
        !analyzer_progress_purple;
}


static void analyzer_activity_stop(void)
{
    status_analyzing();
}


static void status_mode_feedback(
    bool analyzer_enabled,
    unsigned count)
{
    for (unsigned i = 0; i < count; ++i)
    {
        if (analyzer_enabled)
        {
            status_analyzing();
        }
        else
        {
            status_success();
        }

        vTaskDelay(pdMS_TO_TICKS(140));
        status_led_off();
        vTaskDelay(pdMS_TO_TICKS(120));
    }
}


static void status_reset_wait(
    bool on)
{
    if (on)
    {
        status_led_rgb(
            STATUS_MEDIUM,
            0,
            0
        );
    }
    else
    {
        status_led_off();
    }
}


static void status_reset_complete(void)
{
    for (int i = 0; i < 2; ++i)
    {
        status_led_rgb(
            0,
            STATUS_MEDIUM,
            0
        );

        vTaskDelay(
            pdMS_TO_TICKS(120)
        );

        status_led_off();

        vTaskDelay(
            pdMS_TO_TICKS(120)
        );
    }
}


// ============================================================
// Helpers
// ============================================================

static int64_t now_ms(void)
{
    return esp_timer_get_time() / 1000;
}


static void put16(
    uint8_t *p,
    uint16_t value)
{
    p[0] =
        (uint8_t)(value & 0xFF);

    p[1] =
        (uint8_t)((value >> 8) & 0xFF);
}


static void put32(
    uint8_t *p,
    uint32_t value)
{
    p[0] =
        (uint8_t)(value & 0xFF);

    p[1] =
        (uint8_t)((value >> 8) & 0xFF);

    p[2] =
        (uint8_t)((value >> 16) & 0xFF);

    p[3] =
        (uint8_t)((value >> 24) & 0xFF);
}


static uint16_t fat_date(
    uint16_t year,
    uint8_t month,
    uint8_t day)
{
    return (uint16_t)(
        ((year - 1980) << 9) |
        ((uint16_t)month << 5) |
        day
    );
}


static uint16_t fat_time(
    uint8_t hour,
    uint8_t minute,
    uint8_t second)
{
    return (uint16_t)(
        ((uint16_t)hour << 11) |
        ((uint16_t)minute << 5) |
        (second / 2)
    );
}


// ============================================================
// FAT12 entry writer
// ============================================================

static void fat12_set(
    uint16_t cluster,
    uint16_t value)
{
    value &= 0x0FFF;

    uint32_t offset =
        cluster + (cluster / 2);

    if (
        offset + 1 >=
        FAT_CACHE_BYTES
    )
    {
        return;
    }

    if (cluster & 1)
    {
        fat_table[offset] =
            (fat_table[offset] & 0x0F) |
            ((value << 4) & 0xF0);

        fat_table[offset + 1] =
            (uint8_t)(
                (value >> 4) &
                0xFF
            );
    }
    else
    {
        fat_table[offset] =
            (uint8_t)(
                value &
                0xFF
            );

        fat_table[offset + 1] =
            (fat_table[offset + 1] & 0xF0) |
            ((value >> 8) & 0x0F);
    }
}


static size_t required_file_clusters(
    size_t payload_length)
{
    size_t total =
        UTF8_BOM_SIZE +
        payload_length;

    size_t count =
        (
            total +
            CLUSTER_SIZE -
            1
        ) /
        CLUSTER_SIZE;

    if (count < 1)
    {
        count = 1;
    }

    if (count > FILE_CLUSTER_COUNT)
    {
        count =
            FILE_CLUSTER_COUNT;
    }

    return count;
}


static void build_file_chain(
    uint16_t first_cluster,
    size_t payload_length)
{
    size_t count =
        required_file_clusters(
            payload_length
        );

    for (size_t i = 0; i < count; ++i)
    {
        uint16_t cluster =
            first_cluster +
            (uint16_t)i;

        fat12_set(
            cluster,
            (i == count - 1)
                ? 0xFFF
                : (uint16_t)(
                    cluster + 1
                )
        );
    }
}


// ============================================================
// Directory helpers
// ============================================================

static void make_entry(
    uint8_t *entry,
    const char name[8],
    const char ext[3],
    uint8_t attributes,
    uint16_t first_cluster,
    uint32_t file_size)
{
    memset(
        entry,
        0,
        32
    );

    memcpy(
        entry,
        name,
        8
    );

    memcpy(
        entry + 8,
        ext,
        3
    );

    entry[11] =
        attributes;

    uint16_t date =
        fat_date(
            2026,
            8,
            16
        );

    uint16_t time =
        fat_time(
            0,
            0,
            0
        );

    put16(entry + 14, time);
    put16(entry + 16, date);
    put16(entry + 18, date);
    put16(entry + 20, 0);
    put16(entry + 22, time);
    put16(entry + 24, date);
    put16(entry + 26, first_cluster);
    put32(entry + 28, file_size);
}


static void make_history_name(
    uint16_t number,
    char name[8])
{
    number %= 10000;

    name[0] =
        '0' + ((number / 1000) % 10);

    name[1] =
        '0' + ((number / 100) % 10);

    name[2] =
        '0' + ((number / 10) % 10);

    name[3] =
        '0' + (number % 10);

    name[4] = ' ';
    name[5] = ' ';
    name[6] = ' ';
    name[7] = ' ';
}


static uint16_t history_first_cluster(
    uint16_t index)
{
    return
        HISTORY_FIRST_CLUSTER +
        index *
        FILE_CLUSTER_COUNT;
}


// ============================================================
// bcdDevice
// ============================================================

static void initialize_bcd_device(void)
{
    bcd_toggle_state =
        false;

    usb_device_descriptor.bcdDevice =
        0x0101;
}


static void toggle_bcd_device(void)
{
    bcd_toggle_state =
        !bcd_toggle_state;

    usb_device_descriptor.bcdDevice =
        bcd_toggle_state
            ? 0x0102
            : 0x0101;
}


// ============================================================
// Virtual-disk RAM cache lifecycle
//
// Analyzer releases this entire heap block after USB detach and Flash commit.
// It is rebuilt after native quirc completes.
// ============================================================

static esp_err_t allocate_virtual_disk_cache(void)
{
    if (virtual_disk_cache != NULL)
    {
        return ESP_OK;
    }

    uint8_t *block =
        heap_caps_malloc(
            VIRTUAL_DISK_CACHE_BYTES,
            MALLOC_CAP_8BIT
        );

    if (block == NULL)
    {
        ESP_LOGE(
            TAG,
            "Virtual disk cache allocation failed: %u bytes",
            (unsigned)VIRTUAL_DISK_CACHE_BYTES
        );
        return ESP_ERR_NO_MEM;
    }

    memset(
        block,
        0,
        VIRTUAL_DISK_CACHE_BYTES
    );

    size_t offset = 0;

    virtual_disk_cache = block;

    boot_sector = block + offset;
    offset += BOOT_CACHE_BYTES;

    fat_table = block + offset;
    offset += FAT_CACHE_BYTES;

    root_directory = block + offset;
    offset += ROOT_CACHE_BYTES;

    log_directory = block + offset;
    offset += LOG_DIR_CACHE_BYTES;

    latest_payload = block + offset;
    offset += LATEST_CACHE_BYTES;

    visible_log =
        (flash_record_info_t *)(void *)(block + offset);
    offset += VISIBLE_LOG_CACHE_BYTES;

    if (offset != VIRTUAL_DISK_CACHE_BYTES)
    {
        ESP_LOGE(
            TAG,
            "Virtual disk cache layout mismatch: %u/%u",
            (unsigned)offset,
            (unsigned)VIRTUAL_DISK_CACHE_BYTES
        );

        heap_caps_free(block);

        virtual_disk_cache = NULL;
        boot_sector = NULL;
        fat_table = NULL;
        root_directory = NULL;
        log_directory = NULL;
        latest_payload = NULL;
        visible_log = NULL;

        return ESP_FAIL;
    }

    ESP_LOGI(
        TAG,
        "Virtual disk cache allocated: %u bytes",
        (unsigned)VIRTUAL_DISK_CACHE_BYTES
    );

    return ESP_OK;
}


static void release_virtual_disk_cache(void)
{
    if (virtual_disk_cache == NULL)
    {
        return;
    }

    heap_caps_free(
        virtual_disk_cache
    );

    virtual_disk_cache = NULL;
    boot_sector = NULL;
    fat_table = NULL;
    root_directory = NULL;
    log_directory = NULL;
    latest_payload = NULL;
    visible_log = NULL;

    ESP_LOGI(
        TAG,
        "Virtual disk cache released for Analyzer"
    );
}


// ============================================================
// Load the newest 500 LOG records from Flash.
// ============================================================

static void refresh_visible_log(
    uint32_t exclude_sequence)
{
    memset(
        visible_log,
        0,
        VISIBLE_LOG_CACHE_BYTES
    );

    visible_log_count =
        (uint16_t)
        flash_store_get_recent(
            exclude_sequence,
            visible_log,
            LOG_MAX_ENTRIES
        );

    ESP_LOGI(
        TAG,
        "Flash committed=%u, LOG visible=%u, current seq=%lu",
        (unsigned)
            flash_store_record_count(),
        visible_log_count,
        (unsigned long)
            exclude_sequence
    );
}


// ============================================================
// Build Boot/FAT/directories in RAM.
//
// History file payloads are NOT copied to RAM.
// ============================================================

static void rebuild_virtual_fat_metadata(void)
{
    memset(
        boot_sector,
        0,
        BOOT_CACHE_BYTES
    );

    memset(
        fat_table,
        0,
        FAT_CACHE_BYTES
    );

    memset(
        root_directory,
        0,
        ROOT_CACHE_BYTES
    );

    memset(
        log_directory,
        0,
        LOG_DIR_CACHE_BYTES
    );


    // --------------------------------------------------------
    // Boot sector
    // --------------------------------------------------------

    boot_sector[0] = 0xEB;
    boot_sector[1] = 0x3C;
    boot_sector[2] = 0x90;

    memcpy(
        boot_sector + 3,
        "MSDOS5.0",
        8
    );

    put16(
        boot_sector + 11,
        SECTOR_SIZE
    );

    boot_sector[13] =
        SECTORS_PER_CLUSTER;

    put16(
        boot_sector + 14,
        RESERVED_SECTORS
    );

    boot_sector[16] =
        1;

    put16(
        boot_sector + 17,
        ROOT_ENTRY_COUNT
    );

    put16(
        boot_sector + 19,
        TOTAL_SECTORS
    );

    boot_sector[21] =
        0xF8;

    put16(
        boot_sector + 22,
        FAT_SECTORS
    );

    put16(
        boot_sector + 24,
        1
    );

    put16(
        boot_sector + 26,
        1
    );

    put32(
        boot_sector + 28,
        0
    );

    put32(
        boot_sector + 32,
        0
    );

    boot_sector[36] = 0x00;
    boot_sector[37] = 0x00;
    boot_sector[38] = 0x29;

    // Fixed FAT Volume Serial.
    put32(
        boot_sector + 39,
        0x51525452
    );

    memcpy(
        boot_sector + 43,
        "QRTRANSFER ",
        11
    );

    memcpy(
        boot_sector + 54,
        "FAT12   ",
        8
    );

    boot_sector[510] = 0x55;
    boot_sector[511] = 0xAA;


    // --------------------------------------------------------
    // FAT
    // --------------------------------------------------------

    fat12_set(
        0,
        0xFF8
    );

    fat12_set(
        1,
        0xFFF
    );


    // LOG directory chain.
    for (
        uint16_t i = 0;
        i < LOG_DIR_CLUSTER_COUNT;
        ++i
    )
    {
        uint16_t cluster =
            LOG_DIR_FIRST_CLUSTER + i;

        fat12_set(
            cluster,
            (i ==
                LOG_DIR_CLUSTER_COUNT - 1)
                ? 0xFFF
                : (uint16_t)(
                    cluster + 1
                )
        );
    }


    build_file_chain(
        LATEST_FIRST_CLUSTER,
        latest_payload_length
    );


    if (
        analyzer_mode_enabled() &&
        analyzer_has_result()
    )
    {
        for (uint16_t i = 0; i < ANALYSIS_CLUSTER_COUNT; ++i)
        {
            uint16_t cluster = ANALYSIS_FIRST_CLUSTER + i;
            fat12_set(
                cluster,
                (i == ANALYSIS_CLUSTER_COUNT - 1)
                    ? 0xFFF
                    : (uint16_t)(cluster + 1)
            );
        }

        if (flash_store_raw_available())
        {
            for (uint16_t i = 0; i < RAW_CLUSTER_COUNT; ++i)
            {
                uint16_t cluster = RAW_FIRST_CLUSTER + i;
                fat12_set(
                    cluster,
                    (i == RAW_CLUSTER_COUNT - 1)
                        ? 0xFFF
                        : (uint16_t)(cluster + 1)
                );
            }
        }
    }


    if (analyzer_mode_enabled() && debug_text_length > 0)
    {
        for (uint16_t i = 0; i < DEBUG_CLUSTER_COUNT; ++i)
        {
            uint16_t cluster = DEBUG_FIRST_CLUSTER + i;
            fat12_set(
                cluster,
                (i == DEBUG_CLUSTER_COUNT - 1)
                    ? 0xFFF
                    : (uint16_t)(cluster + 1)
            );
        }
    }


    for (
        uint16_t i = 0;
        i < visible_log_count;
        ++i
    )
    {
        build_file_chain(
            history_first_cluster(i),
            visible_log[i].length
        );
    }


    // --------------------------------------------------------
    // Root directory
    // --------------------------------------------------------

    memcpy(
        root_directory,
        "QRTRANSFER ",
        11
    );

    root_directory[11] =
        0x08;


    static const char latest_name[8] = {
        'L','A','T','E','S','T',' ',' '
    };

    static const char txt_ext[3] = {
        'T','X','T'
    };

    static const char log_name[8] = {
        'L','O','G',' ',' ',' ',' ',' '
    };

    static const char no_ext[3] = {
        ' ',' ',' '
    };


    make_entry(
        root_directory + 32,
        latest_name,
        txt_ext,
        0x21,
        LATEST_FIRST_CLUSTER,
        UTF8_BOM_SIZE +
            latest_payload_length
    );


    make_entry(
        root_directory + 64,
        log_name,
        no_ext,
        0x10,
        LOG_DIR_FIRST_CLUSTER,
        0
    );


    if (
        analyzer_mode_enabled() &&
        analyzer_has_result()
    )
    {
        static const char qrinfo_name[8] = {
            'Q','R','I','N','F','O',' ',' '
        };

        make_entry(
            root_directory + 96,
            qrinfo_name,
            txt_ext,
            0x21,
            ANALYSIS_FIRST_CLUSTER,
            (uint32_t)analyzer_result_json_length()
        );

        if (flash_store_raw_available())
        {
            static const char latest_image_name[8] = {
                'L','A','T','E','S','T',' ',' '
            };

            static const char bmp_ext[3] = {
                'B','M','P'
            };

            make_entry(
                root_directory + 128,
                latest_image_name,
                bmp_ext,
                0x21,
                RAW_FIRST_CLUSTER,
                RAW_BMP_FILE_SIZE
            );
        }
    }


    if (analyzer_mode_enabled() && debug_text_length > 0)
    {
        static const char debug_name[8] = {
            'D','E','B','U','G',' ',' ',' '
        };

        make_entry(
            root_directory + 160,
            debug_name,
            txt_ext,
            0x21,
            DEBUG_FIRST_CLUSTER,
            (uint32_t)debug_text_length
        );
    }


    // --------------------------------------------------------
    // LOG directory "." and ".."
    // --------------------------------------------------------

    static const char dot_name[8] = {
        '.',' ',' ',' ',' ',' ',' ',' '
    };

    static const char dotdot_name[8] = {
        '.','.',' ',' ',' ',' ',' ',' '
    };


    make_entry(
        log_directory,
        dot_name,
        no_ext,
        0x10,
        LOG_DIR_FIRST_CLUSTER,
        0
    );


    make_entry(
        log_directory + 32,
        dotdot_name,
        no_ext,
        0x10,
        0,
        0
    );


    // --------------------------------------------------------
    // LOG entries
    // --------------------------------------------------------

    for (
        uint16_t i = 0;
        i < visible_log_count;
        ++i
    )
    {
        char history_name[8];

        make_history_name(
            visible_log[i].number,
            history_name
        );

        make_entry(
            log_directory +
                (size_t)(i + 2) * 32,
            history_name,
            txt_ext,
            0x21,
            history_first_cluster(i),
            UTF8_BOM_SIZE +
                visible_log[i].length
        );
    }
}


// ============================================================
// Initialize Windows-visible view after MCU boot.
//
// All committed Flash records become LOG.
// LATEST is blank.
// ============================================================

static void initialize_virtual_disk_from_flash(void)
{
    current_record_sequence =
        0;

    memset(
        latest_payload,
        0,
        LATEST_CACHE_BYTES
    );

    latest_payload[0] =
        0x20;

    latest_payload_length =
        1;

    refresh_visible_log(0);

    rebuild_virtual_fat_metadata();
}


// ============================================================
// Read file bytes: BOM + RAM payload.
// ============================================================

static void read_latest_file_range(
    size_t file_offset,
    uint8_t *dst,
    size_t length)
{
    memset(
        dst,
        0,
        length
    );

    size_t file_size =
        UTF8_BOM_SIZE +
        latest_payload_length;

    if (file_offset >= file_size)
    {
        return;
    }

    size_t available =
        file_size -
        file_offset;

    if (length > available)
    {
        length =
            available;
    }


    for (size_t i = 0; i < length; ++i)
    {
        size_t pos =
            file_offset + i;

        if (pos < UTF8_BOM_SIZE)
        {
            dst[i] =
                utf8_bom[pos];
        }
        else
        {
            dst[i] =
                latest_payload[
                    pos -
                    UTF8_BOM_SIZE
                ];
        }
    }
}


// ============================================================
// Read file bytes: BOM + Flash payload.
// ============================================================

static esp_err_t read_history_file_range(
    const flash_record_info_t *record,
    size_t file_offset,
    uint8_t *dst,
    size_t length)
{
    memset(
        dst,
        0,
        length
    );

    size_t file_size =
        UTF8_BOM_SIZE +
        record->length;

    if (file_offset >= file_size)
    {
        return ESP_OK;
    }

    size_t valid_length =
        file_size -
        file_offset;

    if (valid_length > length)
    {
        valid_length =
            length;
    }


    size_t cursor = 0;


    // BOM portion.
    if (file_offset < UTF8_BOM_SIZE)
    {
        size_t bom_available =
            UTF8_BOM_SIZE -
            file_offset;

        size_t bom_count =
            (valid_length < bom_available)
                ? valid_length
                : bom_available;

        memcpy(
            dst,
            utf8_bom +
                file_offset,
            bom_count
        );

        cursor +=
            bom_count;
    }


    // Payload portion.
    if (cursor < valid_length)
    {
        size_t absolute_pos =
            file_offset +
            cursor;

        if (absolute_pos >= UTF8_BOM_SIZE)
        {
            size_t payload_offset =
                absolute_pos -
                UTF8_BOM_SIZE;

            size_t payload_count =
                valid_length -
                cursor;

            esp_err_t err =
                flash_store_read_range(
                    record,
                    payload_offset,
                    dst + cursor,
                    payload_count
                );

            if (err != ESP_OK)
            {
                ESP_LOGE(
                    TAG,
                    "Flash MSC read failed seq=%lu off=%u len=%u: %s",
                    (unsigned long)
                        record->sequence,
                    (unsigned)
                        payload_offset,
                    (unsigned)
                        payload_count,
                    esp_err_to_name(err)
                );

                return err;
            }
        }
    }

    return ESP_OK;
}


// ============================================================
// Virtual disk sector reader.
// ============================================================

static esp_err_t virtual_disk_read_sector(
    uint32_t lba,
    uint8_t sector[SECTOR_SIZE])
{
    memset(
        sector,
        0,
        SECTOR_SIZE
    );


    // Boot.
    if (lba == 0)
    {
        memcpy(
            sector,
            boot_sector,
            SECTOR_SIZE
        );

        return ESP_OK;
    }


    // FAT.
    if (
        lba >= FAT_START_SECTOR &&
        lba <
            FAT_START_SECTOR +
            FAT_SECTORS
    )
    {
        size_t offset =
            (size_t)(
                lba -
                FAT_START_SECTOR
            ) *
            SECTOR_SIZE;

        memcpy(
            sector,
            fat_table + offset,
            SECTOR_SIZE
        );

        return ESP_OK;
    }


    // Root.
    if (
        lba >= ROOT_START_SECTOR &&
        lba <
            ROOT_START_SECTOR +
            ROOT_SECTORS
    )
    {
        size_t offset =
            (size_t)(
                lba -
                ROOT_START_SECTOR
            ) *
            SECTOR_SIZE;

        memcpy(
            sector,
            root_directory + offset,
            SECTOR_SIZE
        );

        return ESP_OK;
    }


    if (lba >= TOTAL_SECTORS)
    {
        return ESP_ERR_INVALID_ARG;
    }


    // --------------------------------------------------------
    // Data area -> cluster mapping
    // --------------------------------------------------------

    uint32_t data_sector =
        lba -
        DATA_START_SECTOR;

    uint16_t cluster =
        (uint16_t)(
            2 +
            (
                data_sector /
                SECTORS_PER_CLUSTER
            )
        );

    uint16_t sector_in_cluster =
        (uint16_t)(
            data_sector %
            SECTORS_PER_CLUSTER
        );


    // LOG directory.
    if (
        cluster >=
            LOG_DIR_FIRST_CLUSTER &&
        cluster <
            LOG_DIR_FIRST_CLUSTER +
            LOG_DIR_CLUSTER_COUNT
    )
    {
        size_t cluster_index =
            cluster -
            LOG_DIR_FIRST_CLUSTER;

        size_t offset =
            cluster_index *
                CLUSTER_SIZE +
            sector_in_cluster *
                SECTOR_SIZE;

        memcpy(
            sector,
            log_directory + offset,
            SECTOR_SIZE
        );

        return ESP_OK;
    }


    // LATEST.
    if (
        cluster >=
            LATEST_FIRST_CLUSTER &&
        cluster <
            LATEST_FIRST_CLUSTER +
            FILE_CLUSTER_COUNT
    )
    {
        size_t file_offset =
            (size_t)(
                cluster -
                LATEST_FIRST_CLUSTER
            ) *
                CLUSTER_SIZE +
            sector_in_cluster *
                SECTOR_SIZE;

        read_latest_file_range(
            file_offset,
            sector,
            SECTOR_SIZE
        );

        return ESP_OK;
    }


    // LOG file payloads.
    if (
        cluster >= HISTORY_FIRST_CLUSTER &&
        cluster < HISTORY_FIRST_CLUSTER + HISTORY_DATA_CLUSTERS
    )
    {
        uint32_t relative =
            cluster -
            HISTORY_FIRST_CLUSTER;

        uint16_t index =
            (uint16_t)(
                relative /
                FILE_CLUSTER_COUNT
            );

        uint16_t cluster_in_file =
            (uint16_t)(
                relative %
                FILE_CLUSTER_COUNT
            );

        if (index >= LOG_MAX_ENTRIES)
        {
            return ESP_OK;
        }

        if (index >= visible_log_count)
        {
            return ESP_OK;
        }

        size_t file_offset =
            (size_t)
                cluster_in_file *
                CLUSTER_SIZE +
            sector_in_cluster *
                SECTOR_SIZE;

        return
            read_history_file_range(
                &visible_log[index],
                file_offset,
                sector,
                SECTOR_SIZE
            );
    }


    // Analyzer metadata JSON stored as QRINFO.TXT.
    if (
        analyzer_mode_enabled() &&
        analyzer_has_result() &&
        cluster >= ANALYSIS_FIRST_CLUSTER &&
        cluster < ANALYSIS_FIRST_CLUSTER + ANALYSIS_CLUSTER_COUNT
    )
    {
        size_t file_offset =
            (size_t)(cluster - ANALYSIS_FIRST_CLUSTER) * CLUSTER_SIZE +
            sector_in_cluster * SECTOR_SIZE;

        size_t json_length = analyzer_result_json_length();
        if (file_offset < json_length)
        {
            size_t amount = json_length - file_offset;
            if (amount > SECTOR_SIZE)
            {
                amount = SECTOR_SIZE;
            }

            memcpy(
                sector,
                analyzer_result_json() + file_offset,
                amount
            );
        }

        return ESP_OK;
    }


    // Boot/debug report. This is independent of analyzer_has_result() so it
    // survives a reset that occurred before QRINFO.TXT was completed.
    if (
        analyzer_mode_enabled() &&
        debug_text_length > 0 &&
        cluster >= DEBUG_FIRST_CLUSTER &&
        cluster < DEBUG_FIRST_CLUSTER + DEBUG_CLUSTER_COUNT
    )
    {
        size_t file_offset =
            (size_t)(cluster - DEBUG_FIRST_CLUSTER) * CLUSTER_SIZE +
            sector_in_cluster * SECTOR_SIZE;

        if (file_offset < debug_text_length)
        {
            size_t amount = debug_text_length - file_offset;
            if (amount > SECTOR_SIZE)
            {
                amount = SECTOR_SIZE;
            }

            memcpy(sector, debug_text + file_offset, amount);
        }

        return ESP_OK;
    }


    // Analyzer image exposed as a Windows-friendly, lossless 8-bit BMP.
    // The flash payload remains the scanner-native 640x480 GRAY8 bytes.
    if (
        analyzer_mode_enabled() &&
        analyzer_has_result() &&
        flash_store_raw_available() &&
        cluster >= RAW_FIRST_CLUSTER &&
        cluster < RAW_FIRST_CLUSTER + RAW_CLUSTER_COUNT
    )
    {
        size_t file_offset =
            (size_t)(cluster - RAW_FIRST_CLUSTER) * CLUSTER_SIZE +
            sector_in_cluster * SECTOR_SIZE;

        // 54-byte BMP/DIB prefix.  Width=640, height=-480 (top-down),
        // 8 bpp, BI_RGB, 256 grayscale palette entries.
        static const uint8_t bmp_prefix[54] = {
            0x42, 0x4d,                         // signature: BM
            0x36, 0xb4, 0x04, 0x00,             // file size: 308278
            0x00, 0x00, 0x00, 0x00,             // reserved
            0x36, 0x04, 0x00, 0x00,             // pixel offset: 1078
            0x28, 0x00, 0x00, 0x00,             // DIB size: 40
            0x80, 0x02, 0x00, 0x00,             // width: 640
            0x20, 0xfe, 0xff, 0xff,             // height: -480 (top-down)
            0x01, 0x00,                         // planes: 1
            0x08, 0x00,                         // bpp: 8
            0x00, 0x00, 0x00, 0x00,             // BI_RGB
            0x00, 0xb0, 0x04, 0x00,             // image bytes: 307200
            0x13, 0x0b, 0x00, 0x00,             // X ppm: 2835
            0x13, 0x0b, 0x00, 0x00,             // Y ppm: 2835
            0x00, 0x01, 0x00, 0x00,             // colors used: 256
            0x00, 0x01, 0x00, 0x00              // important colors: 256
        };

        if (file_offset < RAW_BMP_HEADER_SIZE)
        {
            size_t header_amount =
                RAW_BMP_HEADER_SIZE - file_offset;

            if (header_amount > SECTOR_SIZE)
            {
                header_amount = SECTOR_SIZE;
            }

            for (size_t i = 0; i < header_amount; ++i)
            {
                size_t pos = file_offset + i;

                if (pos < sizeof(bmp_prefix))
                {
                    sector[i] = bmp_prefix[pos];
                }
                else
                {
                    // Palette entry n is B,G,R,0 = n,n,n,0.
                    size_t palette_pos = pos - sizeof(bmp_prefix);
                    uint8_t level = (uint8_t)(palette_pos / 4u);
                    sector[i] =
                        (palette_pos % 4u == 3u) ? 0u : level;
                }
            }

            if (header_amount < SECTOR_SIZE)
            {
                size_t raw_amount = SECTOR_SIZE - header_amount;

                if (raw_amount > FLASH_STORE_RAW_BYTES)
                {
                    raw_amount = FLASH_STORE_RAW_BYTES;
                }

                return flash_store_raw_read(
                    0,
                    sector + header_amount,
                    raw_amount
                );
            }

            return ESP_OK;
        }

        size_t raw_offset = file_offset - RAW_BMP_HEADER_SIZE;

        if (raw_offset < FLASH_STORE_RAW_BYTES)
        {
            size_t amount = FLASH_STORE_RAW_BYTES - raw_offset;

            if (amount > SECTOR_SIZE)
            {
                amount = SECTOR_SIZE;
            }

            return flash_store_raw_read(
                raw_offset,
                sector,
                amount
            );
        }

        return ESP_OK;
    }

    return ESP_OK;
}


// ============================================================
// Generic read that supports offset/bufsize crossing sectors.
// ============================================================

static esp_err_t virtual_disk_read(
    uint32_t lba,
    uint32_t offset,
    uint8_t *buffer,
    uint32_t bufsize)
{
    if (
        lba >= TOTAL_SECTORS ||
        offset >= SECTOR_SIZE
    )
    {
        return ESP_ERR_INVALID_ARG;
    }

    uint64_t position =
        (uint64_t)lba *
            SECTOR_SIZE +
        offset;

    uint64_t total_bytes =
        (uint64_t)TOTAL_SECTORS *
        SECTOR_SIZE;

    if (
        position +
        bufsize >
        total_bytes
    )
    {
        return ESP_ERR_INVALID_SIZE;
    }


    uint8_t sector[SECTOR_SIZE];

    uint32_t remaining =
        bufsize;

    uint32_t out_offset =
        0;


    while (remaining > 0)
    {
        uint32_t current_lba =
            (uint32_t)(
                position /
                SECTOR_SIZE
            );

        uint32_t inside =
            (uint32_t)(
                position %
                SECTOR_SIZE
            );

        uint32_t chunk =
            SECTOR_SIZE -
            inside;

        if (chunk > remaining)
        {
            chunk =
                remaining;
        }


        esp_err_t err =
            virtual_disk_read_sector(
                current_lba,
                sector
            );

        if (err != ESP_OK)
        {
            return err;
        }


        memcpy(
            buffer + out_offset,
            sector + inside,
            chunk
        );


        position +=
            chunk;

        out_offset +=
            chunk;

        remaining -=
            chunk;
    }


    return ESP_OK;
}


// ============================================================
// Boot LOG-reset gesture
//
// The button must already be held when the MCU starts.
// Release after >=3 s and before 10 s to erase history and return to Normal.
// Hold through 10 s to toggle Normal/Analyzer without erasing history.
// This intentionally does NOT use long-press during normal operation.
// ============================================================

typedef enum
{
    BOOT_ACTION_NONE = 0,
    BOOT_ACTION_CLEAR_HISTORY,
    BOOT_ACTION_TOGGLE_MODE

} boot_action_t;


static boot_action_t boot_gesture_action(void)
{
    if (gpio_get_level(BUTTON_GPIO) != 0)
    {
        return BOOT_ACTION_NONE;
    }

    ESP_LOGW(
        TAG,
        "Boot button held: release after 3s to erase LOG and return Normal; hold 10s to toggle mode"
    );

    int64_t started = now_ms();
    int64_t last_blink = started;
    bool blink_on = true;
    bool mode_threshold_reached = false;

    status_reset_wait(true);

    while (gpio_get_level(BUTTON_GPIO) == 0)
    {
        int64_t now = now_ms();
        int64_t elapsed = now - started;

        if (elapsed >= BOOT_MODE_TOGGLE_HOLD_MS)
        {
            mode_threshold_reached = true;
            status_analyzing();

            /* Wait for release so one hold produces one toggle only. */
            while (gpio_get_level(BUTTON_GPIO) == 0)
            {
                vTaskDelay(pdMS_TO_TICKS(10));
            }
            break;
        }

        if (elapsed >= BOOT_CLEAR_MIN_HOLD_MS)
        {
            /* Solid red means erase is armed if released before 10s. */
            status_reset_wait(true);
        }
        else if (now - last_blink >= 250)
        {
            blink_on = !blink_on;
            status_reset_wait(blink_on);
            last_blink = now;
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }

    int64_t held_ms = now_ms() - started;
    status_idle();

    if (mode_threshold_reached || held_ms >= BOOT_MODE_TOGGLE_HOLD_MS)
    {
        ESP_LOGW(TAG, "Boot mode toggle confirmed");
        return BOOT_ACTION_TOGGLE_MODE;
    }

    if (held_ms >= BOOT_CLEAR_MIN_HOLD_MS)
    {
        ESP_LOGW(TAG, "Boot LOG reset confirmed after %lld ms", held_ms);
        return BOOT_ACTION_CLEAR_HISTORY;
    }

    ESP_LOGI(TAG, "Boot hold cancelled after %lld ms", held_ms);
    return BOOT_ACTION_NONE;
}


// ============================================================
// QRCode2 protocol commands
// ============================================================

static const uint8_t QR_CMD_PING[] = {
    0x23, 0x61, 0x41
};


// Analyzer may temporarily persist the scanner at 128000 bps if power is lost.
// Boot recovery probes 128000 and restores the normal 115200 baseline.
static const uint8_t QR_CMD_BAUD_115200[] = {
    0x21, 0x41, 0x41, 0x0B
};

static const uint8_t QR_CMD_MANUAL_MODE[] = {
    0x21, 0x61, 0x41, 0x00
};

static const uint8_t QR_CMD_SCAN_START[] = {
    0x32, 0x75, 0x01
};

static const uint8_t QR_CMD_SCAN_STOP[] = {
    0x32, 0x75, 0x02
};

static const uint8_t QR_CMD_STARTUP_SOUND_OFF[] = {
    0x21, 0x63, 0x45, 0x00
};

static const uint8_t QR_CMD_SUCCESS_SOUND_ON[] = {
    0x21, 0x63, 0x46, 0x01
};

static const uint8_t QR_CMD_SUCCESS_COUNT_ONE[] = {
    0x21, 0x63, 0x42, 0x01
};

static const uint8_t QR_CMD_SUCCESS_TONE_SHORT[] = {
    0x21, 0x63, 0x41, 0x00
};

static const uint8_t QR_CMD_FILL_LIGHT_OFF[] = {
    0x21, 0x62, 0x41, 0x00
};

static const uint8_t QR_CMD_FILL_LIGHT_DECODE[] = {
    0x21, 0x62, 0x41, 0x02
};


// QRCode2 native Protocol Format setting (PID/FID 51 43).
// 00 = no protocol, 03 = Format 3 with Code ID metadata.
//
// The official protocol states Configuration Write values are applied and
// saved to the scanner storage medium. Normal boot therefore explicitly
// restores value 00 before normal scanning.
static const uint8_t QR_CMD_PROTOCOL_OFF[] = {
    0x21, 0x51, 0x43, 0x00
};

static const uint8_t QR_CMD_PROTOCOL_FORMAT3[] = {
    0x21, 0x51, 0x43, 0x03
};


// ============================================================
// QRCode2 positioning / aiming light
//
// 21 62 42 00 : off
// 21 62 42 01 : flash
//
// This is separate from the white fill light.
// ============================================================

static const uint8_t QR_CMD_POSITION_LIGHT_OFF[] = {
    0x21, 0x62, 0x42, 0x00
};

static const uint8_t QR_CMD_POSITION_LIGHT_FLASH[] = {
    0x21, 0x62, 0x42, 0x01
};


// ============================================================
// QRCode2 native Protocol Format 3
//
// M5Stack UIFlow2 documents Format 3 as:
//   03 + Data Length + Number of Barcodes
//      + Code 1 ID + Code 1 Data Length + Code 1 Data + ... + CRC
//
// The documentation does not make byte order / CRC coverage explicit enough
// for this firmware, so the PoC parser validates both BE/LE length encodings
// and several plausible CRC placements. The actual observed encoding is
// recorded in QRINFO.TXT.
// ============================================================

static bool qr_protocol_format3_requested = false;
static bool qr_protocol_write_reply_seen = false;
static int qr_protocol_write_rid = -1;
static bool qr_protocol_readback_seen = false;
static int qr_protocol_readback_value = -1;
static char qr_protocol_write_reply_hex[64] = "";
static char qr_protocol_readback_hex[64] = "";

typedef struct
{
    bool detected;
    bool crc_valid;
    uint8_t barcode_count;
    uint16_t code_id;
    const uint8_t *payload;
    size_t payload_length;
    const char *length_endian;
    const char *crc_scope;
    const char *crc_endian;
} qr_protocol3_frame_t;


// ============================================================
// QR UART helpers
// ============================================================

static void qr_uart_flush(void)
{
    uart_flush_input(
        QR_UART
    );
}


static void qr_send(
    const uint8_t *data,
    size_t length)
{
    uart_write_bytes(
        QR_UART,
        data,
        length
    );

    uart_wait_tx_done(
        QR_UART,
        pdMS_TO_TICKS(100)
    );
}


static void qr_send_config(
    const uint8_t *command,
    size_t length)
{
    qr_uart_flush();

    qr_send(
        command,
        length
    );

    vTaskDelay(
        pdMS_TO_TICKS(80)
    );

    qr_uart_flush();
}


static void qr_bytes_to_hex(
    const uint8_t *src,
    size_t src_len,
    char *dst,
    size_t dst_size)
{
    if (
        dst == NULL ||
        dst_size == 0
    )
    {
        return;
    }

    dst[0] = 0;
    size_t used = 0;

    for (size_t i = 0; i < src_len; ++i)
    {
        int n =
            snprintf(
                dst + used,
                dst_size - used,
                "%s%02X",
                i == 0 ? "" : " ",
                src[i]
            );

        if (
            n < 0 ||
            (size_t)n >= dst_size - used
        )
        {
            break;
        }

        used +=
            (size_t)n;
    }
}


static int qr_read_exact_timeout(
    uint8_t *dst,
    size_t length,
    int timeout_ms)
{
    size_t done = 0;
    int elapsed = 0;

    while (
        done < length &&
        elapsed < timeout_ms
    )
    {
        int got =
            uart_read_bytes(
                QR_UART,
                dst + done,
                length - done,
                pdMS_TO_TICKS(25)
            );

        if (got > 0)
        {
            done +=
                (size_t)got;
        }

        elapsed += 25;
    }

    return (int)done;
}


static void qr_protocol_format_write_and_readback(
    uint8_t requested_value)
{
    const uint8_t *write_command = NULL;
    size_t write_command_length = 0;

    if (requested_value == 0x03)
    {
        write_command =
            QR_CMD_PROTOCOL_FORMAT3;
        write_command_length =
            sizeof(QR_CMD_PROTOCOL_FORMAT3);
    }
    else if (requested_value == 0x00)
    {
        write_command =
            QR_CMD_PROTOCOL_OFF;
        write_command_length =
            sizeof(QR_CMD_PROTOCOL_OFF);
    }
    else
    {
        ESP_LOGE(
            TAG,
            "Unsupported local Protocol Format request: 0x%02X",
            requested_value
        );
        return;
    }

    qr_protocol_write_reply_seen = false;
    qr_protocol_write_rid = -1;
    qr_protocol_readback_seen = false;
    qr_protocol_readback_value = -1;
    qr_protocol_write_reply_hex[0] = 0;
    qr_protocol_readback_hex[0] = 0;

    /*
     * Configuration Write Reply:
     *   22 PID FID PAR RID
     *
     * For a one-byte value, PAR echoes the requested value.
     * RID 00 = success, 01 = illegal PID/FID.
     */
    qr_uart_flush();

    qr_send(
        write_command,
        write_command_length
    );

    uint8_t write_reply[5] = {0};

    int write_got =
        qr_read_exact_timeout(
            write_reply,
            sizeof(write_reply),
            500
        );

    if (write_got > 0)
    {
        qr_bytes_to_hex(
            write_reply,
            (size_t)write_got,
            qr_protocol_write_reply_hex,
            sizeof(qr_protocol_write_reply_hex)
        );
    }

    if (
        write_got == 5 &&
        write_reply[0] == 0x22 &&
        write_reply[1] == 0x51 &&
        write_reply[2] == 0x43 &&
        write_reply[3] == requested_value
    )
    {
        qr_protocol_write_reply_seen =
            true;

        qr_protocol_write_rid =
            write_reply[4];
    }

    /*
     * Configuration Read:
     *   host   23 PID FID
     *   module 24 PID FID PARAM
     */
    qr_uart_flush();

    static const uint8_t read_command[3] = {
        0x23, 0x51, 0x43
    };

    qr_send(
        read_command,
        sizeof(read_command)
    );

    uint8_t readback[4] = {0};

    int read_got =
        qr_read_exact_timeout(
            readback,
            sizeof(readback),
            500
        );

    if (read_got > 0)
    {
        qr_bytes_to_hex(
            readback,
            (size_t)read_got,
            qr_protocol_readback_hex,
            sizeof(qr_protocol_readback_hex)
        );
    }

    if (
        read_got == 4 &&
        readback[0] == 0x24 &&
        readback[1] == 0x51 &&
        readback[2] == 0x43
    )
    {
        qr_protocol_readback_seen =
            true;

        qr_protocol_readback_value =
            readback[3];
    }

    ESP_LOGI(
        TAG,
        "Protocol Format write=%02X reply=[%s] rid=%d readback=[%s] value=%d",
        requested_value,
        qr_protocol_write_reply_hex,
        qr_protocol_write_rid,
        qr_protocol_readback_hex,
        qr_protocol_readback_value
    );

    qr_uart_flush();
}


static uint16_t qr_crc16_calc(
    const uint8_t *data,
    size_t length)
{
    uint32_t crc = 0;

    for (size_t n = 0; n < length; ++n)
    {
        uint8_t byte = data[n];

        for (int bit = 7; bit >= 0; --bit)
        {
            if (crc & 0x8000u)
            {
                crc =
                    (crc << 1) ^
                    0x18005u;
            }
            else
            {
                crc <<= 1;
            }

            if (
                byte &
                (1u << bit)
            )
            {
                crc ^=
                    0x18005u;
            }
        }
    }

    return
        (uint16_t)(crc & 0xFFFFu);
}


static bool qr_protocol3_crc_matches(
    const uint8_t *frame,
    size_t frame_length)
{
    if (
        frame == NULL ||
        frame_length < 5
    )
    {
        return false;
    }

    /*
     * Verified against an actual QRCode2 Format 3 frame:
     *
     *   03 00 0C 01 00 57 00 05 61 62 63 64 65 91 F3
     *
     * for QR payload "abcde".
     *
     * M5Stack's published crc16_calc() over every byte from the initial 0x03
     * through the last payload byte returns 0x91F3 exactly. CRC storage is
     * therefore big-endian and the CRC covers the complete frame except the
     * final two CRC bytes.
     */
    uint16_t stored =
        ((uint16_t)frame[frame_length - 2] << 8) |
        frame[frame_length - 1];

    uint16_t calculated =
        qr_crc16_calc(
            frame,
            frame_length - 2
        );

    return
        calculated == stored;
}


static bool qr_protocol3_parse_be(
    const uint8_t *frame,
    size_t frame_length,
    qr_protocol3_frame_t *result)
{
    if (
        frame == NULL ||
        result == NULL ||
        frame_length < 10 ||
        frame[0] != 0x03
    )
    {
        return false;
    }

    /*
     * Actual QRCode2 Format 3 frame observed on
     * ZScan.mh T43m3 1.2.1.18.230604:
     *
     *   03 00 0C 01 00 57 00 05 "abcde" 91 F3
     *
     * Meaning:
     *   03       format
     *   00 0C    Data Length = 12 bytes following this field, INCLUDING CRC
     *   01       number of barcodes
     *   00 57    Code ID (2 bytes)
     *   00 05    barcode data length
     *   ...      barcode payload
     *   91 F3    CRC16, big-endian
     *
     * Therefore total UART frame size is:
     *   1 + 2 + DataLength
     */
    uint16_t data_length =
        ((uint16_t)frame[1] << 8) |
        frame[2];

    if (
        data_length < 7 ||
        (size_t)data_length + 3u !=
            frame_length
    )
    {
        return false;
    }

    uint8_t barcode_count =
        frame[3];

    if (barcode_count == 0)
    {
        return false;
    }

    size_t offset = 4;

    /*
     * Current product path stores the first barcode only. The frame is still
     * CRC-verified over the complete multi-barcode packet.
     */
    if (offset + 4u > frame_length - 2u)
    {
        return false;
    }

    uint16_t code_id =
        ((uint16_t)frame[offset] << 8) |
        frame[offset + 1];

    offset += 2;

    uint16_t code_length =
        ((uint16_t)frame[offset] << 8) |
        frame[offset + 1];

    offset += 2;

    if (
        offset + (size_t)code_length >
            frame_length - 2u
    )
    {
        return false;
    }

    /*
     * For a single barcode, its data must end exactly before CRC.
     * Keep the parser conservative until multi-barcode framing is exercised.
     */
    if (
        barcode_count == 1 &&
        offset + (size_t)code_length !=
            frame_length - 2u
    )
    {
        return false;
    }

    result->detected = true;
    result->barcode_count =
        barcode_count;
    result->code_id =
        code_id;
    result->payload =
        frame + offset;
    result->payload_length =
        code_length;
    result->length_endian =
        "BE";
    result->crc_valid =
        qr_protocol3_crc_matches(
            frame,
            frame_length
        );
    result->crc_scope =
        "FULL_FRAME_EXCEPT_CRC";
    result->crc_endian =
        "BE";

    return true;
}


static qr_protocol3_frame_t qr_parse_protocol_format3(
    const uint8_t *frame,
    size_t frame_length)
{
    qr_protocol3_frame_t result = {
        .detected = false,
        .crc_valid = false,
        .barcode_count = 0,
        .code_id = 0,
        .payload = frame,
        .payload_length = frame_length,
        .length_endian = "UNKNOWN",
        .crc_scope = "UNVERIFIED",
        .crc_endian = "UNKNOWN"
    };

    if (
        frame == NULL ||
        frame_length < 10 ||
        frame[0] != 0x03
    )
    {
        return result;
    }

    qr_protocol3_frame_t candidate =
        result;

    if (
        qr_protocol3_parse_be(
            frame,
            frame_length,
            &candidate
        )
    )
    {
        return candidate;
    }

    return result;
}


static void qr_configure_protocol_format(
    bool analyzer_enabled)
{
    uint8_t requested_value =
        analyzer_enabled ? 0x03 : 0x00;

    qr_protocol_format_write_and_readback(
        requested_value
    );

    qr_protocol_format3_requested =
        analyzer_enabled;

    ESP_LOGI(
        TAG,
        "QRCode2 Protocol Format requested: %s; write_reply=%s rid=%d readback=%s value=%d",
        analyzer_enabled
            ? "FORMAT_3"
            : "OFF",
        qr_protocol_write_reply_seen
            ? "yes"
            : "no",
        qr_protocol_write_rid,
        qr_protocol_readback_seen
            ? "yes"
            : "no",
        qr_protocol_readback_value
    );
}


static void qr_set_fill_light(
    bool enabled)
{
    if (enabled)
    {
        qr_send_config(
            QR_CMD_FILL_LIGHT_DECODE,
            sizeof(
                QR_CMD_FILL_LIGHT_DECODE
            )
        );

        fill_light_enabled =
            true;
    }
    else
    {
        qr_send_config(
            QR_CMD_FILL_LIGHT_OFF,
            sizeof(
                QR_CMD_FILL_LIGHT_OFF
            )
        );

        fill_light_enabled =
            false;
    }

    ESP_LOGI(
        TAG,
        "Fill light=%s",
        fill_light_enabled
            ? "ON during scan"
            : "OFF"
    );
}


static void qr_toggle_fill_light(void)
{
    qr_set_fill_light(
        !fill_light_enabled
    );

    status_fill_light_feedback(
        fill_light_enabled
    );
}


static void qr_set_position_light(
    bool flashing)
{
    if (flashing)
    {
        qr_send_config(
            QR_CMD_POSITION_LIGHT_FLASH,
            sizeof(
                QR_CMD_POSITION_LIGHT_FLASH
            )
        );
    }
    else
    {
        qr_send_config(
            QR_CMD_POSITION_LIGHT_OFF,
            sizeof(
                QR_CMD_POSITION_LIGHT_OFF
            )
        );
    }
}


static void qr_configure_audio(void)
{
    qr_send_config(
        QR_CMD_STARTUP_SOUND_OFF,
        sizeof(
            QR_CMD_STARTUP_SOUND_OFF
        )
    );

    qr_send_config(
        QR_CMD_SUCCESS_SOUND_ON,
        sizeof(
            QR_CMD_SUCCESS_SOUND_ON
        )
    );

    qr_send_config(
        QR_CMD_SUCCESS_COUNT_ONE,
        sizeof(
            QR_CMD_SUCCESS_COUNT_ONE
        )
    );

    qr_send_config(
        QR_CMD_SUCCESS_TONE_SHORT,
        sizeof(
            QR_CMD_SUCCESS_TONE_SHORT
        )
    );
}


static bool qr_scanner_ping_once(void)
{
    qr_uart_flush();

    qr_send(
        QR_CMD_PING,
        sizeof(QR_CMD_PING)
    );

    uint8_t response[16] = {0};

    int received =
        uart_read_bytes(
            QR_UART,
            response,
            sizeof(response),
            pdMS_TO_TICKS(300)
        );

    return
        received >= 3 &&
        response[0] == 0x24 &&
        response[1] == 0x61 &&
        response[2] == 0x41;
}


static bool qr_scanner_init(void)
{
    uart_config_t config = {
        .baud_rate =
            QR_UART_BAUD,

        .data_bits =
            UART_DATA_8_BITS,

        .parity =
            UART_PARITY_DISABLE,

        .stop_bits =
            UART_STOP_BITS_1,

        .flow_ctrl =
            UART_HW_FLOWCTRL_DISABLE,

        .source_clk =
            UART_SCLK_DEFAULT
    };


    ESP_ERROR_CHECK(
        uart_driver_install(
            QR_UART,
            QR_UART_RX_BUFFER_SIZE,
            0,
            0,
            NULL,
            0
        )
    );


    ESP_ERROR_CHECK(
        uart_param_config(
            QR_UART,
            &config
        )
    );


    ESP_ERROR_CHECK(
        uart_set_pin(
            QR_UART,
            QR_UART_TX_GPIO,
            QR_UART_RX_GPIO,
            UART_PIN_NO_CHANGE,
            UART_PIN_NO_CHANGE
        )
    );


    vTaskDelay(
        pdMS_TO_TICKS(1500)
    );


    bool ready = false;


    for (
        int attempt = 0;
        attempt < 5;
        ++attempt
    )
    {
        if (
            qr_scanner_ping_once())
        {
            ready = true;
            break;
        }


        ESP_LOGW(
            TAG,
            "QRCode2 init retry %d at 115200",
            attempt + 1
        );


        vTaskDelay(
            pdMS_TO_TICKS(300)
        );
    }


    if (!ready)
    {
        /*
         * Analyzer uses 128000 for RAW transfer. If power was removed before
         * Analyzer restored 115200, the scanner can boot at 128000 because
         * this setting is persistent. Recover automatically.
         */
        ESP_LOGW(
            TAG,
            "QRCode2 not responding at 115200; probing 128000"
        );


        ESP_ERROR_CHECK(
            uart_set_baudrate(
                QR_UART,
                128000
            )
        );


        vTaskDelay(
            pdMS_TO_TICKS(100)
        );


        for (
            int attempt = 0;
            attempt < 3;
            ++attempt
        )
        {
            if (
                qr_scanner_ping_once())
            {
                ESP_LOGW(
                    TAG,
                    "QRCode2 recovered at 128000; restoring 115200"
                );


                qr_uart_flush();

                qr_send(
                    QR_CMD_BAUD_115200,
                    sizeof(
                        QR_CMD_BAUD_115200
                    )
                );


                uint8_t reply[5] = {0};


                int got =
                    uart_read_bytes(
                        QR_UART,
                        reply,
                        sizeof(reply),
                        pdMS_TO_TICKS(500)
                    );


                if (
                    got == 5 &&
                    reply[0] == 0x22 &&
                    reply[1] == 0x41 &&
                    reply[2] == 0x41 &&
                    reply[3] == 0x0B &&
                    reply[4] == 0x00)
                {
                    ESP_ERROR_CHECK(
                        uart_set_baudrate(
                            QR_UART,
                            QR_UART_BAUD
                        )
                    );


                    vTaskDelay(
                        pdMS_TO_TICKS(100)
                    );


                    ready =
                        qr_scanner_ping_once();
                }


                break;
            }


            vTaskDelay(
                pdMS_TO_TICKS(300)
            );
        }
    }


    if (!ready)
    {
        return false;
    }


    qr_send_config(
        QR_CMD_MANUAL_MODE,
        sizeof(
            QR_CMD_MANUAL_MODE
        )
    );

    qr_configure_audio();

    qr_set_fill_light(
        false
    );

    qr_set_position_light(
        false
    );

    qr_uart_flush();


    ESP_LOGI(
        TAG,
        "QRCode2 ready at 115200"
    );


    return true;
}


static void qr_start_scan(void)
{
    qr_uart_flush();

    qr_length = 0;
    qr_receiving = false;

    // Enable the QRCode2 positioning marker only for scanning.
    qr_set_position_light(
        true
    );

    status_scanning();

    scan_started_ms =
        now_ms();

    qr_send(
        QR_CMD_SCAN_START,
        sizeof(
            QR_CMD_SCAN_START
        )
    );

    device_state =
        STATE_SCANNING;
}


static void qr_stop_scan(void)
{
    qr_send(
        QR_CMD_SCAN_STOP,
        sizeof(
            QR_CMD_SCAN_STOP
        )
    );

    vTaskDelay(
        pdMS_TO_TICKS(20)
    );

    qr_uart_flush();

    qr_set_position_light(
        false
    );
}


static bool qr_is_status_packet(
    const uint8_t *data,
    size_t length)
{
    if (length != 3)
    {
        return false;
    }

    if (
        data[0] == 0x33 &&
        data[1] == 0x75 &&
        data[2] == 0x02
    )
    {
        return true;
    }

    if (
        data[0] == 0x22 &&
        data[1] == 0x61 &&
        data[2] == 0x41
    )
    {
        return true;
    }

    return false;
}


// ============================================================
// New scan -> Flash -> virtual FAT.
// ============================================================

static void update_latest_from_qr(
    const uint8_t *data,
    size_t length,
    bool protocol3_detected,
    bool crc_valid,
    uint8_t barcode_count,
    uint16_t code_id,
    const char *length_endian,
    const char *crc_scope,
    const char *crc_endian)
{
    if (length > MAX_QR_BYTES)
    {
        ESP_LOGE(
            TAG,
            "QR too large: %u",
            (unsigned)length
        );

        status_recoverable_error(
            ERROR_UX_SCAN_SAVE
        );

        device_state =
            STATE_IDLE;

        return;
    }


    device_state =
        STATE_UPDATING;

    tap_pending =
        false;

    // QRCode2 normally stops decoding after a successful read,
    // but explicitly restore the positioning light to OFF.
    qr_set_position_light(
        false
    );

    status_success();


    tud_disconnect();


    vTaskDelay(
        pdMS_TO_TICKS(
            USB_DISCONNECT_MS
        )
    );


    flash_record_info_t new_record;


    esp_err_t err =
        flash_store_append(
            data,
            length,
            &new_record
        );


    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Flash append failed: %s",
            esp_err_to_name(err)
        );

        tud_connect();

        // The old virtual disk is still valid because metadata was
        // rebuilt only after a successful Flash commit. Give clear
        // feedback, then allow a retry rather than locking the UI.
        status_recoverable_error(
            ERROR_UX_SCAN_SAVE
        );

        guard_started_ms =
            now_ms();

        device_state =
            STATE_GUARD;

        return;
    }


    if (analyzer_mode_enabled())
    {
        analyzer_diag_mark(
            10,  /* AD_SCAN_COMMITTED */
            0
        );
    }


    /*
     * Analyzer work starts only after the QR payload has been committed
     * successfully. The USB device is already detached in the established
     * update path, so Analyzer mode intentionally has a longer detach time.
     * Normal mode follows the original v1.5 timing path unchanged.
     */
    if (analyzer_mode_enabled())
    {
        qr_stop_scan();

        release_virtual_disk_cache();

        ESP_LOGI(
            TAG,
            "Analyzer pre-quirc after MSC cache release: free=%u largest=%u",
            (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
            (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT)
        );

        analyzer_activity_start();

        esp_err_t analysis_err =
            analyzer_process_scan_metadata(
                QR_UART,
                data,
                length,
                qr_protocol_format3_requested,
                qr_protocol_write_reply_seen,
                qr_protocol_write_rid,
                qr_protocol_readback_seen,
                qr_protocol_readback_value,
                qr_protocol_write_reply_hex,
                qr_protocol_readback_hex,
                protocol3_detected,
                crc_valid,
                barcode_count,
                code_id,
                length_endian,
                crc_scope,
                crc_endian
            );

        analyzer_activity_stop();

        if (analysis_err != ESP_OK)
        {
            ESP_LOGW(
                TAG,
                "Analyzer result incomplete: %s",
                esp_err_to_name(analysis_err)
            );
        }

        status_success();

        esp_err_t cache_err =
            allocate_virtual_disk_cache();

        if (cache_err != ESP_OK)
        {
            fatal_error_loop(
                ERROR_UX_FLASH,
                "Virtual disk cache re-allocation failed after Analyzer"
            );
        }

        ESP_LOGI(
            TAG,
            "Analyzer post-quirc cache restored: free=%u largest=%u",
            (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
            (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT)
        );
    }


    current_record_sequence =
        new_record.sequence;


    memset(
        latest_payload,
        0,
        LATEST_CACHE_BYTES
    );


    if (length > 0)
    {
        memcpy(
            latest_payload,
            data,
            length
        );
    }


    latest_payload_length =
        length;


    refresh_visible_log(
        current_record_sequence
    );


    toggle_bcd_device();

    if (analyzer_mode_enabled())
    {
        analyzer_diag_mark(
            210, /* AD_FAT_REBUILD_START */
            0
        );
    }

    rebuild_virtual_fat_metadata();

    if (analyzer_mode_enabled())
    {
        analyzer_diag_mark(
            220, /* AD_FAT_REBUILD_DONE */
            0
        );
    }


    ESP_LOGI(
        TAG,
        "QR=%u bytes seq=%lu num=%04u LOG=%u/%u physical=%u/%u bcdDevice=0x%04X",
        (unsigned)length,
        (unsigned long)
            new_record.sequence,
        new_record.number,
        visible_log_count,
        LOG_MAX_ENTRIES,
        (unsigned)
            flash_store_record_count(),
        (unsigned)
            flash_store_slot_count(),
        usb_device_descriptor.bcdDevice
    );


    tud_connect();

    if (analyzer_mode_enabled())
    {
        analyzer_diag_mark(
            230, /* AD_USB_CONNECT_CALLED */
            0
        );
    }


    guard_started_ms =
        now_ms();


    device_state =
        STATE_GUARD;

    if (analyzer_mode_enabled())
    {
        analyzer_diag_mark(
            240, /* AD_GUARD_ENTERED */
            0
        );
    }
}


// ============================================================
// QR poll
// ============================================================

static void qr_poll(void)
{
    uint8_t temp[256];


    int received =
        uart_read_bytes(
            QR_UART,
            temp,
            sizeof(temp),
            0
        );


    if (received > 0)
    {
        size_t free_space =
            MAX_QR_BYTES -
            qr_length;


        if (
            (size_t)received >
            free_space
        )
        {
            ESP_LOGE(
                TAG,
                "QR exceeds %d bytes",
                MAX_QR_BYTES
            );

            qr_stop_scan();

            qr_length = 0;
            qr_receiving = false;

            status_recoverable_error(
                ERROR_UX_SCAN_SAVE
            );

            device_state =
                STATE_IDLE;

            return;
        }


        memcpy(
            qr_buffer +
                qr_length,
            temp,
            received
        );


        qr_length +=
            received;

        qr_receiving =
            true;

        qr_last_byte_ms =
            now_ms();
    }


    int64_t now =
        now_ms();


    if (
        qr_receiving &&
        (
            now -
            qr_last_byte_ms
        ) >=
            QR_INTERBYTE_TIMEOUT_MS
    )
    {
        if (
            qr_is_status_packet(
                qr_buffer,
                qr_length
            )
        )
        {
            qr_length = 0;
            qr_receiving = false;

            return;
        }


        size_t completed_length =
            qr_length;


        qr_length = 0;
        qr_receiving = false;


        qr_protocol3_frame_t protocol3 =
            qr_parse_protocol_format3(
                qr_buffer,
                completed_length
            );

        bool protocol3_expected =
            analyzer_mode_enabled() &&
            qr_protocol_write_reply_seen &&
            qr_protocol_write_rid == 0 &&
            qr_protocol_readback_seen &&
            qr_protocol_readback_value == 3;

        /*
         * Payload integrity is a product invariant.
         *
         * If a Format 3 envelope is present, never persist data extracted from
         * it unless the frame CRC is valid and exactly one barcode is present.
         *
         * When Analyzer has positively configured/read back Format 3, a frame
         * that does not parse as Format 3 is also rejected rather than being
         * mistaken for raw QR payload. This prevents protocol bytes from ever
         * leaking into LATEST.TXT/LOG again.
         */
        if (
            (
                protocol3.detected &&
                (
                    !protocol3.crc_valid ||
                    protocol3.barcode_count != 1
                )
            ) ||
            (
                protocol3_expected &&
                !protocol3.detected
            )
        )
        {
            ESP_LOGE(
                TAG,
                "Rejecting invalid Analyzer frame: expected=%d detected=%d crc=%d count=%u",
                protocol3_expected ? 1 : 0,
                protocol3.detected ? 1 : 0,
                protocol3.crc_valid ? 1 : 0,
                (unsigned)protocol3.barcode_count
            );

            qr_stop_scan();

            status_recoverable_error(
                ERROR_UX_SCAN_SAVE
            );

            device_state =
                STATE_IDLE;

            return;
        }

        update_latest_from_qr(
            protocol3.payload,
            protocol3.payload_length,
            protocol3.detected,
            protocol3.crc_valid,
            protocol3.barcode_count,
            protocol3.code_id,
            protocol3.length_endian,
            protocol3.crc_scope,
            protocol3.crc_endian
        );

        return;
    }


    if (
        (
            now -
            scan_started_ms
        ) >=
            QR_SCAN_TIMEOUT_MS
    )
    {
        ESP_LOGW(
            TAG,
            "QR scan timeout"
        );

        qr_stop_scan();

        qr_length = 0;
        qr_receiving = false;

        // Brief timeout feedback. The positioning light has
        // already been turned off by qr_stop_scan().
        status_timeout();

        vTaskDelay(
            pdMS_TO_TICKS(400)
        );

        status_idle();

        device_state =
            STATE_IDLE;
    }
}


// ============================================================
// Idle button handling
// ============================================================

static void handle_idle_button_press(void)
{
    int64_t now =
        now_ms();


    if (
        tap_pending &&
        (
            now -
            first_tap_ms
        ) <=
            DOUBLE_TAP_MS
    )
    {
        tap_pending =
            false;

        qr_toggle_fill_light();

        return;
    }


    tap_pending =
        true;

    first_tap_ms =
        now;
}


// ============================================================
// TinyUSB MSC callbacks
// ============================================================

void tud_msc_inquiry_cb(
    uint8_t lun,
    uint8_t vendor_id[8],
    uint8_t product_id[16],
    uint8_t product_rev[4])
{
    (void)lun;

    memset(vendor_id, ' ', 8);
    memset(product_id, ' ', 16);
    memset(product_rev, ' ', 4);

    memcpy(vendor_id, "QRDEV", 5);
    memcpy(product_id, "QR TRANSFER", 11);
    memcpy(product_rev, "1.6", 3);
}


bool tud_msc_test_unit_ready_cb(
    uint8_t lun)
{
    (void)lun;

    return true;
}


void tud_msc_capacity_cb(
    uint8_t lun,
    uint32_t *block_count,
    uint16_t *block_size)
{
    (void)lun;

    *block_count =
        TOTAL_SECTORS;

    *block_size =
        SECTOR_SIZE;
}


bool tud_msc_start_stop_cb(
    uint8_t lun,
    uint8_t power_condition,
    bool start,
    bool load_eject)
{
    (void)lun;
    (void)power_condition;
    (void)start;
    (void)load_eject;

    return true;
}


bool tud_msc_is_writable_cb(
    uint8_t lun)
{
    (void)lun;

    return false;
}


int32_t tud_msc_read10_cb(
    uint8_t lun,
    uint32_t lba,
    uint32_t offset,
    void *buffer,
    uint32_t bufsize)
{
    (void)lun;


    esp_err_t err =
        virtual_disk_read(
            lba,
            offset,
            (uint8_t *)buffer,
            bufsize
        );


    if (err != ESP_OK)
    {
        return -1;
    }


    return
        (int32_t)bufsize;
}


int32_t tud_msc_write10_cb(
    uint8_t lun,
    uint32_t lba,
    uint32_t offset,
    uint8_t *buffer,
    uint32_t bufsize)
{
    (void)lun;
    (void)lba;
    (void)offset;
    (void)buffer;
    (void)bufsize;

    return -1;
}


bool tud_msc_prevent_allow_medium_removal_cb(
    uint8_t lun,
    uint8_t prohibit_removal,
    uint8_t control)
{
    (void)lun;
    (void)prohibit_removal;
    (void)control;

    // The QR Transfer volume is virtual/read-only and has no
    // physically removable medium behind the MSC LUN.
    //
    // Accept the host request.  Modern TinyUSB provides this
    // dedicated callback for PREVENT/ALLOW MEDIUM REMOVAL.
    return true;
}


int32_t tud_msc_scsi_cb(
    uint8_t lun,
    uint8_t const scsi_cmd[16],
    void *buffer,
    uint16_t bufsize)
{
    (void)lun;
    (void)scsi_cmd;
    (void)buffer;
    (void)bufsize;

    // All SCSI commands required by this device are handled by
    // TinyUSB's built-in MSC path or their dedicated callbacks.
    //
    // Returning -1 for an unsupported command makes TinyUSB fail
    // the request.  TinyUSB supplies the default ILLEGAL REQUEST
    // sense when the application has not set a more specific one.
    //
    // Keeping this callback free of TinyUSB-internal SCSI enum
    // constants improves compatibility across TinyUSB revisions.
    return -1;
}


// ============================================================
// Main device task
// ============================================================

static void device_task(
    void *arg)
{
    (void)arg;


    int previous_button =
        gpio_get_level(
            BUTTON_GPIO
        );


    while (1)
    {
        int current_button =
            gpio_get_level(
                BUTTON_GPIO
            );


        if (
            device_state ==
                STATE_IDLE &&
            previous_button == 1 &&
            current_button == 0
        )
        {
            vTaskDelay(
                pdMS_TO_TICKS(
                    BUTTON_DEBOUNCE_MS
                )
            );


            if (
                device_state ==
                    STATE_IDLE &&
                gpio_get_level(
                    BUTTON_GPIO
                ) == 0
            )
            {
                handle_idle_button_press();
            }
        }


        current_button =
            gpio_get_level(
                BUTTON_GPIO
            );


        if (
            device_state ==
                STATE_IDLE &&
            tap_pending &&
            (
                now_ms() -
                first_tap_ms
            ) >
                DOUBLE_TAP_MS
        )
        {
            tap_pending =
                false;

            qr_start_scan();
        }


        if (
            device_state ==
                STATE_SCANNING
        )
        {
            qr_poll();
        }


        if (
            device_state ==
                STATE_GUARD
        )
        {
            tap_pending =
                false;


            if (
                (
                    now_ms() -
                    guard_started_ms
                ) >=
                    RECONNECT_GUARD_MS
            )
            {
                status_idle();

                device_state =
                    STATE_IDLE;
            }
        }


        previous_button =
            current_button;


        vTaskDelay(
            pdMS_TO_TICKS(5)
        );
    }
}


// ============================================================
// app_main
// ============================================================

void app_main(void)
{
    esp_reset_reason_t reset_reason = esp_reset_reason();
    ESP_LOGW(
        TAG,
        "BOOT reset_reason=%d (%s)",
        (int)reset_reason,
        reset_reason_name(reset_reason)
    );

    gpio_config_t button_config = {
        .pin_bit_mask =
            1ULL <<
            BUTTON_GPIO,

        .mode =
            GPIO_MODE_INPUT,

        .pull_up_en =
            GPIO_PULLUP_ENABLE,

        .pull_down_en =
            GPIO_PULLDOWN_DISABLE,

        .intr_type =
            GPIO_INTR_DISABLE
    };


    ESP_ERROR_CHECK(
        gpio_config(
            &button_config
        )
    );


    ESP_ERROR_CHECK(
        status_led_init()
    );

    status_idle();


    // --------------------------------------------------------
    // Persistent operating mode is loaded before interpreting the
    // power-on hold gesture. Normal mode performs no image analysis.
    // --------------------------------------------------------

    esp_err_t mode_err = analyzer_mode_init();
    if (mode_err != ESP_OK)
    {
        ESP_LOGW(
            TAG,
            "Analyzer mode NVS unavailable; defaulting to Normal: %s",
            esp_err_to_name(mode_err)
        );
    }

    if (analyzer_mode_enabled())
    {
        int written = snprintf(
            debug_text,
            sizeof(debug_text),
            "QRTransfer Analyzer DEBUG\r\n"
            "firmware_version=2.4.6\r\n"
            "source_variant=qrtransfer_v2_4_6_stable_analyzer\r\n"
            "reset_reason=%d\r\n"
            "reset_reason_name=%s\r\n"
            "operating_mode=ANALYZER\r\n",
            (int)reset_reason,
            reset_reason_name(reset_reason)
        );

        if (written > 0)
        {
            debug_text_length = (size_t)written;
            if (debug_text_length >= sizeof(debug_text))
            {
                debug_text_length = sizeof(debug_text) - 1;
            }

            if (debug_text_length < sizeof(debug_text) - 1)
            {
                debug_text_length += analyzer_diag_format_last(
                    debug_text + debug_text_length,
                    sizeof(debug_text) - debug_text_length
                );
                if (debug_text_length >= sizeof(debug_text))
                {
                    debug_text_length = sizeof(debug_text) - 1;
                }
            }
        }
    }


    boot_action_t boot_action = boot_gesture_action();

    if (boot_action == BOOT_ACTION_TOGGLE_MODE)
    {
        mode_err = analyzer_mode_toggle();
        if (mode_err != ESP_OK)
        {
            fatal_error_loop(
                ERROR_UX_FLASH,
                "Operating mode persistence failed"
            );
        }

        status_mode_feedback(
            analyzer_mode_enabled(),
            3
        );
    }


    esp_err_t flash_err =
        flash_store_init();

    if (flash_err != ESP_OK)
    {
        fatal_error_loop(
            ERROR_UX_FLASH,
            "Flash history initialization failed"
        );
    }


    if (boot_action == BOOT_ACTION_CLEAR_HISTORY)
    {
        /*
         * A 3-second clear is also the explicit way to leave Analyzer mode.
         * Keep the mode persistent across ordinary reboots, but make the
         * diagnostic cleanup gesture return the unit to Normal.
         */
        if (analyzer_mode_enabled())
        {
            mode_err = analyzer_mode_toggle();
            if (mode_err != ESP_OK)
            {
                fatal_error_loop(
                    ERROR_UX_FLASH,
                    "Operating mode reset failed"
                );
            }

            ESP_LOGW(
                TAG,
                "History clear also reset Analyzer mode to Normal"
            );
        }

        flash_err =
            flash_store_reset();

        if (flash_err != ESP_OK)
        {
            fatal_error_loop(
                ERROR_UX_FLASH,
                "Flash history erase failed"
            );
        }

        status_reset_complete();
    }


    initialize_bcd_device();


    esp_err_t cache_err =
        allocate_virtual_disk_cache();

    if (cache_err != ESP_OK)
    {
        fatal_error_loop(
            ERROR_UX_FLASH,
            "Virtual disk cache allocation failed"
        );
    }


    initialize_virtual_disk_from_flash();


    if (!qr_scanner_init())
    {
        ESP_LOGE(
            TAG,
            "QRCode2 initialization FAILED"
        );

        fatal_error_loop(
            ERROR_UX_QR_INIT,
            "QRCode2 initialization failed"
        );
    }


    /*
     * Use QRCode2's own Protocol Format setting.
     *
     * Analyzer:
     *   21 51 43 03 -> Format 3 (includes Code ID)
     *
     * Normal:
     *   21 51 43 00 -> protocol off / original payload
     *
     * The receive path also recognizes Format 3 explicitly and unwraps the
     * first barcode before storage, keeping LATEST.TXT as payload-only.
     */
    qr_configure_protocol_format(
        analyzer_mode_enabled()
    );


    const tinyusb_config_t tusb_cfg = {
        .device_descriptor =
            &usb_device_descriptor,

        .string_descriptor =
            usb_string_descriptors,

        .string_descriptor_count =
            sizeof(
                usb_string_descriptors
            ) /
            sizeof(
                usb_string_descriptors[0]
            ),

        .external_phy =
            false,

        .configuration_descriptor =
            NULL,

        .self_powered =
            false,

        .vbus_monitor_io =
            0
    };


    esp_err_t usb_err =
        tinyusb_driver_install(
            &tusb_cfg
        );

    if (usb_err != ESP_OK)
    {
        fatal_error_loop(
            ERROR_UX_FLASH,
            "USB MSC initialization failed"
        );
    }


    ESP_LOGI(
        TAG,
        "v2.4.6 LATEST.BMP diagnostic capture ready"
    );

    ESP_LOGI(
        TAG,
        "Virtual disk: %u sectors (%u bytes), cluster=%u bytes",
        (unsigned)TOTAL_SECTORS,
        (unsigned)(
            TOTAL_SECTORS *
            SECTOR_SIZE
        ),
        (unsigned)
            CLUSTER_SIZE
    );

    ESP_LOGI(
        TAG,
        "LOG policy: max %u, physical Flash slots=%u",
        LOG_MAX_ENTRIES,
        (unsigned)
            flash_store_slot_count()
    );

    ESP_LOGI(
        TAG,
        "Operating mode: %s",
        analyzer_mode_enabled() ? "ANALYZER" : "NORMAL"
    );

    if (analyzer_mode_enabled())
    {
        status_mode_feedback(true, 2);
    }

    status_idle();


    xTaskCreate(
        device_task,
        "device_task",
        analyzer_mode_enabled() ? 8192 : 4096,
        NULL,
        5,
        NULL
    );
}
