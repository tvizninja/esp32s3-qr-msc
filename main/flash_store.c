\
#include "flash_store.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_partition.h"

static const char *TAG = "FLASH_STORE";

#define STORE_PARTITION_LABEL   "qrstore"

#define FLASH_SECTOR_SIZE       4096u
#define RECORD_SLOT_SIZE        8192u
#define RECORD_PAYLOAD_OFFSET   4096u

#define RAW_RESERVED_SLOTS      44u
#define RAW_RESERVED_BYTES      (RAW_RESERVED_SLOTS * RECORD_SLOT_SIZE)
#define RAW_HEADER_BYTES        FLASH_SECTOR_SIZE
#define RAW_MAGIC               0x31574152u  /* "RAW1" little-endian */
#define BIN_MAGIC               0x314E4942u  /* "BIN1" little-endian */

#define RECORD_MAGIC            0x31545251u  /* "QRT1" little-endian */
#define RECORD_VERSION          1u

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t header_size;
    uint32_t sequence;
    uint16_t number;
    uint16_t payload_length;
    uint32_t payload_crc32;
    uint32_t reserved0;
    uint32_t reserved1;
    uint32_t reserved2;
} record_header_t;

_Static_assert(
    sizeof(record_header_t) == 32,
    "record_header_t must be 32 bytes"
);

typedef struct {
    uint32_t magic;
    uint16_t width;
    uint16_t height;
    uint32_t length;
    uint32_t reserved0;
} raw_header_t;

typedef raw_header_t binary_header_t;

static const esp_partition_t *store_partition = NULL;


static uint32_t crc32_ieee(
    const uint8_t *data,
    size_t length)
{
    uint32_t crc = 0xFFFFFFFFu;

    for (size_t i = 0; i < length; ++i)
    {
        crc ^= data[i];

        for (int bit = 0; bit < 8; ++bit)
        {
            uint32_t mask =
                (uint32_t)(-(int32_t)(crc & 1u));

            crc =
                (crc >> 1) ^
                (0xEDB88320u & mask);
        }
    }

    return ~crc;
}


static size_t slot_count_internal(void)
{
    if (store_partition == NULL)
    {
        return 0;
    }

    size_t physical_slots =
        store_partition->size /
        RECORD_SLOT_SIZE;

    if (physical_slots <= RAW_RESERVED_SLOTS)
    {
        return 0;
    }

    return
        physical_slots -
        RAW_RESERVED_SLOTS;
}


static size_t slot_offset(
    uint16_t slot)
{
    return
        (size_t)slot *
        RECORD_SLOT_SIZE;
}


static bool header_is_valid(
    const record_header_t *header)
{
    return
        header->magic ==
            RECORD_MAGIC &&
        header->version ==
            RECORD_VERSION &&
        header->header_size ==
            sizeof(record_header_t) &&
        header->payload_length <=
            FLASH_STORE_MAX_PAYLOAD;
}


static esp_err_t read_header(
    uint16_t slot,
    record_header_t *header)
{
    if (store_partition == NULL)
    {
        return ESP_ERR_INVALID_STATE;
    }

    if (slot >= slot_count_internal())
    {
        return ESP_ERR_INVALID_ARG;
    }

    return
        esp_partition_read(
            store_partition,
            slot_offset(slot),
            header,
            sizeof(*header)
        );
}


static int compare_record_sequence(
    const void *a,
    const void *b)
{
    const flash_record_info_t *ra =
        (const flash_record_info_t *)a;

    const flash_record_info_t *rb =
        (const flash_record_info_t *)b;

    if (ra->sequence < rb->sequence)
    {
        return -1;
    }

    if (ra->sequence > rb->sequence)
    {
        return 1;
    }

    return 0;
}


static size_t scan_records(
    flash_record_info_t *records,
    size_t capacity)
{
    size_t count = 0;
    size_t slots =
        slot_count_internal();

    for (size_t slot = 0; slot < slots; ++slot)
    {
        record_header_t header;

        if (
            read_header(
                (uint16_t)slot,
                &header
            ) != ESP_OK
        )
        {
            continue;
        }

        if (!header_is_valid(&header))
        {
            continue;
        }

        if (
            records != NULL &&
            count < capacity
        )
        {
            records[count].sequence =
                header.sequence;

            records[count].number =
                header.number;

            records[count].length =
                header.payload_length;

            records[count].slot =
                (uint16_t)slot;
        }

        ++count;
    }

    return count;
}


static esp_err_t verify_info(
    const flash_record_info_t *info,
    record_header_t *header)
{
    if (
        store_partition == NULL ||
        info == NULL ||
        header == NULL
    )
    {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err =
        read_header(
            info->slot,
            header
        );

    if (err != ESP_OK)
    {
        return err;
    }

    if (
        !header_is_valid(header) ||
        header->sequence != info->sequence ||
        header->number != info->number ||
        header->payload_length != info->length
    )
    {
        return ESP_ERR_INVALID_STATE;
    }

    return ESP_OK;
}


static size_t raw_area_offset(void)
{
    return
        slot_count_internal() *
        RECORD_SLOT_SIZE;
}


static size_t raw_payload_offset(void)
{
    return
        raw_area_offset() +
        RAW_HEADER_BYTES;
}

static size_t binary_header_offset(void)
{
    return raw_payload_offset() + FLASH_STORE_RAW_BYTES;
}

static size_t binary_payload_offset(void)
{
    return binary_header_offset() + FLASH_SECTOR_SIZE;
}


esp_err_t flash_store_raw_begin(void)
{
    if (store_partition == NULL)
    {
        return ESP_ERR_INVALID_STATE;
    }

    if (
        RAW_HEADER_BYTES +
            FLASH_STORE_RAW_BYTES >
        RAW_RESERVED_BYTES)
    {
        return ESP_ERR_INVALID_SIZE;
    }

    return
        esp_partition_erase_range(
            store_partition,
            raw_area_offset(),
            RAW_RESERVED_BYTES
        );
}


esp_err_t flash_store_raw_write(
    size_t offset,
    const uint8_t *data,
    size_t length)
{
    if (
        store_partition == NULL ||
        (length > 0 && data == NULL) ||
        offset > FLASH_STORE_RAW_BYTES ||
        length >
            FLASH_STORE_RAW_BYTES -
            offset)
    {
        return ESP_ERR_INVALID_ARG;
    }

    return
        esp_partition_write(
            store_partition,
            raw_payload_offset() +
                offset,
            data,
            length
        );
}


esp_err_t flash_store_raw_commit(void)
{
    if (store_partition == NULL)
    {
        return ESP_ERR_INVALID_STATE;
    }

    raw_header_t header = {
        .magic = RAW_MAGIC,
        .width = FLASH_STORE_RAW_WIDTH,
        .height = FLASH_STORE_RAW_HEIGHT,
        .length = FLASH_STORE_RAW_BYTES,
        .reserved0 = 0xFFFFFFFFu
    };

    return
        esp_partition_write(
            store_partition,
            raw_area_offset(),
            &header,
            sizeof(header)
        );
}


bool flash_store_raw_available(void)
{
    if (store_partition == NULL)
    {
        return false;
    }

    raw_header_t header;

    if (
        esp_partition_read(
            store_partition,
            raw_area_offset(),
            &header,
            sizeof(header)
        ) != ESP_OK)
    {
        return false;
    }

    return
        header.magic == RAW_MAGIC &&
        header.width == FLASH_STORE_RAW_WIDTH &&
        header.height == FLASH_STORE_RAW_HEIGHT &&
        header.length == FLASH_STORE_RAW_BYTES;
}


esp_err_t flash_store_raw_read(
    size_t offset,
    uint8_t *buffer,
    size_t length)
{
    if (
        store_partition == NULL ||
        buffer == NULL ||
        offset > FLASH_STORE_RAW_BYTES ||
        length >
            FLASH_STORE_RAW_BYTES -
            offset)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (!flash_store_raw_available())
    {
        return ESP_ERR_NOT_FOUND;
    }

    return
        esp_partition_read(
            store_partition,
            raw_payload_offset() +
                offset,
            buffer,
            length
        );
}



esp_err_t flash_store_binary_begin(void)
{
    if (store_partition == NULL) return ESP_ERR_INVALID_STATE;

    const size_t erase_len = FLASH_SECTOR_SIZE + FLASH_STORE_BINARY_BYTES;
    const size_t erase_aligned =
        (erase_len + FLASH_SECTOR_SIZE - 1) & ~(FLASH_SECTOR_SIZE - 1);

    return esp_partition_erase_range(
        store_partition, binary_header_offset(), erase_aligned);
}


esp_err_t flash_store_binary_write(
    size_t offset,
    const uint8_t *data,
    size_t length)
{
    if (store_partition == NULL || (length > 0 && data == NULL) ||
        offset > FLASH_STORE_BINARY_BYTES ||
        length > FLASH_STORE_BINARY_BYTES - offset)
    {
        return ESP_ERR_INVALID_ARG;
    }

    return esp_partition_write(
        store_partition,
        binary_payload_offset() + offset,
        data,
        length
    );
}

esp_err_t flash_store_binary_commit(void)
{
    if (store_partition == NULL) return ESP_ERR_INVALID_STATE;

    binary_header_t header = {
        .magic = BIN_MAGIC,
        .width = FLASH_STORE_RAW_WIDTH,
        .height = FLASH_STORE_RAW_HEIGHT,
        .length = FLASH_STORE_BINARY_BYTES,
        .reserved0 = 0xFFFFFFFFu
    };

    return esp_partition_write(
        store_partition, binary_header_offset(), &header, sizeof(header));
}

bool flash_store_binary_available(void)
{
    if (store_partition == NULL) return false;
    binary_header_t header;
    if (esp_partition_read(store_partition, binary_header_offset(), &header, sizeof(header)) != ESP_OK)
        return false;
    return header.magic == BIN_MAGIC &&
           header.width == FLASH_STORE_RAW_WIDTH &&
           header.height == FLASH_STORE_RAW_HEIGHT &&
           header.length == FLASH_STORE_BINARY_BYTES;
}

esp_err_t flash_store_binary_read(
    size_t offset, uint8_t *buffer, size_t length)
{
    if (store_partition == NULL || buffer == NULL ||
        offset > FLASH_STORE_BINARY_BYTES ||
        length > FLASH_STORE_BINARY_BYTES - offset)
        return ESP_ERR_INVALID_ARG;
    if (!flash_store_binary_available()) return ESP_ERR_NOT_FOUND;
    return esp_partition_read(store_partition, binary_payload_offset() + offset, buffer, length);
}

esp_err_t flash_store_init(void)
{
    store_partition =
        esp_partition_find_first(
            ESP_PARTITION_TYPE_DATA,
            ESP_PARTITION_SUBTYPE_ANY,
            STORE_PARTITION_LABEL
        );

    if (store_partition == NULL)
    {
        ESP_LOGE(
            TAG,
            "Partition '%s' not found",
            STORE_PARTITION_LABEL
        );

        return ESP_ERR_NOT_FOUND;
    }

    if (
        store_partition->size <
            RECORD_SLOT_SIZE ||
        (store_partition->size %
            FLASH_SECTOR_SIZE) != 0
    )
    {
        ESP_LOGE(
            TAG,
            "Invalid partition size: 0x%lx",
            (unsigned long)
                store_partition->size
        );

        return ESP_ERR_INVALID_SIZE;
    }

    ESP_LOGI(
        TAG,
        "partition=%s offset=0x%lx size=0x%lx slots=%u",
        store_partition->label,
        (unsigned long)
            store_partition->address,
        (unsigned long)
            store_partition->size,
        (unsigned)
            slot_count_internal()
    );

    return ESP_OK;
}


size_t flash_store_slot_count(void)
{
    return slot_count_internal();
}


size_t flash_store_record_count(void)
{
    return scan_records(NULL, 0);
}


esp_err_t flash_store_reset(void)
{
    if (store_partition == NULL)
    {
        return ESP_ERR_INVALID_STATE;
    }

    ESP_LOGW(
        TAG,
        "Erasing complete QR history partition..."
    );

    esp_err_t err =
        esp_partition_erase_range(
            store_partition,
            0,
            store_partition->size
        );

    if (err == ESP_OK)
    {
        ESP_LOGW(
            TAG,
            "QR history partition erased"
        );
    }
    else
    {
        ESP_LOGE(
            TAG,
            "History erase failed: %s",
            esp_err_to_name(err)
        );
    }

    return err;
}


esp_err_t flash_store_append(
    const uint8_t *data,
    size_t length,
    flash_record_info_t *out_info)
{
    if (store_partition == NULL)
    {
        return ESP_ERR_INVALID_STATE;
    }

    if (
        length > FLASH_STORE_MAX_PAYLOAD ||
        (length > 0 && data == NULL)
    )
    {
        return ESP_ERR_INVALID_ARG;
    }

    const size_t slots =
        slot_count_internal();

    if (slots == 0)
    {
        return ESP_ERR_INVALID_SIZE;
    }

    flash_record_info_t *records =
        calloc(
            slots,
            sizeof(flash_record_info_t)
        );

    if (records == NULL)
    {
        return ESP_ERR_NO_MEM;
    }

    size_t count =
        scan_records(
            records,
            slots
        );

    if (count > slots)
    {
        count = slots;
    }

    if (count > 1)
    {
        qsort(
            records,
            count,
            sizeof(records[0]),
            compare_record_sequence
        );
    }

    uint32_t next_sequence = 1;
    uint16_t next_number = 1;
    uint16_t target_slot = 0;

    if (count > 0)
    {
        const flash_record_info_t *newest =
            &records[count - 1];

        next_sequence =
            newest->sequence + 1u;

        next_number =
            (newest->number == 9999u)
                ? 0u
                : (uint16_t)
                    (newest->number + 1u);

        target_slot =
            (uint16_t)(
                (newest->slot + 1u) %
                slots
            );
    }

    free(records);


    const size_t base =
        slot_offset(target_slot);


    esp_err_t err =
        esp_partition_erase_range(
            store_partition,
            base,
            RECORD_SLOT_SIZE
        );

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "erase slot %u failed: %s",
            target_slot,
            esp_err_to_name(err)
        );

        return err;
    }


    if (length > 0)
    {
        err =
            esp_partition_write(
                store_partition,
                base +
                    RECORD_PAYLOAD_OFFSET,
                data,
                length
            );

        if (err != ESP_OK)
        {
            ESP_LOGE(
                TAG,
                "payload write slot %u failed: %s",
                target_slot,
                esp_err_to_name(err)
            );

            return err;
        }
    }


    record_header_t header = {
        .magic =
            RECORD_MAGIC,

        .version =
            RECORD_VERSION,

        .header_size =
            sizeof(record_header_t),

        .sequence =
            next_sequence,

        .number =
            next_number,

        .payload_length =
            (uint16_t)length,

        .payload_crc32 =
            crc32_ieee(
                data,
                length
            ),

        .reserved0 =
            0xFFFFFFFFu,

        .reserved1 =
            0xFFFFFFFFu,

        .reserved2 =
            0xFFFFFFFFu
    };


    err =
        esp_partition_write(
            store_partition,
            base,
            &header,
            sizeof(header)
        );

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "header commit slot %u failed: %s",
            target_slot,
            esp_err_to_name(err)
        );

        return err;
    }


    if (out_info != NULL)
    {
        out_info->sequence =
            next_sequence;

        out_info->number =
            next_number;

        out_info->length =
            (uint16_t)length;

        out_info->slot =
            target_slot;
    }


    ESP_LOGI(
        TAG,
        "committed seq=%lu num=%04u len=%u slot=%u",
        (unsigned long)next_sequence,
        next_number,
        (unsigned)length,
        target_slot
    );

    return ESP_OK;
}


size_t flash_store_get_recent(
    uint32_t exclude_sequence,
    flash_record_info_t *out_records,
    size_t max_count)
{
    if (
        store_partition == NULL ||
        out_records == NULL ||
        max_count == 0
    )
    {
        return 0;
    }

    const size_t slots =
        slot_count_internal();

    flash_record_info_t *records =
        calloc(
            slots,
            sizeof(flash_record_info_t)
        );

    if (records == NULL)
    {
        return 0;
    }

    size_t count =
        scan_records(
            records,
            slots
        );

    if (count > slots)
    {
        count = slots;
    }

    if (count > 1)
    {
        qsort(
            records,
            count,
            sizeof(records[0]),
            compare_record_sequence
        );
    }


    size_t eligible = 0;

    for (size_t i = 0; i < count; ++i)
    {
        if (
            exclude_sequence != 0 &&
            records[i].sequence ==
                exclude_sequence
        )
        {
            continue;
        }

        records[eligible++] =
            records[i];
    }


    size_t take =
        (eligible < max_count)
            ? eligible
            : max_count;

    size_t start =
        eligible - take;

    for (size_t i = 0; i < take; ++i)
    {
        out_records[i] =
            records[start + i];
    }

    free(records);

    return take;
}


esp_err_t flash_store_read(
    const flash_record_info_t *info,
    uint8_t *buffer,
    size_t buffer_capacity,
    size_t *out_length)
{
    if (
        info == NULL ||
        buffer == NULL
    )
    {
        return ESP_ERR_INVALID_ARG;
    }

    record_header_t header;

    esp_err_t err =
        verify_info(
            info,
            &header
        );

    if (err != ESP_OK)
    {
        return err;
    }

    if (
        header.payload_length >
        buffer_capacity
    )
    {
        return ESP_ERR_INVALID_SIZE;
    }

    if (header.payload_length > 0)
    {
        err =
            esp_partition_read(
                store_partition,
                slot_offset(info->slot) +
                    RECORD_PAYLOAD_OFFSET,
                buffer,
                header.payload_length
            );

        if (err != ESP_OK)
        {
            return err;
        }
    }

    uint32_t crc =
        crc32_ieee(
            buffer,
            header.payload_length
        );

    if (crc != header.payload_crc32)
    {
        ESP_LOGE(
            TAG,
            "CRC mismatch seq=%lu slot=%u",
            (unsigned long)
                header.sequence,
            info->slot
        );

        return ESP_ERR_INVALID_CRC;
    }

    if (out_length != NULL)
    {
        *out_length =
            header.payload_length;
    }

    return ESP_OK;
}


esp_err_t flash_store_read_range(
    const flash_record_info_t *info,
    size_t payload_offset,
    uint8_t *buffer,
    size_t length)
{
    if (
        info == NULL ||
        (length > 0 && buffer == NULL)
    )
    {
        return ESP_ERR_INVALID_ARG;
    }

    record_header_t header;

    esp_err_t err =
        verify_info(
            info,
            &header
        );

    if (err != ESP_OK)
    {
        return err;
    }

    if (
        payload_offset >
            header.payload_length ||
        length >
            (
                (size_t)
                    header.payload_length -
                payload_offset
            )
    )
    {
        return ESP_ERR_INVALID_SIZE;
    }

    if (length == 0)
    {
        return ESP_OK;
    }

    return
        esp_partition_read(
            store_partition,
            slot_offset(info->slot) +
                RECORD_PAYLOAD_OFFSET +
                payload_offset,
            buffer,
            length
        );
}
