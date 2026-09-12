SHELL := /bin/bash

# Project root must be defined before any immediate (:=) path expansion.
PROJECT_DIR := $(CURDIR)

# Reproducible ESP-IDF build toolchain.
IDF_IMAGE ?= espressif/idf:v5.5.5
IDF_TARGET ?= esp32s3

# Native single-binary flasher.
ESPFLASH_VERSION ?= 4.5.0
ESPFLASH_FETCH_IMAGE ?= alpine:3.22
FLASH_TOOL := $(PROJECT_DIR)/.tools/bin/espflash
FLASH_BAUD ?= 460800
MERGED_BIN := $(PROJECT_DIR)/build/qrtransfer-merged.bin
APP_BIN := $(PROJECT_DIR)/build/qrtransfer_msc.bin
BUILD_INPUT_HASH := $(PROJECT_DIR)/build/.qrtransfer-input.sha256

# Preferred:
#   make flash PORT=/dev/ttyACM0
#
# Positional Linux form:
#   make flash /dev/ttyACM0
SERIAL_GOAL := $(firstword $(filter /dev/%,$(MAKECMDGOALS)))
PORT ?= $(SERIAL_GOAL)

DOCKER = docker

DOCKER_BUILD = $(DOCKER) run --rm -t \
	-e HOME=/tmp/idf-home \
	-e IDF_TARGET="$(IDF_TARGET)" \
	-v "$(PROJECT_DIR):/project" \
	-w /project \
	$(IDF_IMAGE)

DOCKER_BUILD_INTERACTIVE = $(DOCKER) run --rm -it \
	-e HOME=/tmp/idf-home \
	-e IDF_TARGET="$(IDF_TARGET)" \
	-v "$(PROJECT_DIR):/project" \
	-w /project \
	$(IDF_IMAGE)

.PHONY: help doctor image build config-check clean fullclean reset-config reconfigure menuconfig size shell \
	flash-tool flash-tool-clean flash erase-flash

help:
	@printf '%s\n' \
	  'QR Transfer portable ESP-IDF environment' \
	  '' \
	  'Firmware build:' \
	  '  make build' \
	  '  make config-check' \
	  '    rootless Docker + espressif/idf:v5.5.5' \
	  '    also creates build/qrtransfer-merged.bin' \
	  '' \
	  'Flash helper:' \
	  '  make flash-tool' \
	  '    rootless Docker downloads official espflash v$(ESPFLASH_VERSION)' \
	  '    into .tools/bin/espflash' \
	  '' \
	  'Flash:' \
	  '  make flash PORT=/dev/ttyACM0' \
	  '  make flash /dev/ttyACM0' \
	  '    host runs espflash with sudo; Docker is not used while flashing' \
	  '' \
	  'Host requirements:' \
	  '  Linux + GNU Make + rootless Docker + sudo' \
	  '  No host ESP-IDF, Python, Rust, Cargo, esptool, or espflash install.' \
	  '' \
	  'Other:' \
	  '  make doctor' \
	  '  make image' \
	  '  make clean' \
	  '  make fullclean' \
	  '  make reset-config   # remove stale sdkconfig/build and reapply defaults' \
	  '  make reconfigure' \
	  '  make menuconfig' \
	  '  make size' \
	  '  make erase-flash PORT=/dev/ttyACM0' \
	  '  make flash-tool-clean' \
	  '  make shell'

doctor:
	@command -v docker >/dev/null || { echo 'ERROR: docker not found.' >&2; exit 1; }
	@command -v sudo >/dev/null || { echo 'ERROR: sudo not found.' >&2; exit 1; }
	@$(DOCKER) version >/dev/null 2>&1 || { \
		echo 'ERROR: rootless Docker daemon is unavailable.' >&2; exit 1; \
	}
	@$(DOCKER) info --format '{{json .SecurityOptions}}' 2>/dev/null | grep -qi rootless || { \
		echo 'ERROR: active Docker daemon does not report rootless mode.' >&2; \
		exit 1; \
	}
	@case "$$(uname -m)" in \
		x86_64|amd64|aarch64|arm64) ;; \
		*) echo "ERROR: unsupported host architecture: $$(uname -m)" >&2; exit 1 ;; \
	esac
	@echo 'Rootless Docker:       OK'
	@echo 'ESP-IDF image:         $(IDF_IMAGE)'
	@echo 'ESP-IDF target:        $(IDF_TARGET)'
	@echo 'espflash:              v$(ESPFLASH_VERSION)'
	@echo 'Host architecture:     '$$(uname -m)

image:
	$(DOCKER) pull $(IDF_IMAGE)
	$(DOCKER) pull $(ESPFLASH_FETCH_IMAGE)

# Build firmware and ask ESP-IDF itself to merge bootloader, partition table,
# application and any other required flash images into one raw image at offset 0.
#
# A stale sdkconfig from an older/default ESP-IDF configuration must not silently
# override sdkconfig.defaults. Validate the two product-critical settings both
# before and after the build.
build:
	@echo 'SOURCE_VARIANT: qrtransfer_v2_4_6_clean_docs_fix8'
	@awk '\
		/^static void scanner_status_read_string\(/ { in_fn=1; next } \
		in_fn && /^static / { exit } \
		in_fn && (/flash_store_raw_begin/ || /result->status/ || /return raw_begin_err/) { \
			print "ERROR: stale RAW-begin block detected inside scanner_status_read_string(): " NR ":" $$0 > "/dev/stderr"; \
			bad=1 \
		} \
		END { exit bad ? 42 : 0 }' main/analyzer.c || { \
		echo 'ERROR: This is not the FIX3 analyzer.c. Re-extract FIX3 and run make from that directory.' >&2; \
		exit 2; \
	}
	@if [ -f "$(PROJECT_DIR)/sdkconfig" ]; then \
		grep -q '^CONFIG_PARTITION_TABLE_CUSTOM=y$$' "$(PROJECT_DIR)/sdkconfig" || { \
			echo 'ERROR: existing sdkconfig does not enable the QR Transfer custom partition table.' >&2; \
			echo 'Run: make reset-config' >&2; \
			exit 2; \
		}; \
		grep -q '^CONFIG_ESPTOOLPY_FLASHSIZE_8MB=y$$' "$(PROJECT_DIR)/sdkconfig" || { \
			echo 'ERROR: existing sdkconfig is not configured for the AtomS3 Lite 8 MB flash.' >&2; \
			echo 'Run: make reset-config' >&2; \
			exit 2; \
		}; \
		grep -q '^CONFIG_TINYUSB_MSC_ENABLED=y$$' "$(PROJECT_DIR)/sdkconfig" || { \
			echo 'ERROR: existing sdkconfig does not enable TinyUSB MSC.' >&2; \
			echo 'Run: make reset-config' >&2; \
			exit 2; \
		}; \
	fi
	rm -f "$(MERGED_BIN)"
	$(DOCKER_BUILD) bash -lc '\
		set -euo pipefail; \
		mkdir -p build; \
		NEW_HASH="$$( \
			{ \
				find main -type f \( \
					-name "*.c" -o -name "*.cc" -o -name "*.cpp" -o \
					-name "*.h" -o -name "*.hpp" -o \
					-name "CMakeLists.txt" -o -name "idf_component.yml" \
				\) -print0 \
				| sort -z \
				| xargs -0 sha256sum; \
				sha256sum CMakeLists.txt sdkconfig.defaults partitions.csv; \
			} \
			| sha256sum \
			| cut -d" " -f1 \
		)"; \
		OLD_HASH="$$(cat build/.qrtransfer-input.sha256 2>/dev/null || true)"; \
		if [ "$$NEW_HASH" != "$$OLD_HASH" ]; then \
			echo "Build inputs changed: forcing main-component timestamp refresh + CMake reconfigure"; \
			find main -type f \( \
				-name "*.c" -o -name "*.cc" -o -name "*.cpp" -o \
				-name "*.h" -o -name "*.hpp" \
			\) -exec touch {} +; \
			touch CMakeLists.txt main/CMakeLists.txt main/idf_component.yml sdkconfig.defaults partitions.csv; \
			idf.py reconfigure; \
		else \
			echo "Build inputs unchanged: normal Ninja incremental build"; \
		fi; \
		idf.py merge-bin -f raw -o qrtransfer-merged.bin; \
		printf "%s\n" "$$NEW_HASH" > build/.qrtransfer-input.sha256; \
	'
	@grep -q '^CONFIG_PARTITION_TABLE_CUSTOM=y$$' "$(PROJECT_DIR)/sdkconfig" || { \
		echo 'ERROR: generated sdkconfig is not using partitions.csv.' >&2; exit 2; \
	}
	@grep -q '^CONFIG_ESPTOOLPY_FLASHSIZE_8MB=y$$' "$(PROJECT_DIR)/sdkconfig" || { \
		echo 'ERROR: generated sdkconfig is not configured for 8 MB flash.' >&2; exit 2; \
	}
	@grep -q '^CONFIG_TINYUSB_MSC_ENABLED=y$$' "$(PROJECT_DIR)/sdkconfig" || { \
		echo 'ERROR: generated sdkconfig does not enable TinyUSB MSC.' >&2; exit 2; \
	}
	@test -f "$(MERGED_BIN)" || { \
		echo 'ERROR: ESP-IDF did not generate build/qrtransfer-merged.bin.' >&2; \
		exit 2; \
	}
	@echo 'Verified: custom partitions.csv + 8 MB flash + TinyUSB MSC.'
	@echo 'Application image: $(APP_BIN)'
	@ls -l "$(APP_BIN)"
	@sha256sum "$(APP_BIN)" 2>/dev/null || true
	@echo 'Merged image: $(MERGED_BIN)'
	@ls -l "$(MERGED_BIN)"
	@sha256sum "$(MERGED_BIN)" 2>/dev/null || true
	@echo 'Build input hash:'
	@cat "$(BUILD_INPUT_HASH)"

config-check:
	@test -f "$(PROJECT_DIR)/sdkconfig" || { \
		echo 'ERROR: sdkconfig does not exist. Run make build first.' >&2; exit 2; \
	}
	@grep -q '^CONFIG_IDF_TARGET="esp32s3"$$' "$(PROJECT_DIR)/sdkconfig" || { \
		echo 'ERROR: target is not esp32s3.' >&2; exit 2; \
	}
	@grep -q '^CONFIG_PARTITION_TABLE_CUSTOM=y$$' "$(PROJECT_DIR)/sdkconfig" || { \
		echo 'ERROR: custom partition table is disabled.' >&2; exit 2; \
	}
	@grep -q '^CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions.csv"$$' "$(PROJECT_DIR)/sdkconfig" || { \
		echo 'ERROR: custom partition filename is not partitions.csv.' >&2; exit 2; \
	}
	@grep -q '^CONFIG_ESPTOOLPY_FLASHSIZE_8MB=y$$' "$(PROJECT_DIR)/sdkconfig" || { \
		echo 'ERROR: flash size is not configured as 8 MB.' >&2; exit 2; \
	}
	@grep -q '^CONFIG_TINYUSB_MSC_ENABLED=y$$' "$(PROJECT_DIR)/sdkconfig" || { \
		echo 'ERROR: TinyUSB MSC is disabled.' >&2; exit 2; \
	}
	@grep -q '^CONFIG_TINYUSB_MSC_BUFSIZE=512$$' "$(PROJECT_DIR)/sdkconfig" || { \
		echo 'ERROR: TinyUSB MSC buffer size is not 512.' >&2; exit 2; \
	}
	@echo 'sdkconfig audit: OK (ESP32-S3 / 8 MB / custom partitions / MSC 512).'

clean:
	$(DOCKER_BUILD) idf.py clean

fullclean:
	$(DOCKER_BUILD) idf.py fullclean

# Remove generated project configuration so sdkconfig.defaults is applied from
# scratch on the next build. This is intentionally explicit/destructive.
reset-config:
	rm -f "$(PROJECT_DIR)/sdkconfig" "$(PROJECT_DIR)/sdkconfig.old"
	rm -rf "$(PROJECT_DIR)/build"
	@echo 'Removed sdkconfig and build/. Next make build will reapply sdkconfig.defaults.'

reconfigure:
	$(DOCKER_BUILD) idf.py reconfigure

menuconfig:
	$(DOCKER_BUILD_INTERACTIVE) idf.py menuconfig

size:
	$(DOCKER_BUILD) idf.py size

shell:
	$(DOCKER_BUILD_INTERACTIVE) bash

# Fetch the official prebuilt espflash release inside rootless Docker, so the
# host does not need curl/wget/unzip/Rust/Cargo.
#
# x86_64 uses the MUSL release for maximum Linux portability.
# aarch64 uses the official GNU/Linux release (v4.5.0 has no aarch64-musl asset).
flash-tool:
	@mkdir -p "$(PROJECT_DIR)/.tools/bin"
	$(DOCKER) run --rm \
		-e ESPFLASH_VERSION="$(ESPFLASH_VERSION)" \
		-v "$(PROJECT_DIR)/.tools/bin:/out" \
		$(ESPFLASH_FETCH_IMAGE) \
		sh -euxc '\
			apk add --no-cache wget unzip; \
			case "$$(uname -m)" in \
				x86_64|amd64) ASSET="espflash-x86_64-unknown-linux-musl.zip" ;; \
				aarch64|arm64) ASSET="espflash-aarch64-unknown-linux-gnu.zip" ;; \
				*) echo "unsupported architecture: $$(uname -m)" >&2; exit 2 ;; \
			esac; \
			URL="https://github.com/esp-rs/espflash/releases/download/v$${ESPFLASH_VERSION}/$${ASSET}"; \
			echo "Fetching $${URL}"; \
			wget -O /tmp/espflash.zip "$${URL}"; \
			rm -rf /tmp/espflash-unpack; mkdir -p /tmp/espflash-unpack; \
			unzip -q /tmp/espflash.zip -d /tmp/espflash-unpack; \
			BIN="$$(find /tmp/espflash-unpack -type f -name espflash | head -n1)"; \
			test -n "$${BIN}"; \
			cp "$${BIN}" /out/espflash; \
			chmod 0755 /out/espflash; \
		'
	@test -x "$(FLASH_TOOL)" || { \
		echo 'ERROR: espflash executable was not produced.' >&2; exit 2; \
	}
	@"$(FLASH_TOOL)" --version | grep -F "$(ESPFLASH_VERSION)" >/dev/null || { \
		echo 'ERROR: downloaded espflash version does not match $(ESPFLASH_VERSION).' >&2; \
		"$(FLASH_TOOL)" --version >&2 || true; \
		exit 2; \
	}
	@echo "Installed: $$("$(FLASH_TOOL)" --version)"

flash-tool-clean:
	rm -f "$(FLASH_TOOL)"

define CHECK_PORT
	@if [ -z "$(PORT)" ]; then \
		echo 'ERROR: serial port is required.' >&2; \
		echo 'Example: make flash PORT=/dev/ttyACM0' >&2; \
		echo '     or: make flash /dev/ttyACM0' >&2; \
		exit 2; \
	fi
	@if [ ! -e "$(PORT)" ]; then \
		echo "ERROR: serial device does not exist: $(PORT)" >&2; \
		exit 2; \
	fi
endef

define ENSURE_BUILD
	@if [ ! -f "$(MERGED_BIN)" ]; then \
		echo 'ERROR: build/qrtransfer-merged.bin not found.' >&2; \
		echo 'Run `make build` successfully first.' >&2; \
		exit 2; \
	fi
endef

define ENSURE_FLASH_TOOL
	@if [ ! -x "$(FLASH_TOOL)" ]; then \
		echo 'espflash is not present; fetching it with rootless Docker...' >&2; \
		$(MAKE) --no-print-directory flash-tool; \
	fi
endef

# Physical device access happens on the host, with sudo.
# No Docker daemon or Python runtime participates in the actual flash.
flash:
	$(CHECK_PORT)
	$(ENSURE_BUILD)
	$(ENSURE_FLASH_TOOL)
	sudo "$(FLASH_TOOL)" --skip-update-check \
		write-bin \
		--chip esp32s3 \
		--port "$(PORT)" \
		--baud "$(FLASH_BAUD)" \
		0x0 "$(MERGED_BIN)"

/dev/%:
	@:

erase-flash:
	$(CHECK_PORT)
	$(ENSURE_FLASH_TOOL)
	sudo "$(FLASH_TOOL)" --skip-update-check \
		erase-flash \
		--chip esp32s3 \
		--port "$(PORT)"
