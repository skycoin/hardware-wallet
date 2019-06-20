.DEFAULT_GOAL := help
.PHONY: clean-lib clean
.PHONY: build-deps firmware-deps bootloader bootloader-mem-protect
.PHONY: check check-version check-trng check-protob test check-ver
.PHONY: firmware sign full-firmware-mem-protect full-firmware
.PHONY: emulator run-emulator st-flash oflash
.PHONY: bootloader-clean release-bootloader release-bootloader-mem-protect
.PHONY: firmware-clean release-firmware
.PHONY: release-combined release-combined-mem-protect

UNAME_S ?= $(shell uname -s)

PYTHON   ?= /usr/bin/python
PIP      ?= pip
PIPARGS  ?=

MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
MKFILE_DIR  := $(dir $(MKFILE_PATH))

FULL_FIRMWARE_PATH ?= releases/full-firmware-no-mem-protect.bin

VERSION_BOOTLOADER       =$(shell cat tiny-firmware/bootloader/VERSION | tr -d v)
VERSION_BOOTLOADER_MAJOR =$(shell echo $(VERSION_BOOTLOADER) | cut -d. -f1)
VERSION_BOOTLOADER_MINOR =$(shell echo $(VERSION_BOOTLOADER) | cut -d. -f2)
VERSION_BOOTLOADER_PATCH =$(shell echo $(VERSION_BOOTLOADER) | cut -d. -f3)
VERSION_FIRMWARE_RAW     =$(shell cat tiny-firmware/VERSION)
VERSION_FIRMWARE_MAJOR   =$(shell echo $(VERSION_FIRMWARE_RAW) | tr -d v | cut -d. -f1)
VERSION_FIRMWARE_MINOR   =$(shell echo $(VERSION_FIRMWARE_RAW) | cut -d. -f2)
VERSION_FIRMWARE_PATCH   =$(shell echo $(VERSION_FIRMWARE_RAW) | cut -d. -f3)
VERSION_FIRMWARE         =$(VERSION_FIRMWARE_MAJOR).$(VERSION_FIRMWARE_MINOR).$(VERSION_FIRMWARE_PATCH)
# https://semver.org/
VERSION_IS_SEMANTIC_COMPLIANT=0
ifeq ($(shell echo $(VERSION_FIRMWARE) | egrep '^[0-9]+\.[0-9]+\.[0-9]+$$'),) # empty result from egrep
	VERSION_FIRMWARE     =$(VERSION_FIRMWARE_RAW)
	ifeq ($(shell echo $(VERSION_FIRMWARE) | egrep '^[0-9]+\.[0-9]+\.[0-9]+$$'),) # empty result from egrep
		VERSION_IS_SEMANTIC_COMPLIANT=0
	else
		VERSION_IS_SEMANTIC_COMPLIANT=1
	endif
else
	VERSION_IS_SEMANTIC_COMPLIANT=1
endif
export VERSION_IS_SEMANTIC_COMPLIANT
export VERSION_FIRMWARE
ID_VENDOR=12602
ID_PRODUCT=1
#https://github.com/skycoin/skycoin-hardware-wallet/tree/55c50ceca0d5552ef4147eb2a26f8b12ee114749#supported-languages
LANG=1
COMBINED_VERSION=v$(VERSION_BOOTLOADER)-v$(VERSION_FIRMWARE)-$(ID_VENDOR)-$(ID_PRODUCT)-$(LANG)

ifeq ($(UNAME_S), Darwin)
	LD_VAR=DYLD_LIBRARY_PATH
else
	LD_VAR=LD_LIBRARY_PATH
endif
check-version: ## Check that the tiny-firmware/VERSION match the current tag
	@./ci-scripts/version.sh > tiny-firmware/VERSION
	@if [ $$VERSION_IS_SEMANTIC_COMPLIANT -eq 1 ]; then git diff --exit-code tiny-firmware/VERSION; fi
	@git checkout tiny-firmware/VERSION

install-linters-Darwin:
	brew install yamllint

install-linters-Linux:
	$(PIP) install $(PIPARGS) yamllint

install-linters: install-linters-$(UNAME_S) ## Install code quality checking tools

lint: ## Check code quality
	yamllint -d relaxed .travis.yml

clean-lib: ## Delete all files generated by tiny-firmware library dependencies
	make -C tiny-firmware/vendor/libopencm3/ clean

clean: ## Delete all files generated by build
	make -C skycoin-api/ clean
	make -C tiny-firmware/bootloader/ clean
	make -C tiny-firmware/ clean
	make -C tiny-firmware/emulator/ clean
	make -C tiny-firmware/protob/ clean-c
	rm -f emulator.img
	rm -f emulator
	rm -f tiny-firmware/bootloader/combine/bl.bin
	rm -f tiny-firmware/bootloader/combine/fw.bin
	rm -f tiny-firmware/bootloader/combine/combined.bin
	rm -f tiny-firmware/bootloader/libskycoin-crypto.so
	rm -f bootloader-memory-protected.bin
	rm -f skybootloader-no-memory-protect.bin
	rm -f full-firmware-no-mem-protect.bin
	rm -f full-firmware-memory-protected.bin
	# FIXME: Remove .d files
	rm -f $$(find . -type f -name '*.d')
	make -C trng-test clean

build-deps: ## Build common dependencies (protob)
	make -C tiny-firmware/protob/ build-c

firmware-deps: build-deps ## Build firmware dependencies
	make -C tiny-firmware/vendor/libopencm3/

generate-bitmaps:
	( cd tiny-firmware/gen/bitmaps/ && python2 generate.py )

bootloader: firmware-deps ## Build bootloader (RDP level 0)
	rm -f tiny-firmware/memory.o tiny-firmware/gen/bitmaps.o # Force rebuild of these two files
	MEMORY_PROTECT=0 SIGNATURE_PROTECT=1 REVERSE_BUTTONS=1 VERSION_MAJOR=$(VERSION_BOOTLOADER_MAJOR) VERSION_MINOR=$(VERSION_BOOTLOADER_MINOR) VERSION_PATCH=$(VERSION_BOOTLOADER_PATCH) make -C tiny-firmware/bootloader/ align
	mv tiny-firmware/bootloader/bootloader.bin skybootloader-no-memory-protect.bin

bootloader-mem-protect: firmware-deps ## Build bootloader (RDP level 2)
	rm -f tiny-firmware/memory.o tiny-firmware/gen/bitmaps.o # Force rebuild of these two files
	MEMORY_PROTECT=1 SIGNATURE_PROTECT=1 REVERSE_BUTTONS=1 VERSION_MAJOR=$(VERSION_BOOTLOADER_MAJOR) VERSION_MINOR=$(VERSION_BOOTLOADER_MINOR) VERSION_PATCH=$(VERSION_BOOTLOADER_PATCH) make -C tiny-firmware/bootloader/ align
	mv tiny-firmware/bootloader/bootloader.bin bootloader-memory-protected.bin

firmware: tiny-firmware/skyfirmware.bin ## Build skycoin wallet firmware

build-libc: tiny-firmware/bootloader/libskycoin-crypto.so ## Build the Skycoin cipher library for firmware

bootloader-clean:
	make -C tiny-firmware/bootloader/ clean

firmware-clean:
	make -C tiny-firmware/ clean

release-emulator: clean emulator ## Build emulator in release mode.
	cp emulator releases/emulator-$(UNAME_S)-v$(VERSION_FIRMWARE)

release-bootloader: ## Build bootloader in release mode.
	if [ -z "$(shell echo $(VERSION_BOOTLOADER) | egrep '^[0-9]+\.[0-9]+\.[0-9]+$$' )" ]; then echo "Wrong bootloader version format"; exit 1; fi
	DEBUG=0 VERSION_MAJOR=$(VERSION_BOOTLOADER_MAJOR) VERSION_MINOR=$(VERSION_BOOTLOADER_MINOR) VERSION_PATCH=$(VERSION_BOOTLOADER_PATCH) make bootloader
	mv skybootloader-no-memory-protect.bin releases/skywallet-bootloader-no-memory-protect-v$(VERSION_BOOTLOADER).bin

release-bootloader-mem-protect: ## Build bootloader(with memory protect enbled, make sure you know what you are doing).
	if [ -z "$(shell echo $(VERSION_BOOTLOADER) | egrep '^[0-9]+\.[0-9]+\.[0-9]+$$' )" ]; then echo "Wrong bootloader version format"; exit 1; fi
	DEBUG=0 VERSION_MAJOR=$(VERSION_BOOTLOADER_MAJOR) VERSION_MINOR=$(VERSION_BOOTLOADER_MINOR) VERSION_PATCH=$(VERSION_BOOTLOADER_PATCH) make bootloader-mem-protect
	mv bootloader-memory-protected.bin releases/skywallet-bootloader-mem-protect-v$(VERSION_BOOTLOADER).bin

release-firmware: check-version ## Build firmware in release mode.
	DEBUG=0 VERSION_MAJOR=$(VERSION_FIRMWARE_MAJOR) VERSION_MINOR=$(VERSION_FIRMWARE_MINOR) VERSION_PATCH=$(VERSION_FIRMWARE_PATCH) make firmware
	mv tiny-firmware/skyfirmware.bin releases/skywallet-firmware-v$(VERSION_FIRMWARE).bin

release-combined: release-bootloader release-firmware ## Build bootloader and firmware together in a combined file in released mode.
	cp releases/skywallet-bootloader-no-memory-protect-v$(VERSION_BOOTLOADER).bin tiny-firmware/bootloader/combine/bl.bin
	cp releases/skywallet-firmware-v$(VERSION_FIRMWARE).bin tiny-firmware/bootloader/combine/fw.bin
	cd tiny-firmware/bootloader/combine/ ; $(PYTHON) prepare.py
	mv tiny-firmware/bootloader/combine/combined.bin releases/skywallet-full-no-mem-protect-$(COMBINED_VERSION).bin

release-combined-mem-protect: release-bootloader-mem-protect release-firmware ## Build bootloader(with memory protect enbled, make sure you know what you are doing) and firmware together in a combined file in released mode.
	cp releases/skywallet-bootloader-mem-protect-v$(VERSION_BOOTLOADER).bin tiny-firmware/bootloader/combine/bl.bin
	cp releases/skywallet-firmware-v$(VERSION_FIRMWARE).bin tiny-firmware/bootloader/combine/fw.bin
	cd tiny-firmware/bootloader/combine/ ; $(PYTHON) prepare.py
	mv tiny-firmware/bootloader/combine/combined.bin releases/skywallet-full-mem-protect-$(COMBINED_VERSION).bin

release: release-combined release-combined-mem-protect release-emulator ## Create a release for production
	@cp tiny-firmware/VERSION releases/version.txt

release-sign: release # Create detached signatures for all the generated files for release
	gpg --armor --detach-sign releases/skywallet-firmware-v$(VERSION_FIRMWARE).bin
	gpg --armor --detach-sign releases/skywallet-full-no-mem-protect-$(COMBINED_VERSION).bin
	gpg --armor --detach-sign releases/skywallet-full-mem-protect-$(COMBINED_VERSION).bin
	gpg --armor --detach-sign releases/emulator-$(UNAME_S)-v$(VERSION_FIRMWARE)

tiny-firmware/bootloader/libskycoin-crypto.so:
	make -C skycoin-api clean
	make -C skycoin-api libskycoin-crypto.so
	cp skycoin-api/libskycoin-crypto.so tiny-firmware/bootloader/
	make -C skycoin-api clean

tiny-firmware/skyfirmware.bin: firmware-deps
	rm -f tiny-firmware/memory.o tiny-firmware/gen/bitmaps.o # Force rebuild of these two files
	REVERSE_BUTTONS=1 VERSION_MAJOR=$(VERSION_FIRMWARE_MAJOR) VERSION_MINOR=$(VERSION_FIRMWARE_MINOR) VERSION_PATCH=$(VERSION_FIRMWARE_PATCH) make -C tiny-firmware/ sign-firmware

sign: sign-firmware sign-bootloader-no-mem-protect ## Sign firmware and non mem protect bootloader

sign-firmware: tiny-firmware/bootloader/libskycoin-crypto.so tiny-firmware/skyfirmware.bin ## Sign skycoin wallet firmware
	tiny-firmware/bootloader/firmware_sign.py -s -f tiny-firmware/skyfirmware.bin

sign-bootloader-mem-protect: tiny-firmware/bootloader/libskycoin-crypto.so tiny-firmware/skyfirmware.bin ## Sign mem protect bootloader
	tiny-firmware/bootloader/firmware_sign.py -s -f bootloader-memory-protected.bin

sign-bootloader-no-mem-protect: tiny-firmware/bootloader/libskycoin-crypto.so tiny-firmware/skyfirmware.bin ## Sign non mem protect bootloader
	tiny-firmware/bootloader/firmware_sign.py -s -f skybootloader-no-memory-protect.bin

full-firmware-mem-protect: bootloader-mem-protect firmware ## Build full firmware (RDP level 2)
	cp bootloader-memory-protected.bin tiny-firmware/bootloader/combine/bl.bin
	cp tiny-firmware/skyfirmware.bin tiny-firmware/bootloader/combine/fw.bin
	cd tiny-firmware/bootloader/combine/ ; $(PYTHON) prepare.py
	mv tiny-firmware/bootloader/combine/combined.bin releases/full-firmware-memory-protected.bin

full-firmware: bootloader firmware ## Build full firmware (RDP level 0)
	cp skybootloader-no-memory-protect.bin tiny-firmware/bootloader/combine/bl.bin
	cp tiny-firmware/skyfirmware.bin tiny-firmware/bootloader/combine/fw.bin
	cd tiny-firmware/bootloader/combine/ ; $(PYTHON) prepare.py
	mv tiny-firmware/bootloader/combine/combined.bin releases/full-firmware-no-mem-protect.bin

emulator: build-deps ## Build emulator
	EMULATOR=1 VERSION_MAJOR=$(VERSION_FIRMWARE_MAJOR) VERSION_MINOR=$(VERSION_FIRMWARE_MINOR) VERSION_PATCH=$(VERSION_FIRMWARE_PATCH) make -C tiny-firmware/emulator/
	EMULATOR=1 VERSION_MAJOR=$(VERSION_FIRMWARE_MAJOR) VERSION_MINOR=$(VERSION_FIRMWARE_MINOR) VERSION_PATCH=$(VERSION_FIRMWARE_PATCH) make -C tiny-firmware/
	mv tiny-firmware/skycoin-emulator emulator

run-emulator: emulator ## Run wallet emulator
	./emulator

test: ## Run all project test suites.
	export LIBRARY_PATH="$(MKFILE_DIR)/skycoin-api/:$$LIBRARY_PATH"
	export $(LD_VAR)="$(MKFILE_DIR)/skycoin-api/:$$$(LD_VAR)"
	PYTHON=$(PYTHON) make -C skycoin-api/ test
	VERSION_MAJOR=$(VERSION_FIRMWARE_MAJOR) VERSION_MINOR=$(VERSION_FIRMWARE_MINOR) VERSION_PATCH=$(VERSION_FIRMWARE_PATCH) make emulator
	EMULATOR=1 VERSION_MAJOR=$(VERSION_FIRMWARE_MAJOR) VERSION_MINOR=$(VERSION_FIRMWARE_MINOR) VERSION_PATCH=$(VERSION_FIRMWARE_PATCH) make -C tiny-firmware/ test

st-flash: ## Deploy (flash) firmware on physical wallet
	st-flash write $(FULL_FIRMWARE_PATH) 0x08000000

oflash: full-firmware
	openocd -f openocd.cfg

check-ver:
	echo "Bootloader : $(VERSION_BOOTLOADER_MAJOR).$(VERSION_BOOTLOADER_MINOR).$(VERSION_BOOTLOADER_PATCH)"
	echo "Firmware   : $(VERSION_FIRMWARE_MAJOR).$(VERSION_FIRMWARE_MINOR).$(VERSION_FIRMWARE_PATCH)"

check-trng: ## Run test tools over random buffers
	make -C trng-test trng-generate-buffers
	make -C trng-test run-tests

check-protob: ## verify protob submodule hash
	./ci-scripts/verify_protob_hash.sh

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
