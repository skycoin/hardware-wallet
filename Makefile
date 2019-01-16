clean-lib:
	make -C tiny-firmware/vendor/libopencm3/ clean

clean:
	make -C skycoin-api/ clean
	make -C tiny-firmware/bootloader/ clean
	make -C tiny-firmware/ clean
	make -C tiny-firmware/emulator/ clean
	make -C tiny-firmware/protob/ clean
	rm -f emulator.img emulator
	rm -f tiny-firmware/bootloader/combine/bl.bin
	rm -f tiny-firmware/bootloader/combine/fw.bin
	rm -f tiny-firmware/bootloader/combine/combined.bin
	rm -f tiny-firmware/bootloader/libskycoin-crypto.so
	rm -f bootloader-memory-protected.bin  bootloader-no-memory-protect.bin  full-firmware-no-mem-protect.bin full-firmware-memory-protected.bin

build-deps:
	make -C tiny-firmware/vendor/nanopb/generator/proto/
	make -C tiny-firmware/protob/

firmware-deps: build-deps
	make -C tiny-firmware/vendor/libopencm3/

bootloader: firmware-deps
	rm -f tiny-firmware/memory.o tiny-firmware/gen/bitmaps.o # Force rebuild of these two files
	SIGNATURE_PROTECT=1 REVERSE_BUTTONS=1 make -C tiny-firmware/bootloader/ align
	mv tiny-firmware/bootloader/bootloader.bin bootloader-no-memory-protect.bin

bootloader-mem-protect: firmware-deps
	rm -f tiny-firmware/memory.o tiny-firmware/gen/bitmaps.o # Force rebuild of these two files
	MEMORY_PROTECT=1 SIGNATURE_PROTECT=1 REVERSE_BUTTONS=1 make -C tiny-firmware/bootloader/ align
	mv tiny-firmware/bootloader/bootloader.bin bootloader-memory-protected.bin

bootloader-clean:
	make -C tiny-firmware/bootloader/ clean

bootloader-release:
	if [ -z $$( echo $(bootloader_version) | egrep "^[0-9]+\.[0-9]+\.[0-9]+$$" ) ]; then echo "Wrong firmware version format"; exit 1; fi
	FIRMWARE_MAJOR=$$(echo $(bootloader_version) | awk -F '.' '{ print $$1 }'); \
	FIRMWARE_MINOR=$$(echo $(bootloader_version) | awk -F '.' '{ print $$2 }'); \
	FIRMWARE_PATCH=$$(echo $(bootloader_version) | awk -F '.' '{ print $$3 }'); \
	VERSION_MAJOR=$$FIRMWARE_MAJOR VERSION_MINOR=$$FIRMWARE_MINOR VERSION_PATCH=$$FIRMWARE_PATCH make -C . bootloader ; \
	mv bootloader-no-memory-protect.bin bootloader-$$FIRMWARE_MAJOR.$$FIRMWARE_MINOR.$$FIRMWARE_PATCH-no-memory-protect.bin

bootloader-release-mem-protect:
	if [ -z $$( echo $(bootloader_version) | egrep "^[0-9]+\.[0-9]+\.[0-9]+$$" ) ]; then echo "Wrong firmware version format"; exit 1; fi
	BOOTLOADER_MAJOR=$$(echo $(bootloader_version) | awk -F '.' '{ print $$1 }'); \
	BOOTLOADER_MINOR=$$(echo $(bootloader_version) | awk -F '.' '{ print $$2 }'); \
	BOOTLOADER_PATCH=$$(echo $(bootloader_version) | awk -F '.' '{ print $$3 }'); \
	VERSION_MAJOR=$$BOOTLOADER_MAJOR VERSION_MINOR=$$BOOTLOADER_MINOR VERSION_PATCH=$$BOOTLOADER_PATCH make -C . bootloader-mem-protect ; \
	mv bootloader-memory-protected.bin bootloader-$$BOOTLOADER_MAJOR.$$BOOTLOADER_MINOR.$$BOOTLOADER_PATCH-mem-protect.bin

firmware: firmware-deps
	rm -f tiny-firmware/memory.o tiny-firmware/gen/bitmaps.o # Force rebuild of these two files
	REVERSE_BUTTONS=1 make -C tiny-firmware/ sign

firmware-clean:
	make -C tiny-firmware/ clean

firmware-release:
	if [ -z $$( echo $(firmware_version) | egrep "^[0-9]+\.[0-9]+\.[0-9]+$$" ) ]; then echo "Wrong firmware version format"; exit 1; fi
	FIRMWARE_MAJOR=$$(echo $(firmware_version) | awk -F '.' '{ print $$1 }'); \
	FIRMWARE_MINOR=$$(echo $(firmware_version) | awk -F '.' '{ print $$2 }'); \
	FIRMWARE_PATCH=$$(echo $(firmware_version) | awk -F '.' '{ print $$3 }'); \
	VERSION_MAJOR=$$FIRMWARE_MAJOR VERSION_MINOR=$$FIRMWARE_MINOR VERSION_PATCH=$$FIRMWARE_PATCH make -C . firmware ; \
	mv tiny-firmware/skycoin.bin skycoin-$$FIRMWARE_MAJOR.$$FIRMWARE_MINOR.$$FIRMWARE_PATCH.bin

combined-release:
	if [ -z $$( echo $(bootloader_version) | egrep "^[0-9]+\.[0-9]+\.[0-9]+$$" ) ]; then echo "Wrong firmware version format"; exit 1; fi ; \
	BOOTLOADER_MAJOR=$$(echo $(bootloader_version) | awk -F '.' '{ print $$1 }'); \
	BOOTLOADER_MINOR=$$(echo $(bootloader_version) | awk -F '.' '{ print $$2 }'); \
	BOOTLOADER_PATCH=$$(echo $(bootloader_version) | awk -F '.' '{ print $$3 }'); \
	make bootloader-release bootloader_version=$$BOOTLOADER_MAJOR.$$BOOTLOADER_MINOR.$$BOOTLOADER_PATCH ; \
	cp bootloader-$$BOOTLOADER_MAJOR.$$BOOTLOADER_MINOR.$$BOOTLOADER_PATCH-no-memory-protect.bin tiny-firmware/bootloader/combine/bl.bin
	if [ -z $$( echo $(firmware_version) | egrep "^[0-9]+\.[0-9]+\.[0-9]+$$" ) ]; then echo "Wrong firmware version format"; exit 1; fi ; \
	FIRMWARE_MAJOR=$$(echo $(firmware_version) | awk -F '.' '{ print $$1 }'); \
	FIRMWARE_MINOR=$$(echo $(firmware_version) | awk -F '.' '{ print $$2 }'); \
	FIRMWARE_PATCH=$$(echo $(firmware_version) | awk -F '.' '{ print $$3 }'); \
	make firmware-release firmware_version=$$FIRMWARE_MAJOR.$$FIRMWARE_MINOR.$$FIRMWARE_PATCH; \
	cp skycoin-$$FIRMWARE_MAJOR.$$FIRMWARE_MINOR.$$FIRMWARE_PATCH.bin tiny-firmware/bootloader/combine/fw.bin
	cd tiny-firmware/bootloader/combine/ ; /usr/bin/python prepare.py
	BOOTLOADER_MAJOR=$$(echo $(bootloader_version) | awk -F '.' '{ print $$1 }'); \
	BOOTLOADER_MINOR=$$(echo $(bootloader_version) | awk -F '.' '{ print $$2 }'); \
	BOOTLOADER_PATCH=$$(echo $(bootloader_version) | awk -F '.' '{ print $$3 }'); \
	FIRMWARE_MAJOR=$$(echo $(firmware_version) | awk -F '.' '{ print $$1 }'); \
	FIRMWARE_MINOR=$$(echo $(firmware_version) | awk -F '.' '{ print $$2 }'); \
	FIRMWARE_PATCH=$$(echo $(firmware_version) | awk -F '.' '{ print $$3 }'); \
	mv tiny-firmware/bootloader/combine/combined.bin bootloader-$$BOOTLOADER_MAJOR.$$BOOTLOADER_MINOR.$$BOOTLOADER_PATCH-firmware-$$FIRMWARE_MAJOR.$$FIRMWARE_MINOR.$$FIRMWARE_PATCH-no-memory-protect.bin

tiny-firmware/bootloader/libskycoin-crypto.so:
	make -C skycoin-api clean
	make -C skycoin-api libskycoin-crypto.so
	cp skycoin-api/libskycoin-crypto.so tiny-firmware/bootloader/
	make -C skycoin-api clean

tiny-firmware/skycoin.bin:
	make firmware

sign: tiny-firmware/bootloader/libskycoin-crypto.so tiny-firmware/skycoin.bin
	tiny-firmware/bootloader/firmware_sign.py -s -f tiny-firmware/skycoin.bin

full-firmware-mem-protect:
	make bootloader-mem-protect
	make firmware
	cp bootloader-memory-protected.bin tiny-firmware/bootloader/combine/bl.bin
	cp tiny-firmware/skycoin.bin tiny-firmware/bootloader/combine/fw.bin
	cd tiny-firmware/bootloader/combine/ ; /usr/bin/python prepare.py 
	mv tiny-firmware/bootloader/combine/combined.bin full-firmware-memory-protected.bin

full-firmware:
	make bootloader
	make firmware
	cp bootloader-no-memory-protect.bin tiny-firmware/bootloader/combine/bl.bin
	cp tiny-firmware/skycoin.bin tiny-firmware/bootloader/combine/fw.bin
	cd tiny-firmware/bootloader/combine/ ; /usr/bin/python prepare.py 
	mv tiny-firmware/bootloader/combine/combined.bin full-firmware-no-mem-protect.bin

emulator: build-deps
	EMULATOR=1 make -C tiny-firmware/emulator/
	EMULATOR=1 make -C tiny-firmware/
	mv tiny-firmware/skycoin-emulator.elf emulator

run-emulator: emulator
	./emulator

st-skycoin:
	cd tiny-firmware/bootloader/combine/; st-flash write combined.bin 0x08000000
