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

build-deps:
	make -C tiny-firmware/vendor/nanopb/generator/proto/
	make -C tiny-firmware/protob/

firmware-deps: build-deps
	make -C tiny-firmware/vendor/libopencm3/

bootloader: firmware-deps
	rm -f tiny-firmware/memory.o tiny-firmware/gen/bitmaps.o # Force rebuild of these two files
	SIGNATURE_PROTECT=1 REVERSE_BUTTONS=1 make -C tiny-firmware/bootloader/ align

firmware: firmware-deps
	rm -f tiny-firmware/memory.o tiny-firmware/gen/bitmaps.o # Force rebuild of these two files
	REVERSE_BUTTONS=1 make -C tiny-firmware/ sign

tiny-firmware/bootloader/libskycoin-crypto.so:
	make -C skycoin-api clean
	make -C skycoin-api libskycoin-crypto.so
	cp skycoin-api/libskycoin-crypto.so tiny-firmware/bootloader/
	make -C skycoin-api clean

sign: tiny-firmware/bootloader/libskycoin-crypto.so firmware
	tiny-firmware/bootloader/firmware_sign.py -s -f tiny-firmware/skycoin.bin

full-firmware: bootloader firmware 
	cp tiny-firmware/bootloader/bootloader.bin tiny-firmware/bootloader/combine/bl.bin
	cp tiny-firmware/skycoin.bin tiny-firmware/bootloader/combine/fw.bin
	cd tiny-firmware/bootloader/combine/ ; /usr/bin/python prepare.py 

emulator: build-deps
	EMULATOR=1 make -C tiny-firmware/emulator/
	EMULATOR=1 make -C tiny-firmware/
	mv tiny-firmware/skycoin-emulator.elf emulator

run-emulator: emulator
	./emulator

st-skycoin:
	cd tiny-firmware/bootloader/combine/; st-flash write combined.bin 0x08000000
