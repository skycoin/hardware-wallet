BINARY = skyfirmware-tinygo.bin
ELF = skyfirmware-tinygo.elf
TARGET = ./stm32f205.json

# All Go source files
# Minimal test - self-contained main.go
SOURCES = main.go
# Full firmware sources:
#SOURCES = _early_init.go main.go oled.go \
#	usb_descriptors.go usb_device.go \
#	messages.go protobuf.go dispatch.go \
#	types.go handlers.go

.PHONY: all build flash clean

all: build

build: $(BINARY)

DEVICE_ASM = device_stm32f205.s
DEVICE_OBJ = device_stm32f205.o

$(DEVICE_OBJ): $(DEVICE_ASM)
	@echo "Assembling device startup code..."
	arm-none-eabi-as -mcpu=cortex-m3 -mthumb -o $(DEVICE_OBJ) $(DEVICE_ASM)

$(BINARY): $(SOURCES) $(TARGET) stm32f205-firmware.ld $(DEVICE_OBJ)
	@echo "Building TinyGo firmware with OLED support..."
	tinygo build -o $(ELF) \
		-target=$(TARGET) \
		-opt=z \
		-gc=leaking \
		-scheduler=none \
		.
	@echo "Converting to binary..."
	arm-none-eabi-objcopy -O binary $(ELF) temp.bin
	@echo "Padding to minimum 4KB..."
	@SIZE=$$(stat -c%s temp.bin); if [ $$SIZE -lt 4096 ]; then truncate -s 4096 temp.bin; fi
	@echo "Signing firmware..."
	../tiny-firmware/bootloader/firmware_sign.py -f temp.bin \
		-pk 03d7fe879bea92c657797881cc2437fea86337ed4dce19859f43d023c1772c81dd \
		02ce15278b4d1cf5c20a2a518b95438bc1d497b1d55bddf69dbb253b538c131625 \
		02bebd3856b3fdadc54714220819946980d413edc8bc49f679b88fd2bf99ae0e15 \
		02015aa7da6acb423266a50db8821b42493cd2d874911c309209a003a1051c5d74 \
		03579beeeb075dcd20c63cbd3851ff0c81b1448c4f28597ce28924344a3f4bdbd4 -a > /dev/null 2>&1
	@mv temp.bin $(BINARY)
	@echo "Firmware size:"
	@ls -lh $(BINARY)
	@echo ""
	@echo "Build complete: $(BINARY)"

flash: $(BINARY)
	@echo "Flash firmware using:"
	@echo "  curl -X PUT http://127.0.0.1:9510/api/v1/firmware_update -F \"file=@$(BINARY)\""

clean:
	rm -f $(BINARY) $(ELF) $(DEVICE_OBJ)

size: $(ELF)
	arm-none-eabi-size $(ELF)
