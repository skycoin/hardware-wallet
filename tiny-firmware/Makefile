ifeq ($(EMULATOR),1)
NAME = skycoin-emulator
else
NAME  = skyfirmware
endif

ENABLE_GETENTROPY ?= 0
DISABLE_GETENTROPY_CONFIRM ?= 0

#libskywallet.a
ifneq ($(EMULATOR),1)
OBJS += startup.o
OBJS += timer.o
OBJS += setup.o
OBJS += supervise.o
endif

OBJS += buttons.o
OBJS += layout.o
OBJS += oled.o
OBJS += rng.o
OBJS += util.o

ifneq ($(BOOTLOADER),1)
OBJS += memory.o
OBJS += gen/bitmaps.o
endif
OBJS += gen/fonts.o
#end libskywallet.a

#test_skyhw
TEST_OBJS += $(patsubst tests/%.c,tests/%.o, $(wildcard tests/*.c))
TEST_OBJS += serialno.o
#end test_skyhw

ifneq ($(EMULATOR),1)
LDSCRIPT  = memory.ld
LDLIBS   += -lopencm3_stm32f2
LIBDEPS  += $(TOOLCHAIN_DIR)/lib/libopencm3_stm32f2.a
endif

DEBUG_LINK ?= 0
CFLAGS += -Wno-sequence-point
CFLAGS += -I$(TOP_DIR)protob/nanopb/vendor/nanopb -I$(TOP_DIR)protob/c -DPB_FIELD_16BIT=1
CFLAGS += -DDEBUG_LINK=$(DEBUG_LINK)
CFLAGS += -DDEBUG_LOG=$(DEBUG_LOG)

INC+=-Ifirmware
CFLAGS += -I. $(INC)

OBJS += $(TOP_DIR)protob/nanopb/vendor/nanopb/pb_common.o
OBJS += $(TOP_DIR)protob/nanopb/vendor/nanopb/pb_decode.o
OBJS += $(TOP_DIR)protob/nanopb/vendor/nanopb/pb_encode.o

ifneq ($(EMULATOR),1)
OBJS += firmware/usb.o
OBJS += firmware/fastflash.o
endif
OBJS += firmware/skywallet.o
OBJS += firmware/layout2.o
OBJS += firmware/storage.o
OBJS += firmware/messages.o
OBJS += firmware/droplet.o
OBJS += firmware/fsm.o
OBJS += firmware/fsm_impl.o
OBJS += firmware/protect.o
OBJS += firmware/pinmatrix.o
OBJS += firmware/reset.o
OBJS += firmware/recovery.o
OBJS += firmware/factory_test.o
OBJS += firmware/gpio_noise.o
OBJS += firmware/entropy.o
OBJS += firmware/swtimer.o

OBJS += protob/c/messages.pb.o
OBJS += protob/c/types.pb.o

#skycoin-crypto
LDLIBS += -lskycoin-crypto
LDFLAGS += -L$(TOP_DIR)
#end skycoin-crypto

CFLAGS   += -frandom-seed=123

ifneq ($(EMULATOR),1)
.PHONY: proto libopencm3

all: libopencm3 proto $(NAME).bin
else
.PHONY: proto

all: proto $(NAME)
endif

proto:
	cd protob && make build-c

libopencm3:
	cd vendor/libopencm3 && make

sign: $(NAME).bin
	bootloader/firmware_sign.py -f $(NAME).bin -pk $(FIRMWARE_SIGNATURE_PUB_KEY1) $(FIRMWARE_SIGNATURE_PUB_KEY2) $(FIRMWARE_SIGNATURE_PUB_KEY3) $(FIRMWARE_SIGNATURE_PUB_KEY4) $(FIRMWARE_SIGNATURE_PUB_KEY5) -s

add_meta_header: $(NAME).bin
	bootloader/firmware_sign.py -f $(NAME).bin -pk $(FIRMWARE_SIGNATURE_PUB_KEY1) $(FIRMWARE_SIGNATURE_PUB_KEY2) $(FIRMWARE_SIGNATURE_PUB_KEY3) $(FIRMWARE_SIGNATURE_PUB_KEY4) $(FIRMWARE_SIGNATURE_PUB_KEY5) -a

ifeq ($(EMULATOR),1)
include emulator/Makefile
endif

include Makefile.include

clean::
	rm -f $(OBJS)
	rm -f firmware/*.o
	rm -f *.a
	rm -f *.bin
	rm -f *.d
	rm -f *.elf
	rm -f *.hex
	rm -f *.list
	rm -f *.log
	rm -f *.srec
	cd protob && make clean-c
