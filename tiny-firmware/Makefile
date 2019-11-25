UNAME_S ?= $(shell uname -s)
ifeq ($(EMULATOR),1)
NAME = skycoin-emulator
else
NAME  = skyfirmware
endif

#libskywallet.a
OBJS += buttons.o
OBJS += layout.o
OBJS += oled.o
OBJS += rng.o
OBJS += util.o
OBJS += gen/fonts.o

ifneq ($(EMULATOR),1)
OBJS += startup.o
OBJS += timer.o
OBJS += setup.o
OBJS += supervise.o
OBJS += usb.o
endif

ifneq ($(BOOTLOADER),1)
OBJS += memory.o
OBJS += gen/bitmaps.o
endif
#end libskywallet.a

OBJS += $(TOP_DIR)protob/nanopb/vendor/nanopb/pb_common.o
OBJS += $(TOP_DIR)protob/nanopb/vendor/nanopb/pb_decode.o
OBJS += $(TOP_DIR)protob/nanopb/vendor/nanopb/pb_encode.o

FIRMWARE_SRCS = $(shell ls firmware/*.c | grep -v main.c)
OBJS += $(FIRMWARE_SRCS:.c=.o)

OBJS += protob/c/messages.pb.o
OBJS += protob/c/types.pb.o
OBJS += protob/c/bitcoin_messages.pb.o
OBJS += protob/c/bitcoin_types.pb.o

#test_skyhw
TEST_OBJS += $(patsubst tests/%.c,tests/%.o, $(wildcard tests/*.c))
TEST_OBJS += serialno.o
#end test_skyhw

ifneq ($(EMULATOR),1)
LDSCRIPT  = memory.ld
LDLIBS   += -lopencm3_stm32f2
LIBDEPS  += $(TOOLCHAIN_DIR)/lib/libopencm3_stm32f2.a
endif

#skycoin-crypto
OBJS += $(TOP_DIR)vendor/skycoin-crypto/skycoin_signature.o
OBJS += $(TOP_DIR)vendor/skycoin-crypto/skycoin_crypto.o
OBJS += $(TOP_DIR)vendor/skycoin-crypto/check_digest.o
OBJS += $(TOP_DIR)vendor/skycoin-crypto/tools/base58.o
OBJS += $(TOP_DIR)vendor/skycoin-crypto/tools/blake256.o
OBJS += $(TOP_DIR)vendor/skycoin-crypto/tools/hasher.o
OBJS += $(TOP_DIR)vendor/skycoin-crypto/tools/rand.o
OBJS += $(TOP_DIR)vendor/skycoin-crypto/tools/sha2.o
OBJS += $(TOP_DIR)vendor/skycoin-crypto/tools/bignum.o
OBJS += $(TOP_DIR)vendor/skycoin-crypto/tools/curves.o
OBJS += $(TOP_DIR)vendor/skycoin-crypto/tools/hmac.o
OBJS += $(TOP_DIR)vendor/skycoin-crypto/tools/ripemd160.o
OBJS += $(TOP_DIR)vendor/skycoin-crypto/tools/bip32.o
OBJS += $(TOP_DIR)vendor/skycoin-crypto/tools/ecdsa.o
OBJS += $(TOP_DIR)vendor/skycoin-crypto/tools/memzero.o
OBJS += $(TOP_DIR)vendor/skycoin-crypto/tools/secp256k1.o
OBJS += $(TOP_DIR)vendor/skycoin-crypto/tools/bip39.o
OBJS += $(TOP_DIR)vendor/skycoin-crypto/tools/pbkdf2.o
OBJS += $(TOP_DIR)vendor/skycoin-crypto/tools/entropypool.o
#end skycoin-crypto

DEBUG_LINK ?= 0
CFLAGS += -I$(TOP_DIR)protob/nanopb/vendor/nanopb \
          -I$(TOP_DIR)protob/c \
          -DPB_FIELD_16BIT=1 \
          -DDEBUG_LINK=$(DEBUG_LINK)

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

coverage: test
	gcov -n -b $(SRCS)
