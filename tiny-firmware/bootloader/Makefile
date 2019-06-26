NAME  = bootloader
BOOTLOADER = 1

FIRMWARE_SIGNATURE_PUB_KEY1 ?= 024291e2425a2fc7ec7bd75c8128726ca8cfb7ce9c04ae8186b66c3516f0f80cd2
FIRMWARE_SIGNATURE_PUB_KEY2 ?= 03e592cb31c3c2cc9b3810e5c78298280b0cc785cd7f28e36e135aa8a0fc74d081
FIRMWARE_SIGNATURE_PUB_KEY3 ?= 03b155df34b4c0879fdd6bde2acb9c7a45e93aa0bd0c697f6292dc3d1cb4c596d6
FIRMWARE_SIGNATURE_PUB_KEY4 ?= 026d1d2e1c4af5a2c89e8e4c8bf724034d0252eb8b9179fc6eec9ceb8bb1734997
FIRMWARE_SIGNATURE_PUB_KEY5 ?= 033bdf377502789d27a1d534775392af97a93333181b9736395b3db687ceffc473

#libskywallet.a
OBJS += ../startup.o
OBJS += ../buttons.o
OBJS += ../layout.o
OBJS += ../oled.o
OBJS += ../rng.o
OBJS += ../serialno.o
OBJS += ../setup.o
OBJS += ../supervise.o
OBJS += ../timer.o
OBJS += ../util.o
OBJS += ../memory.o
OBJS += ../gen/bitmaps.o
OBJS += ../gen/fonts.o
#end libskywallet.a

#skycoin-crypto
OBJS += $(TOP_DIR)vendor/skycoin-crypto/skycoin_signature.o
OBJS += $(TOP_DIR)vendor/skycoin-crypto/tools/curves.o
OBJS += $(TOP_DIR)vendor/skycoin-crypto/tools/hmac.o
OBJS += $(TOP_DIR)vendor/skycoin-crypto/tools/secp256k1.o
# OBJS += $(TOP_DIR)vendor/skycoin-crypto/tools/bip32.o

#end skycoin-crypto

OBJS += bootloader.o
OBJS += signatures.o
OBJS += usb.o

OBJS += $(TOP_DIR)vendor/skycoin-crypto/tools/bignum.small.o
OBJS += $(TOP_DIR)vendor/skycoin-crypto/tools/ecdsa.small.o
# OBJS += $(TOP_DIR)vendor/skycoin-crypto/tools/secp256k1.small.o
OBJS += $(TOP_DIR)vendor/skycoin-crypto/tools/sha2.small.o
OBJS += $(TOP_DIR)vendor/skycoin-crypto/tools/memzero.small.o

CFLAGS += -DUSE_PRECOMPUTED_IV=0
CFLAGS += -DUSE_PRECOMPUTED_CP=0

ifeq ($(SIGNATURE_PROTECT),1)
CFLAGS += -DSIGNATURE_PROTECT=1
else
CFLAGS += -DSIGNATURE_PROTECT=0
endif

CFLAGS += -DBOOTLOADER

ifeq ($(SIGNATURE_DEBUG),1)
CFLAGS += -DSIGNATURE_DEBUG=1
else
CFLAGS += -DSIGNATURE_DEBUG=0
endif
OPTFLAGS ?= -Os
DEBUG ?= 0

LDSCRIPT = bootloader-memory.ld
LDLIBS   += -lopencm3_stm32f2

pub_keys.h:
	./generate-pubkeys-cfile.py -pk $(FIRMWARE_SIGNATURE_PUB_KEY1) $(FIRMWARE_SIGNATURE_PUB_KEY2) $(FIRMWARE_SIGNATURE_PUB_KEY3) $(FIRMWARE_SIGNATURE_PUB_KEY4) $(FIRMWARE_SIGNATURE_PUB_KEY5)

include ../Makefile.include

align: $(NAME).bin
	./firmware_align.py $(NAME).bin

clean::
	rm -f pub_keys.h
