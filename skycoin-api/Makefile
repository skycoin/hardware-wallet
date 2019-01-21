.DEFAULT_GOAL := help
.PHONY: test clean

CC       ?= gcc

MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
MKFILE_DIR  := $(notdir $(patsubst %/,%,$(dir $(mkfile_path))))

OPTFLAGS ?= -O3 -g -fPIC

CFLAGS   += $(OPTFLAGS) \
            -std=gnu99 \
            -W \
            -Wall \
            -Wextra \
            -Wimplicit-function-declaration \
            -Wredundant-decls \
            -Wstrict-prototypes \
            -Wundef \
            -Wshadow \
            -Wpointer-arith \
            -Wformat \
            -Wreturn-type \
            -Wsign-compare \
            -Wmultichar \
            -Wformat-nonliteral \
            -Winit-self \
            -Wuninitialized \
            -Wformat-security \
            -Werror

TESTINC=-I$(CHECK_PATH)/src
TESTINC+=-I$(CHECK_PATH)
INC=-I$(MKFILE_DIR)/tools/
CFLAGS += -I$(MKFILE_DIR) $(INC)

SRCS += skycoin_crypto.c
SRCS += skycoin_check_signature.c
SRCS += skycoin_check_signature_tools.c
SRCS += $(shell ls tools/*.c)

OBJS   = $(SRCS:.c=.o)

%.o: %.c %.h
	$(CC) $(CFLAGS) -o $@ -c $<

LIBS = -L/usr/local/lib/ -lm -lrt
TESTLIBS = -L$(CHECK_PATH)/src -lcheck 

all: test_skycoin_crypto

libskycoin-crypto.so: skycoin_crypto.o $(OBJS)
	$(CC) -rdynamic -shared $(CFLAGS) $(OBJS) -o libskycoin-crypto.so

libskycoin-crypto.a: skycoin_crypto.o $(OBJS)
	$(AR) rcs libskycoin-crypto.a skycoin_crypto.o $(OBJS)

test_skycoin_crypto.o: test_skycoin_crypto.c
	$(CC) $(CFLAGS) $(TESTINC) -o $@ -c $<

test_skycoin_crypto: test_skycoin_crypto.o libskycoin-crypto.so
	$(CC) test_skycoin_crypto.o $(OBJS) -L. -lskycoin-crypto $(LIBS) $(TESTLIBS) -o test_skycoin_crypto

test: test_skycoin_crypto ## Run test suite for Skycoin cipher library for firmware
	./test_skycoin_crypto

clean: ## Delete all temporary files
	rm -f *.o test_skycoin_crypto
	rm -f *.so
	rm -f tools/*.o
	rm -f trezor-tools/*.o
	rm -f *.a

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

