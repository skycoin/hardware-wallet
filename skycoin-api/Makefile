.DEFAULT_GOAL := help
.PHONY: test clean

UNAME_S     ?= $(shell uname -s)
MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
MKFILE_DIR  := $(dir $(MKFILE_PATH))
TOOLS_DIR   := $(MKFILE_DIR)/tools
COVERAGE ?= 0

CC       ?= gcc

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

INC += -I$(TOOLS_DIR)
CFLAGS += -I$(MKFILE_DIR) $(INC)

SRCS += skycoin_crypto.c
SRCS += skycoin_signature.c
SRCS += check_digest.c
SRCS += $(shell ls $(TOOLS_DIR)/*.c)

OBJS   = $(SRCS:.c=.o)

%.o: %.c %.h
	$(CC) $(CFLAGS) -o $@ -c $<

LIBS_DARWIN +=
LIBS_LINUX += -L/usr/local/lib/ -lm -lrt
TESTLIBS = `pkg-config --cflags --libs check`
CC_VERSION = $(shell $(CC) -dumpversion)
STDC_FLAG = $(python -c "if tuple(map(int, '$(CC_VERSION)'.split('.'))) < (6,): print('-std=C99'")
ifeq ($(UNAME_S), Linux)
	LIBS=$(LIBS_LINUX)
endif
ifeq ($(COVERAGE), 1)
	CFLAGS += -fprofile-arcs -ftest-coverage
	TESTLIBS+=-lgcov --coverage
endif
ifeq ($(UNAME_S), Darwin)
	LIBS=$(LIBS_DARWIN)
endif


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
	$(PYTHON) ./test_skycoin_crypto.py

clean: ## Delete all temporary files
	rm -f $(MKFILE_DIR)/*.o test_skycoin_crypto
	rm -f $(MKFILE_DIR)/*.so
	rm -f $(TOOLS_DIR)/*.o
	rm -f $(MKFILE_DIR)/tools/*.o
	rm -f $(MKFILE_DIR)/*.a

coverage: test_skycoin_crypto
	gcov -n -b $(SRCS) test_skycoin_crypto.c

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

