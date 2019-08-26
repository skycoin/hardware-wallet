.PHONY: proto
EMULATOR = 1
PYTHON ?= python
CC       ?= gcc
LD       := $(CC)
ifneq ($(UNAME_S),Darwin)
OBJCOPY  = objcopy
endif
OBJDUMP  = objdump
AR       = ar
AS       = as
ifeq ($(UNAME_S),Darwin)
	CFLAGS += -DCONFIDENTIAL=
else
	CFLAGS += -DCONFIDENTIAL='__attribute__((section("confidential")))'
endif

OBJS += emulator/setup.o
OBJS += emulator/buttons.o
OBJS += emulator/flash.o
OBJS += emulator/oled.o
OBJS += emulator/rng.o
OBJS += emulator/timer.o
OBJS += emulator/udp.o
OBJS += firmware/udp.o

ifneq ($(UNAME_S),Darwin)
OBJS += emulator/strl.o
endif

CFLAGS += -DEMULATOR=1
CFLAGS += -Wno-pointer-to-int-cast
CFLAGS += -Wno-int-to-pointer-cast

CFLAGS += -include stdio.h
CFLAGS += -include $(TOP_DIR)emulator/emulator.h

HEADLESS ?= 0
CFLAGS   += -DHEADLESS=$(HEADLESS)
SDL_CFLAGS ?= $(shell sdl2-config --cflags | sed 's/-D_THREAD_SAFE//g')
CFLAGS   += $(SDL_CFLAGS) -D_REENTRANT
CFLAGS   += -I$(TOOLCHAIN_DIR)/include
LDLIBS   += -lSDL2

ifeq ($(COVERAGE), 1)
	CFLAGS += -fprofile-arcs -ftest-coverage
	LDLIBS+=-lgcov --coverage
	SRCS  = $(OBJS:.o=.c)
	SRCS += $(TEST_OBJS:.o=.c)
endif

clean::
	rm -f $(OBJS)
	rm -f *.a
	rm -f *.bin
	rm -f *.d
	rm -f *.elf
	rm -f *.hex
	rm -f *.list
	rm -f *.log
	rm -f *.srec
