EMULATOR := 1
UNAME_S := $(shell uname -s)

SDL_CFLAGS ?= $(shell sdl2-config --cflags | sed 's/-D_THREAD_SAFE//g')

TOOLCHAIN_DIR ?= $(TOP_DIR)vendor/libopencm3

CFLAGS += -DEMULATOR=1
CFLAGS += -Wno-pointer-to-int-cast
CFLAGS += -Wno-int-to-pointer-cast

HEADLESS ?= 0

CFLAGS += -include stdio.h
CFLAGS += -include $(TOP_DIR)emulator/emulator.h

ifeq ($(HEADLESS),1)
CFLAGS   += -DHEADLESS=1
else
CFLAGS   += -DHEADLESS=0
CFLAGS   += $(SDL_CFLAGS) -D_REENTRANT
LDLIBS   += -lSDL2
endif

OBJS += setup.o

OBJS += buttons.o
OBJS += flash.o
OBJS += oled.o
OBJS += rng.o
OBJS += timer.o
OBJS += udp.o
ifneq ($(UNAME_S),Darwin)
OBJS += strl.o
endif

libemulator.a: $(OBJS)
	$(AR) rcs $@ $(OBJS)

include ../Makefile.include
