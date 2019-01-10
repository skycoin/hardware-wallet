#ifndef __CNBITMAPS_H__
#define __CNBITMAPS_H__

#include <stdint.h>

#define CNBITMAPLEN 10

typedef struct {
	uint32_t index;
	const uint8_t data[32];
} CNBITMAP;


extern const CNBITMAP chinese_bitmap[CNBITMAPLEN];

#endif
