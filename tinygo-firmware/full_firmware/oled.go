package main

// OLED is 128x64 SSD1306 on SPI1
// Pins: PA5=SCK, PA7=MOSI, PA4=CS, PB0=RST, PB1=DC

const (
	// OLED dimensions
	OLED_WIDTH  = 128
	OLED_HEIGHT = 64

	// RCC APB2 for SPI1
	RCC_APB2ENR = RCC_BASE + 0x44

	// SPI1 registers (on APB2)
	SPI1_BASE = 0x40013000
	SPI1_CR1  = SPI1_BASE + 0x00
	SPI1_CR2  = SPI1_BASE + 0x04
	SPI1_SR   = SPI1_BASE + 0x08
	SPI1_DR   = SPI1_BASE + 0x0C

	// GPIOA for SPI pins and CS
	GPIOA_AFRL = GPIOA_BASE + 0x20

	// GPIOB for RST and DC
	GPIOB_BASE  = 0x40020400
	GPIOB_MODER = GPIOB_BASE + 0x00
	GPIOB_ODR   = GPIOB_BASE + 0x14
	GPIOB_BSRR  = GPIOB_BASE + 0x18

	// OLED pins (from C firmware oled.c)
	OLED_CS_PIN   = 4 // PA4 - Chip Select
	OLED_SCK_PIN  = 5 // PA5 - SPI Clock
	OLED_MOSI_PIN = 7 // PA7 - SPI MOSI
	OLED_DC_PIN   = 0 // PB0 - Data/Command
	OLED_RST_PIN  = 1 // PB1 - Reset

	// SPI1 CR1 bits
	SPI_CR1_CPHA     = 1 << 0
	SPI_CR1_CPOL     = 1 << 1
	SPI_CR1_MSTR     = 1 << 2
	SPI_CR1_BR_DIV8  = 2 << 3 // Baud rate = fPCLK/8
	SPI_CR1_SPE      = 1 << 6
	SPI_CR1_LSBFIRST = 1 << 7
	SPI_CR1_SSI      = 1 << 8
	SPI_CR1_SSM      = 1 << 9

	// SPI1 CR2 bits
	SPI_CR2_SSOE = 1 << 2
)

var oledBuffer [OLED_WIDTH * OLED_HEIGHT / 8]byte

func oledDelay(us uint32) {
	for i := uint32(0); i < us*120/4; i++ {
		_ = regGet(RCC_AHB1ENR) // Volatile read from always-accessible register
	}
}

func oledSetRST(val bool) {
	if val {
		regSet(GPIOB_BSRR, 1<<OLED_RST_PIN) // Set
	} else {
		regSet(GPIOB_BSRR, 1<<(OLED_RST_PIN+16)) // Reset
	}
}

func oledSetDC(val bool) {
	if val {
		regSet(GPIOB_BSRR, 1<<OLED_DC_PIN) // Data
	} else {
		regSet(GPIOB_BSRR, 1<<(OLED_DC_PIN+16)) // Command
	}
}

func oledSetCS(val bool) {
	if val {
		regSet(GPIOA_ODR, regGet(GPIOA_ODR)|(1<<OLED_CS_PIN)) // Deselect
	} else {
		regSet(GPIOA_ODR, regGet(GPIOA_ODR)&^(1<<OLED_CS_PIN)) // Select
	}
}

func spiSend(data byte) {
	// Wait for TXE
	for regGet(SPI1_SR)&(1<<1) == 0 {
	}
	regSet(SPI1_DR, uint32(data))
	// Wait for BSY
	for regGet(SPI1_SR)&(1<<7) != 0 {
	}
}

func oledCmd(cmd byte) {
	oledSetDC(false) // Command mode
	spiSend(cmd)
}

func oledData(data byte) {
	oledSetDC(true) // Data mode
	spiSend(data)
}

func oledInit() {
	println("Initializing OLED...")

	// Enable GPIO clocks
	regSetBits(RCC_AHB1ENR, 1<<0) // GPIOA
	regSetBits(RCC_AHB1ENR, 1<<1) // GPIOB

	// Enable SPI1 clock (on APB2)
	regSetBits(RCC_APB2ENR, 1<<12) // SPI1

	oledDelay(100) // Let clocks stabilize

	// Configure PA4 (CS) as output
	moder := regGet(GPIOA_MODER)
	moder &^= (3 << (OLED_CS_PIN * 2))
	moder |= (1 << (OLED_CS_PIN * 2)) // Output
	regSet(GPIOA_MODER, moder)

	// Configure PA5 (SCK) and PA7 (MOSI) as alternate function
	moder = regGet(GPIOA_MODER)
	moder &^= (3 << (OLED_SCK_PIN * 2)) | (3 << (OLED_MOSI_PIN * 2))
	moder |= (2 << (OLED_SCK_PIN * 2)) | (2 << (OLED_MOSI_PIN * 2)) // AF mode
	regSet(GPIOA_MODER, moder)

	// Set AF5 (SPI1) for PA5 and PA7
	afrl := regGet(GPIOA_AFRL)
	afrl &^= (0xF << (OLED_SCK_PIN * 4)) | (0xF << (OLED_MOSI_PIN * 4))
	afrl |= (5 << (OLED_SCK_PIN * 4)) | (5 << (OLED_MOSI_PIN * 4)) // AF5 = SPI1
	regSet(GPIOA_AFRL, afrl)

	// Configure PB0 (RST) and PB1 (DC) as output
	moder = regGet(GPIOB_MODER)
	moder &^= (3 << (OLED_RST_PIN * 2)) | (3 << (OLED_DC_PIN * 2))
	moder |= (1 << (OLED_RST_PIN * 2)) | (1 << (OLED_DC_PIN * 2))
	regSet(GPIOB_MODER, moder)

	// Initialize SPI1 as master
	// CPOL=0, CPHA=0, MSB first, 8-bit, baudrate=fPCLK/8
	regSet(SPI1_CR1, 0)            // Disable SPI first
	regSet(SPI1_CR2, SPI_CR2_SSOE) // Enable SS output
	regSet(SPI1_CR1, SPI_CR1_MSTR|SPI_CR1_BR_DIV8|SPI_CR1_SSI|SPI_CR1_SSM)
	regSetBits(SPI1_CR1, SPI_CR1_SPE) // Enable SPI

	// Set CS high (deselect) initially
	oledSetCS(true)
	oledSetDC(false) // Command mode

	// Reset OLED
	oledSetRST(true)
	oledDelay(1000)
	oledSetRST(false)
	oledDelay(10000) // 10ms reset pulse
	oledSetRST(true)
	oledDelay(1000)

	// Select OLED
	oledSetCS(false)

	// Initialize OLED controller
	oledCmd(0xAE) // Display off
	oledCmd(0xD5) // Set display clock
	oledCmd(0x80)
	oledCmd(0xA8) // Set multiplex
	oledCmd(0x3F) // 1/64 duty
	oledCmd(0xD3) // Set display offset
	oledCmd(0x00)
	oledCmd(0x40) // Set start line
	oledCmd(0x8D) // Charge pump
	oledCmd(0x14) // Enable charge pump
	oledCmd(0x20) // Memory mode
	oledCmd(0x00) // Horizontal addressing
	oledCmd(0xA1) // Segment remap
	oledCmd(0xC8) // COM scan direction
	oledCmd(0xDA) // COM pins
	oledCmd(0x12)
	oledCmd(0x81) // Contrast
	oledCmd(0xCF)
	oledCmd(0xD9) // Precharge
	oledCmd(0xF1)
	oledCmd(0xDB) // VCOMH
	oledCmd(0x40)
	oledCmd(0xA4) // Display all on resume
	oledCmd(0xA6) // Normal display (not inverted)
	oledCmd(0xAF) // Display on

	// Deselect OLED
	oledSetCS(true)

	println("OLED initialized")
}

func oledClear() {
	for i := range oledBuffer {
		oledBuffer[i] = 0
	}
}

func oledRefresh() {
	// Select OLED
	oledSetCS(false)

	// Set column and page address
	oledCmd(0x21) // Column addr
	oledCmd(0x00) // Start column
	oledCmd(0x7F) // End column
	oledCmd(0x22) // Page addr
	oledCmd(0x00) // Start page
	oledCmd(0x07) // End page

	// Send buffer
	oledSetDC(true)
	for i := range oledBuffer {
		spiSend(oledBuffer[i])
	}

	// Deselect OLED
	oledSetCS(true)
}

func oledDrawPixel(x, y int, on bool) {
	if x < 0 || x >= OLED_WIDTH || y < 0 || y >= OLED_HEIGHT {
		return
	}

	idx := x + (y/8)*OLED_WIDTH
	bit := byte(1 << (y % 8))

	if on {
		oledBuffer[idx] |= bit
	} else {
		oledBuffer[idx] &^= bit
	}
}

// Simple 5x7 font for numbers and letters
var font5x7 = map[rune][5]byte{
	'0': {0x3E, 0x51, 0x49, 0x45, 0x3E},
	'1': {0x00, 0x42, 0x7F, 0x40, 0x00},
	'2': {0x42, 0x61, 0x51, 0x49, 0x46},
	'3': {0x21, 0x41, 0x45, 0x4B, 0x31},
	'4': {0x18, 0x14, 0x12, 0x7F, 0x10},
	'5': {0x27, 0x45, 0x45, 0x45, 0x39},
	'6': {0x3C, 0x4A, 0x49, 0x49, 0x30},
	'7': {0x01, 0x71, 0x09, 0x05, 0x03},
	'8': {0x36, 0x49, 0x49, 0x49, 0x36},
	'9': {0x06, 0x49, 0x49, 0x29, 0x1E},
	'A': {0x7E, 0x11, 0x11, 0x11, 0x7E},
	'B': {0x7F, 0x49, 0x49, 0x49, 0x36},
	'C': {0x3E, 0x41, 0x41, 0x41, 0x22},
	'D': {0x7F, 0x41, 0x41, 0x22, 0x1C},
	'E': {0x7F, 0x49, 0x49, 0x49, 0x41},
	'F': {0x7F, 0x09, 0x09, 0x09, 0x01},
	'G': {0x3E, 0x41, 0x49, 0x49, 0x7A},
	'H': {0x7F, 0x08, 0x08, 0x08, 0x7F},
	'I': {0x00, 0x41, 0x7F, 0x41, 0x00},
	'K': {0x7F, 0x08, 0x14, 0x22, 0x41},
	'L': {0x7F, 0x40, 0x40, 0x40, 0x40},
	'M': {0x7F, 0x02, 0x0C, 0x02, 0x7F},
	'N': {0x7F, 0x04, 0x08, 0x10, 0x7F},
	'O': {0x3E, 0x41, 0x41, 0x41, 0x3E},
	'R': {0x7F, 0x09, 0x19, 0x29, 0x46},
	'S': {0x46, 0x49, 0x49, 0x49, 0x31},
	'T': {0x01, 0x01, 0x7F, 0x01, 0x01},
	'U': {0x3F, 0x40, 0x40, 0x40, 0x3F},
	'Y': {0x07, 0x08, 0x70, 0x08, 0x07},
	' ': {0x00, 0x00, 0x00, 0x00, 0x00},
	'.': {0x00, 0x60, 0x60, 0x00, 0x00},
	'!': {0x00, 0x00, 0x5F, 0x00, 0x00},
}

func oledDrawChar(x, y int, c rune) {
	glyph, ok := font5x7[c]
	if !ok {
		glyph = font5x7[' ']
	}

	for col := 0; col < 5; col++ {
		for row := 0; row < 7; row++ {
			if glyph[col]&(1<<row) != 0 {
				oledDrawPixel(x+col, y+row, true)
			}
		}
	}
}

func oledDrawString(x, y int, s string) {
	for i, c := range s {
		oledDrawChar(x+i*6, y, c)
	}
}

func oledDrawStringCenter(y int, s string) {
	x := (OLED_WIDTH - len(s)*6) / 2
	oledDrawString(x, y, s)
}

func oledBox(x1, y1, x2, y2 int, fill bool) {
	for x := x1; x <= x2; x++ {
		for y := y1; y <= y2; y++ {
			oledDrawPixel(x, y, fill)
		}
	}
}
