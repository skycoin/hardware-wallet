package main

import (
	"unsafe"
)

// USB Device State
type USBState uint8

const (
	USBStateDefault USBState = iota
	USBStateAddress
	USBStateConfigured
)

// USB Setup Packet (8 bytes)
type SetupPacket struct {
	bmRequestType uint8
	bRequest      uint8
	wValue        uint16
	wIndex        uint16
	wLength       uint16
}

// Additional USB OTG FS registers for endpoints
const (
	// EP1 registers
	USB_DIEPCTL1  = USB_OTG_FS + 0x920
	USB_DIEPINT1  = USB_OTG_FS + 0x928
	USB_DIEPTSIZ1 = USB_OTG_FS + 0x930
	USB_DTXFSTS1  = USB_OTG_FS + 0x938
	USB_DOEPCTL1  = USB_OTG_FS + 0xB20
	USB_DOEPINT1  = USB_OTG_FS + 0xB28
	USB_DOEPTSIZ1 = USB_OTG_FS + 0xB30

	// TX FIFO configuration
	USB_DIEPTXF1 = USB_OTG_FS + 0x104

	// FIFO addresses
	USB_FIFO1 = USB_OTG_FS + 0x2000

	// EP0 sizes
	USB_DIEPINT0 = USB_OTG_FS + 0x908
	USB_DOEPINT0 = USB_OTG_FS + 0xB08
)

// USB device state
var (
	usbState       USBState = USBStateDefault
	usbAddress     uint8    = 0
	usbConfigured  bool     = false
	pendingAddress uint8    = 0

	// EP0 control transfer state
	ep0TxBuf    [64]byte
	ep0TxLen    int
	ep0TxOffset int

	// EP1 HID packet buffers
	ep1RxBuf    [64]byte
	ep1RxReady  bool
	ep1TxBuf    [64]byte
	ep1TxPending bool
)

// Initialize USB device with HID support
func usbDeviceInit() {
	println("USB Device Init with HID support...")

	// Enable USB OTG FS clock
	regSetBits(RCC_AHB2ENR, 1<<7)
	delay(10000)

	// Clear all USB peripheral RAM (1.25KB at 0x50020000)
	println("Clearing USB FIFO RAM...")
	usbRAM := (*[320]uint32)(unsafe.Pointer(uintptr(0x50020000)))
	for i := range usbRAM {
		usbRAM[i] = 0
	}

	// Clear GCCFG
	regSet(USB_GCCFG, 0)

	// Select full-speed PHY
	regSetBits(USB_GUSBCFG, 1<<6) // PHYSEL

	// Wait for AHB idle
	for regGet(USB_GRSTCTL)&(1<<31) == 0 {
	}

	// Core soft reset
	regSetBits(USB_GRSTCTL, 1<<0) // CSRST
	for regGet(USB_GRSTCTL)&(1<<0) != 0 {
	}

	delay(100000)

	// Force device mode
	regSetBits(USB_GUSBCFG, 1<<30)     // FDMOD
	regSetBits(USB_GUSBCFG, 0xF<<10)   // TRDT = 15
	regClearBits(USB_GUSBCFG, 0x3F<<0) // Clear TOCAL
	regSetBits(USB_GUSBCFG, 0x01<<0)   // TOCAL = 1

	// Configure GCCFG for VBUS sensing
	cid := regGet(USB_CID)
	if cid >= 0x00001200 {
		regSet(USB_GCCFG, (1<<21)|(1<<16)) // VBDEN | PWRDWN
	} else {
		regSet(USB_GCCFG, (1<<19)|(1<<16)) // VBUSBSEN | PWRDWN
	}

	// Enable DP pull-up
	regClearBits(USB_DCTL, 1<<1) // Clear SDIS

	// Set device speed to full-speed
	dcfg := regGet(USB_DCFG)
	dcfg |= 0x3 // DSPD = 11 (full speed)
	regSet(USB_DCFG, dcfg)

	// Restart PHY clock
	regSet(USB_PCGCCTL, 0)

	// Configure FIFO sizes
	// RX FIFO: 128 words (512 bytes) at offset 0
	regSet(USB_GRXFSIZ, 128)
	// TX FIFO 0 (EP0): 64 words at offset 128
	regSet(USB_HNPTXFSIZ, (64<<16)|128)
	// TX FIFO 1 (EP1): 64 words at offset 192
	regSet(USB_DIEPTXF1, (64<<16)|192)

	// Clear all pending interrupts
	regSet(USB_GINTSTS, 0xFFFFFFFF)

	// Unmask USB interrupts
	regSet(USB_GINTMSK,
		(1<<13)| // ENUMDNEM
			(1<<12)| // USBRST
			(1<<11)| // USBSUSP
			(1<<10)| // ESUSP (early suspend)
			(1<<4)|  // RXFLVL
			(1<<18)| // IEPINT (IN endpoint)
			(1<<19)) // OEPINT (OUT endpoint)

	// Enable endpoint interrupts for EP0 and EP1
	regSet(USB_DAINTMSK, 0x00030003) // EP0+EP1 IN and OUT

	// Enable endpoint interrupt masks
	regSet(USB_DIEPMSK, (1<<0)|(1<<3)) // XFRCM, TOC
	regSet(USB_DOEPMSK, (1<<0)|(1<<3)|(1<<5)) // XFRCM, STUP, STSPHSRX

	// Enable global USB interrupt
	regSetBits(USB_GAHBCFG, 1<<0) // GINTMSK

	// Setup EP0 for control transfers
	setupEP0()

	println("USB Device initialized")
}

// Setup EP0 for control transfers
func setupEP0() {
	// EP0 OUT: Enable, set max packet size = 64
	regSet(USB_DOEPTSIZ0, (1<<29)|(1<<19)|64) // STUPCNT=1, PKTCNT=1, XFRSIZ=64
	regSet(USB_DOEPCTL0, (1<<31)|(1<<26)|0)   // EPENA, CNAK, MPSIZ=64
}

// Setup EP1 for HID IN/OUT
func setupEP1() {
	println("Setting up EP1 for HID...")

	// EP1 IN (device to host)
	// Type = Interrupt (11), Max packet = 64
	regSet(USB_DIEPCTL1,
		(1<<15)|  // USBAEP (active)
			(3<<18)|  // EPTYP = Interrupt
			(1<<22)|  // TXFNUM = 1
			64)       // MPSIZ = 64

	// EP1 OUT (host to device)
	// Type = Interrupt (11), Max packet = 64
	regSet(USB_DOEPTSIZ1, (1<<19)|64) // PKTCNT=1, XFRSIZ=64
	regSet(USB_DOEPCTL1,
		(1<<31)|  // EPENA
			(1<<26)|  // CNAK
			(1<<15)|  // USBAEP
			(3<<18)|  // EPTYP = Interrupt
			64)       // MPSIZ = 64

	println("EP1 configured")
}

// Poll USB device
func usbDevicePoll() {
	gintsts := regGet(USB_GINTSTS)

	if gintsts == 0 {
		return
	}

	// USB Reset
	if gintsts&(1<<12) != 0 {
		handleUSBReset()
		regSet(USB_GINTSTS, 1<<12)
	}

	// Enumeration done
	if gintsts&(1<<13) != 0 {
		handleEnumDone()
		regSet(USB_GINTSTS, 1<<13)
	}

	// RX FIFO non-empty
	if gintsts&(1<<4) != 0 {
		handleRxFifoNonEmpty()
	}

	// IN endpoint interrupt
	if gintsts&(1<<18) != 0 {
		handleInEndpoints()
	}

	// OUT endpoint interrupt
	if gintsts&(1<<19) != 0 {
		handleOutEndpoints()
	}

	// USB Suspend
	if gintsts&(1<<11) != 0 {
		regSet(USB_GINTSTS, 1<<11)
	}
}

// Handle USB bus reset
func handleUSBReset() {
	println("USB Reset")
	usbState = USBStateDefault
	usbAddress = 0
	usbConfigured = false
	pendingAddress = 0

	// Clear device address
	dcfg := regGet(USB_DCFG)
	dcfg &^= (0x7F << 4)
	regSet(USB_DCFG, dcfg)

	// Re-setup EP0
	setupEP0()
}

// Handle enumeration complete
func handleEnumDone() {
	println("Enumeration done")

	// Get enumeration speed
	dsts := regGet(USB_DSTS)
	speed := (dsts >> 1) & 0x3
	println("Speed:", speed) // 3 = full speed

	// Update EP0 max packet size based on speed
	// For full speed, keep 64 bytes
	setupEP0()
}

// Handle RX FIFO non-empty
func handleRxFifoNonEmpty() {
	rxstsp := regGet(USB_GRXSTSP)

	pktsts := (rxstsp >> 17) & 0xF
	bcnt := (rxstsp >> 4) & 0x7FF
	epnum := rxstsp & 0xF

	switch pktsts {
	case 0x06: // SETUP packet received
		if epnum == 0 {
			readSetupPacket()
		}
	case 0x02: // OUT data packet received
		if epnum == 0 {
			readEP0Data(int(bcnt))
		} else if epnum == 1 {
			readEP1Data(int(bcnt))
		}
	case 0x04: // SETUP stage complete
		// Re-enable EP0 OUT
		regSet(USB_DOEPCTL0, regGet(USB_DOEPCTL0)|(1<<26)) // CNAK
	case 0x03: // OUT transfer complete
		// Nothing to do
	}
}

// Read SETUP packet from FIFO
func readSetupPacket() {
	// Read 8 bytes (2 words) from FIFO
	w0 := regGet(USB_FIFO0)
	w1 := regGet(USB_FIFO0)

	setup := SetupPacket{
		bmRequestType: uint8(w0),
		bRequest:      uint8(w0 >> 8),
		wValue:        uint16(w0 >> 16),
		wIndex:        uint16(w1),
		wLength:       uint16(w1 >> 16),
	}

	handleSetupPacket(&setup)
}

// Handle SETUP packet
func handleSetupPacket(setup *SetupPacket) {
	reqType := setup.bmRequestType & 0x60 // Type bits

	switch reqType {
	case 0x00: // Standard request
		handleStandardRequest(setup)
	case 0x20: // Class request
		handleClassRequest(setup)
	default:
		stallEP0()
	}
}

// Handle standard USB requests
func handleStandardRequest(setup *SetupPacket) {
	switch setup.bRequest {
	case USB_REQ_GET_DESCRIPTOR:
		handleGetDescriptor(setup)

	case USB_REQ_SET_ADDRESS:
		handleSetAddress(setup)

	case USB_REQ_SET_CONFIGURATION:
		handleSetConfiguration(setup)

	case USB_REQ_GET_CONFIGURATION:
		ep0TxBuf[0] = 0
		if usbConfigured {
			ep0TxBuf[0] = 1
		}
		ep0SendData(ep0TxBuf[:1])

	case USB_REQ_GET_STATUS:
		ep0TxBuf[0] = 0
		ep0TxBuf[1] = 0
		ep0SendData(ep0TxBuf[:2])

	default:
		stallEP0()
	}
}

// Handle GET_DESCRIPTOR request
func handleGetDescriptor(setup *SetupPacket) {
	descType := uint8(setup.wValue >> 8)
	descIndex := uint8(setup.wValue)
	maxLen := int(setup.wLength)

	var data []byte

	switch descType {
	case USB_DT_DEVICE:
		data = deviceDescriptor[:]

	case USB_DT_CONFIGURATION:
		data = configDescriptor[:]

	case USB_DT_STRING:
		data = getStringDescriptor(descIndex)

	case USB_DT_HID:
		// Return HID descriptor (part of config descriptor)
		// HID descriptor starts at offset 18 (after config + interface)
		data = configDescriptor[18:27]

	case USB_DT_REPORT:
		data = hidReportDescriptor[:]

	default:
		stallEP0()
		return
	}

	if data == nil {
		stallEP0()
		return
	}

	// Limit to requested length
	if len(data) > maxLen {
		data = data[:maxLen]
	}

	ep0SendData(data)
}

// Handle SET_ADDRESS request
func handleSetAddress(setup *SetupPacket) {
	pendingAddress = uint8(setup.wValue)

	// Send ZLP status
	ep0SendZLP()

	// Address will be set after status stage completes
	usbState = USBStateAddress
}

// Handle SET_CONFIGURATION request
func handleSetConfiguration(setup *SetupPacket) {
	config := uint8(setup.wValue)

	if config == 0 {
		usbConfigured = false
	} else if config == 1 {
		usbConfigured = true
		usbState = USBStateConfigured

		// Setup HID endpoints
		setupEP1()
		println("Device configured!")
	} else {
		stallEP0()
		return
	}

	ep0SendZLP()
}

// Handle HID class requests
func handleClassRequest(setup *SetupPacket) {
	switch setup.bRequest {
	case USB_HID_REQ_GET_REPORT:
		// Not typically used for vendor HID
		ep0SendZLP()

	case USB_HID_REQ_SET_IDLE:
		// Accept and ignore
		ep0SendZLP()

	case USB_HID_REQ_GET_IDLE:
		ep0TxBuf[0] = 0
		ep0SendData(ep0TxBuf[:1])

	default:
		stallEP0()
	}
}

// Send data on EP0
func ep0SendData(data []byte) {
	if len(data) == 0 {
		ep0SendZLP()
		return
	}

	// Copy to TX buffer
	copy(ep0TxBuf[:], data)
	ep0TxLen = len(data)
	ep0TxOffset = 0

	// Send first chunk
	ep0SendNextChunk()
}

// Send next chunk on EP0
func ep0SendNextChunk() {
	remaining := ep0TxLen - ep0TxOffset
	if remaining <= 0 {
		return
	}

	chunkSize := remaining
	if chunkSize > 64 {
		chunkSize = 64
	}

	// Configure EP0 IN
	regSet(USB_DIEPTSIZ0, (1<<19)|uint32(chunkSize)) // PKTCNT=1, XFRSIZ

	// Enable EP0 IN
	regSet(USB_DIEPCTL0, regGet(USB_DIEPCTL0)|(1<<31)|(1<<26)) // EPENA, CNAK

	// Write data to FIFO
	words := (chunkSize + 3) / 4
	for i := 0; i < words; i++ {
		var w uint32
		for j := 0; j < 4 && ep0TxOffset+i*4+j < ep0TxLen; j++ {
			w |= uint32(ep0TxBuf[ep0TxOffset+i*4+j]) << (j * 8)
		}
		regSet(USB_FIFO0, w)
	}

	ep0TxOffset += chunkSize
}

// Send Zero-Length Packet on EP0
func ep0SendZLP() {
	regSet(USB_DIEPTSIZ0, (1<<19)|0) // PKTCNT=1, XFRSIZ=0
	regSet(USB_DIEPCTL0, regGet(USB_DIEPCTL0)|(1<<31)|(1<<26)) // EPENA, CNAK
}

// Stall EP0
func stallEP0() {
	regSetBits(USB_DIEPCTL0, 1<<21) // STALL
	regSetBits(USB_DOEPCTL0, 1<<21) // STALL
}

// Read EP0 data
func readEP0Data(bcnt int) {
	// Read and discard (we don't expect OUT data on EP0 for HID)
	words := (bcnt + 3) / 4
	for i := 0; i < words; i++ {
		_ = regGet(USB_FIFO0)
	}
}

// Read EP1 data (HID packet)
func readEP1Data(bcnt int) {
	if bcnt != 64 {
		// Invalid HID packet size
		return
	}

	// Read 64 bytes from FIFO
	for i := 0; i < 16; i++ {
		w := regGet(USB_FIFO1)
		ep1RxBuf[i*4+0] = uint8(w)
		ep1RxBuf[i*4+1] = uint8(w >> 8)
		ep1RxBuf[i*4+2] = uint8(w >> 16)
		ep1RxBuf[i*4+3] = uint8(w >> 24)
	}

	ep1RxReady = true
	println("HID packet received")
}

// Handle IN endpoint interrupts
func handleInEndpoints() {
	daint := regGet(USB_DAINT)

	// EP0 IN
	if daint&(1<<0) != 0 {
		diepint := regGet(USB_DIEPINT0)

		if diepint&(1<<0) != 0 { // Transfer complete
			// Apply pending address after SET_ADDRESS status
			if pendingAddress != 0 {
				dcfg := regGet(USB_DCFG)
				dcfg &^= (0x7F << 4)
				dcfg |= uint32(pendingAddress) << 4
				regSet(USB_DCFG, dcfg)
				usbAddress = pendingAddress
				pendingAddress = 0
				println("Address set:", usbAddress)
			}

			// Send more data if pending
			if ep0TxOffset < ep0TxLen {
				ep0SendNextChunk()
			}
		}

		regSet(USB_DIEPINT0, diepint) // Clear interrupts
	}

	// EP1 IN
	if daint&(1<<1) != 0 {
		diepint := regGet(USB_DIEPINT1)

		if diepint&(1<<0) != 0 { // Transfer complete
			ep1TxPending = false
		}

		regSet(USB_DIEPINT1, diepint)
	}
}

// Handle OUT endpoint interrupts
func handleOutEndpoints() {
	daint := regGet(USB_DAINT)

	// EP0 OUT
	if daint&(1<<16) != 0 {
		doepint := regGet(USB_DOEPINT0)

		if doepint&(1<<3) != 0 { // SETUP done
			// Re-enable EP0 OUT for next SETUP
			setupEP0()
		}

		regSet(USB_DOEPINT0, doepint)
	}

	// EP1 OUT
	if daint&(1<<17) != 0 {
		doepint := regGet(USB_DOEPINT1)

		if doepint&(1<<0) != 0 { // Transfer complete
			// Re-enable EP1 OUT
			regSet(USB_DOEPTSIZ1, (1<<19)|64)
			regSet(USB_DOEPCTL1, regGet(USB_DOEPCTL1)|(1<<31)|(1<<26))
		}

		regSet(USB_DOEPINT1, doepint)
	}
}

// Send HID packet on EP1 IN
func ep1SendPacket(data *[64]byte) bool {
	if ep1TxPending || !usbConfigured {
		return false
	}

	// Configure EP1 IN
	regSet(USB_DIEPTSIZ1, (1<<19)|64) // PKTCNT=1, XFRSIZ=64

	// Enable EP1 IN
	regSet(USB_DIEPCTL1, regGet(USB_DIEPCTL1)|(1<<31)|(1<<26)) // EPENA, CNAK

	// Write data to FIFO
	for i := 0; i < 16; i++ {
		w := uint32(data[i*4+0]) |
			uint32(data[i*4+1])<<8 |
			uint32(data[i*4+2])<<16 |
			uint32(data[i*4+3])<<24
		regSet(USB_FIFO1, w)
	}

	ep1TxPending = true
	return true
}

// Check if HID packet is available
func ep1HasPacket() bool {
	return ep1RxReady
}

// Get received HID packet
func ep1GetPacket() *[64]byte {
	if !ep1RxReady {
		return nil
	}
	ep1RxReady = false
	return &ep1RxBuf
}

// Check if device is configured
func isConfigured() bool {
	return usbConfigured
}
