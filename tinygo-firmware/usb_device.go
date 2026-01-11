package main

import (
	"runtime/volatile"
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

// USB OTG FS base and register addresses
const (
	USB_OTG_FS uintptr = 0x50000000
	RCC_BASE   uintptr = 0x40023800
	RCC_AHB2ENR uintptr = RCC_BASE + 0x34

	// USB Core registers
	USB_GAHBCFG   uintptr = USB_OTG_FS + 0x008
	USB_GUSBCFG   uintptr = USB_OTG_FS + 0x00C
	USB_GRSTCTL   uintptr = USB_OTG_FS + 0x010
	USB_GINTSTS   uintptr = USB_OTG_FS + 0x014
	USB_GINTMSK   uintptr = USB_OTG_FS + 0x018
	USB_GRXSTSP   uintptr = USB_OTG_FS + 0x020
	USB_GRXFSIZ   uintptr = USB_OTG_FS + 0x024
	USB_HNPTXFSIZ uintptr = USB_OTG_FS + 0x028
	USB_GCCFG     uintptr = USB_OTG_FS + 0x038
	USB_CID       uintptr = USB_OTG_FS + 0x03C

	// USB Device registers
	USB_DCFG     uintptr = USB_OTG_FS + 0x800
	USB_DCTL     uintptr = USB_OTG_FS + 0x804
	USB_DSTS     uintptr = USB_OTG_FS + 0x808
	USB_DIEPMSK  uintptr = USB_OTG_FS + 0x810
	USB_DOEPMSK  uintptr = USB_OTG_FS + 0x814
	USB_DAINT    uintptr = USB_OTG_FS + 0x818
	USB_DAINTMSK uintptr = USB_OTG_FS + 0x81C
	USB_PCGCCTL  uintptr = USB_OTG_FS + 0xE00

	// EP0 registers
	USB_DIEPCTL0  uintptr = USB_OTG_FS + 0x900
	USB_DIEPINT0  uintptr = USB_OTG_FS + 0x908
	USB_DIEPTSIZ0 uintptr = USB_OTG_FS + 0x910
	USB_DOEPCTL0  uintptr = USB_OTG_FS + 0xB00
	USB_DOEPINT0  uintptr = USB_OTG_FS + 0xB08
	USB_DOEPTSIZ0 uintptr = USB_OTG_FS + 0xB10
	USB_FIFO0     uintptr = USB_OTG_FS + 0x1000

	// EP1 registers
	USB_DIEPCTL1  uintptr = USB_OTG_FS + 0x920
	USB_DIEPINT1  uintptr = USB_OTG_FS + 0x928
	USB_DIEPTSIZ1 uintptr = USB_OTG_FS + 0x930
	USB_DOEPCTL1  uintptr = USB_OTG_FS + 0xB20
	USB_DOEPINT1  uintptr = USB_OTG_FS + 0xB28
	USB_DOEPTSIZ1 uintptr = USB_OTG_FS + 0xB30
	USB_DIEPTXF1  uintptr = USB_OTG_FS + 0x104
	USB_FIFO1     uintptr = USB_OTG_FS + 0x2000
)

// USB device state variables
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
	ep1RxBuf     [64]byte
	ep1RxReady   bool
	ep1TxBuf     [64]byte
	ep1TxPending bool
)

// ureg returns a volatile register at the given address
func ureg(addr uintptr) *volatile.Register32 {
	return (*volatile.Register32)(unsafe.Pointer(addr))
}

// delay performs a simple busy-wait delay
func usbDelay(count int) {
	for i := 0; i < count; i++ {
		ureg(USB_GINTSTS).Get() // Read a register to prevent optimization
	}
}

// usbDeviceInit initializes USB device with HID support
func usbDeviceInit() {
	// Enable USB OTG FS clock (bit 7 of AHB2ENR)
	ureg(RCC_AHB2ENR).SetBits(1 << 7)
	usbDelay(10000)

	// Clear all USB peripheral RAM (1.25KB at 0x50020000)
	usbRAM := (*[320]uint32)(unsafe.Pointer(uintptr(0x50020000)))
	for i := range usbRAM {
		usbRAM[i] = 0
	}

	// Clear GCCFG
	ureg(USB_GCCFG).Set(0)

	// Select full-speed PHY
	ureg(USB_GUSBCFG).SetBits(1 << 6) // PHYSEL

	// Wait for AHB idle
	for ureg(USB_GRSTCTL).Get()&(1<<31) == 0 {
	}

	// Core soft reset
	ureg(USB_GRSTCTL).SetBits(1 << 0) // CSRST
	for ureg(USB_GRSTCTL).Get()&(1<<0) != 0 {
	}

	usbDelay(100000)

	// Force device mode
	ureg(USB_GUSBCFG).SetBits(1 << 30)   // FDMOD
	ureg(USB_GUSBCFG).SetBits(0xF << 10) // TRDT = 15
	cfg := ureg(USB_GUSBCFG).Get()
	cfg &^= 0x3F << 0 // Clear TOCAL
	cfg |= 0x01 << 0  // TOCAL = 1
	ureg(USB_GUSBCFG).Set(cfg)

	// Configure GCCFG for VBUS sensing
	cid := ureg(USB_CID).Get()
	if cid >= 0x00001200 {
		ureg(USB_GCCFG).Set((1 << 21) | (1 << 16)) // VBDEN | PWRDWN
	} else {
		ureg(USB_GCCFG).Set((1 << 19) | (1 << 16)) // VBUSBSEN | PWRDWN
	}

	// Enable DP pull-up
	dctl := ureg(USB_DCTL).Get()
	dctl &^= (1 << 1) // Clear SDIS
	ureg(USB_DCTL).Set(dctl)

	// Set device speed to full-speed
	dcfg := ureg(USB_DCFG).Get()
	dcfg |= 0x3 // DSPD = 11 (full speed)
	ureg(USB_DCFG).Set(dcfg)

	// Restart PHY clock
	ureg(USB_PCGCCTL).Set(0)

	// Configure FIFO sizes
	// RX FIFO: 128 words (512 bytes) at offset 0
	ureg(USB_GRXFSIZ).Set(128)
	// TX FIFO 0 (EP0): 64 words at offset 128
	ureg(USB_HNPTXFSIZ).Set((64 << 16) | 128)
	// TX FIFO 1 (EP1): 64 words at offset 192
	ureg(USB_DIEPTXF1).Set((64 << 16) | 192)

	// Clear all pending interrupts
	ureg(USB_GINTSTS).Set(0xFFFFFFFF)

	// Unmask USB interrupts (matching C firmware exactly)
	// NO USBRST - C firmware only uses ENUMDNEM
	// NO OEPINT - C firmware doesn't mask OUT endpoint interrupts
	ureg(USB_GINTMSK).Set(
		(1 << 13) | // ENUMDNEM
			(1 << 4) | // RXFLVL
			(1 << 18) | // IEPINT (IN endpoint)
			(1 << 11) | // USBSUSP
			(1 << 31)) // WUIM (wake-up interrupt)

	// Enable endpoint interrupts - C firmware uses 0xF (IN endpoints only)
	ureg(USB_DAINTMSK).Set(0xF) // EP0-EP3 IN only

	// Enable IN endpoint interrupt mask - C firmware only sets XFRCM
	ureg(USB_DIEPMSK).Set(1 << 0) // XFRCM only
	// C firmware doesn't set DOEPMSK at all

	// Enable global USB interrupt
	ureg(USB_GAHBCFG).SetBits(1 << 0) // GINTMSK

	// Setup EP0 for control transfers
	setupEP0()
}

// setupEP0 sets up EP0 for control transfers
func setupEP0() {
	// EP0 OUT: Enable, set max packet size = 64
	ureg(USB_DOEPTSIZ0).Set((1 << 29) | (1 << 19) | 64) // STUPCNT=1, PKTCNT=1, XFRSIZ=64
	ureg(USB_DOEPCTL0).Set((1 << 31) | (1 << 26) | 0)   // EPENA, CNAK, MPSIZ=64
}

// setupEP1 sets up EP1 for HID IN/OUT
func setupEP1() {
	// EP1 IN (device to host)
	// Type = Interrupt (11), Max packet = 64
	ureg(USB_DIEPCTL1).Set(
		(1 << 28) | // SD0PID (set DATA0 PID)
			(1 << 15) | // USBAEP (active)
			(3 << 18) | // EPTYP = Interrupt
			(1 << 22) | // TXFNUM = 1
			64) // MPSIZ = 64

	// EP1 OUT (host to device)
	// Type = Interrupt (11), Max packet = 64
	ureg(USB_DOEPTSIZ1).Set((1 << 19) | 64) // PKTCNT=1, XFRSIZ=64
	ureg(USB_DOEPCTL1).Set(
		(1 << 31) | // EPENA
			(1 << 28) | // SD0PID (set DATA0 PID for interrupt endpoint)
			(1 << 26) | // CNAK
			(1 << 15) | // USBAEP
			(3 << 18) | // EPTYP = Interrupt
			64) // MPSIZ = 64
}

// usbDevicePoll polls USB device for events
// Matches C firmware's stm32fx07_poll exactly
func usbDevicePoll() {
	gintsts := ureg(USB_GINTSTS).Get()

	if gintsts == 0 {
		return
	}

	// Enumeration done (also handles reset - C firmware pattern)
	if gintsts&(1<<13) != 0 {
		handleEnumDone()
		ureg(USB_GINTSTS).Set(1 << 13)
	}

	// RX FIFO non-empty - process all pending data
	for gintsts&(1<<4) != 0 {
		handleRxFifoNonEmpty()
		gintsts = ureg(USB_GINTSTS).Get()
	}

	// IN endpoint interrupt
	if gintsts&(1<<18) != 0 {
		handleInEndpoints()
	}

	// USB Suspend
	if gintsts&(1<<11) != 0 {
		ureg(USB_GINTSTS).Set(1 << 11)
	}

	// Wake-up
	if gintsts&(1<<31) != 0 {
		ureg(USB_GINTSTS).Set(1 << 31)
	}
}

// Debug counter for USB events
var usbDebugCounter uint8

// handleUSBReset handles USB bus reset
func handleUSBReset() {
	usbState = USBStateDefault
	usbAddress = 0
	usbConfigured = false
	pendingAddress = 0

	// Clear device address
	dcfg := ureg(USB_DCFG).Get()
	dcfg &^= (0x7F << 4)
	ureg(USB_DCFG).Set(dcfg)

	// Re-setup EP0
	setupEP0()

	// Debug: mark USB reset
	usbDebugCounter++
	// debugShowUSBEvent(1) // Reset - disabled for timing
}

// handleEnumDone handles enumeration complete (also acts as reset handler like C firmware)
func handleEnumDone() {
	// Reset state (like C firmware's _usbd_reset)
	usbState = USBStateDefault
	usbAddress = 0
	usbConfigured = false
	pendingAddress = 0

	// Clear device address
	dcfg := ureg(USB_DCFG).Get()
	dcfg &^= (0x7F << 4)
	ureg(USB_DCFG).Set(dcfg)

	// Setup EP0 for control transfers
	setupEP0()

	// Debug output (needed for timing!)
	debugShowUSBEvent(2)
}

// handleRxFifoNonEmpty handles RX FIFO non-empty
func handleRxFifoNonEmpty() {
	rxstsp := ureg(USB_GRXSTSP).Get()

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
	case 0x04, 0x03: // SETUP complete or OUT complete
		// Re-program DOEPTSIZ and re-enable endpoint for next packet
		// This is critical - must happen on completion event
		if epnum == 0 {
			ureg(USB_DOEPTSIZ0).Set((1 << 29) | (1 << 19) | 64) // STUPCNT=1, PKTCNT=1, XFRSIZ=64
			ureg(USB_DOEPCTL0).SetBits((1 << 31) | (1 << 26))   // EPENA | CNAK
		} else if epnum == 1 {
			// Re-enable EP1 OUT for next HID packet
			ureg(USB_DOEPTSIZ1).Set((1 << 19) | 64) // PKTCNT=1, XFRSIZ=64
			ureg(USB_DOEPCTL1).SetBits((1 << 31) | (1 << 26)) // EPENA | CNAK
		}
		return // Don't process further, like the C firmware does
	}
}

// Setup packet counter for compact display
var setupCount int

// readSetupPacket reads SETUP packet from FIFO
func readSetupPacket() {
	// Read 8 bytes (2 words) from FIFO
	w0 := ureg(USB_FIFO0).Get()
	w1 := ureg(USB_FIFO0).Get()

	setup := SetupPacket{
		bmRequestType: uint8(w0),
		bRequest:      uint8(w0 >> 8),
		wValue:        uint16(w0 >> 16),
		wIndex:        uint16(w1),
		wLength:       uint16(w1 >> 16),
	}

	// Debug: count SETUP packets
	setupCount++
	// debugShowSetupCount(setupCount) // Disabled for timing

	handleSetupPacket(&setup)
}

// handleSetupPacket handles a SETUP packet
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

// handleStandardRequest handles standard USB requests
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

// handleGetDescriptor handles GET_DESCRIPTOR request
func handleGetDescriptor(setup *SetupPacket) {
	descType := uint8(setup.wValue >> 8)
	maxLen := int(setup.wLength)

	// Debug: show descriptor type being requested
	// debugShowDescType(descType) // Disabled for timing

	switch descType {
	case USB_DT_DEVICE:
		sendDescriptor(deviceDescriptor[:], maxLen)

	case USB_DT_CONFIGURATION:
		sendDescriptor(configDescriptor[:], maxLen)

	case USB_DT_STRING:
		descIndex := uint8(setup.wValue)
		data := getStringDescriptor(descIndex)
		if data == nil {
			stallEP0()
			return
		}
		sendDescriptor(data, maxLen)

	case USB_DT_HID:
		sendDescriptor(configDescriptor[18:27], maxLen)

	case USB_DT_REPORT:
		sendDescriptor(hidReportDescriptor[:], maxLen)

	default:
		// debugShowUSBEvent(9) // Unknown descriptor - disabled for timing
		stallEP0()
	}
}

// sendDescriptor sends a descriptor, limiting to maxLen
func sendDescriptor(data []byte, maxLen int) {
	if len(data) > maxLen {
		data = data[:maxLen]
	}
	ep0SendData(data)
}

// handleSetAddress handles SET_ADDRESS request
// C firmware uses set_address_before_status = 1, meaning address is set IMMEDIATELY
func handleSetAddress(setup *SetupPacket) {
	addr := uint8(setup.wValue)

	// Set address IMMEDIATELY (before status ZLP) - matching C firmware
	dcfg := ureg(USB_DCFG).Get()
	dcfg &^= (0x7F << 4)       // Clear DAD field
	dcfg |= uint32(addr) << 4  // Set new address
	ureg(USB_DCFG).Set(dcfg)

	usbAddress = addr
	usbState = USBStateAddress

	// Debug: show we got address
	debugShowUSBEvent(5) // ADDR

	// Send ZLP status (address already set)
	ep0SendZLP()
}

// handleSetConfiguration handles SET_CONFIGURATION request
func handleSetConfiguration(setup *SetupPacket) {
	config := uint8(setup.wValue)

	if config == 0 {
		usbConfigured = false
	} else if config == 1 {
		usbConfigured = true
		usbState = USBStateConfigured

		// Setup HID endpoints
		setupEP1()

		// Debug: show config done
		debugShowUSBEvent(13) // CFG
	} else {
		stallEP0()
		return
	}

	ep0SendZLP()
}

// handleClassRequest handles HID class requests
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

// ep0SendData sends data on EP0
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

// ep0SendNextChunk sends the next chunk on EP0
func ep0SendNextChunk() {
	remaining := ep0TxLen - ep0TxOffset
	if remaining <= 0 {
		return
	}

	chunkSize := remaining
	if chunkSize > 64 {
		chunkSize = 64
	}

	// Debug: mark sending data
	// debugShowUSBEvent(4) // Disabled for timing

	// Configure EP0 IN
	ureg(USB_DIEPTSIZ0).Set((1 << 19) | uint32(chunkSize)) // PKTCNT=1, XFRSIZ

	// Enable EP0 IN
	ureg(USB_DIEPCTL0).Set(ureg(USB_DIEPCTL0).Get() | (1 << 31) | (1 << 26)) // EPENA, CNAK

	// Write data to FIFO
	words := (chunkSize + 3) / 4
	for i := 0; i < words; i++ {
		var w uint32
		for j := 0; j < 4 && ep0TxOffset+i*4+j < ep0TxLen; j++ {
			w |= uint32(ep0TxBuf[ep0TxOffset+i*4+j]) << (j * 8)
		}
		ureg(USB_FIFO0).Set(w)
	}

	ep0TxOffset += chunkSize
}

// ep0SendZLP sends a Zero-Length Packet on EP0
func ep0SendZLP() {
	ureg(USB_DIEPTSIZ0).Set((1 << 19) | 0)                                   // PKTCNT=1, XFRSIZ=0
	ureg(USB_DIEPCTL0).Set(ureg(USB_DIEPCTL0).Get() | (1 << 31) | (1 << 26)) // EPENA, CNAK
}

// stallEP0 stalls EP0
func stallEP0() {
	ureg(USB_DIEPCTL0).SetBits(1 << 21) // STALL
	ureg(USB_DOEPCTL0).SetBits(1 << 21) // STALL
}

// readEP0Data reads EP0 data
func readEP0Data(bcnt int) {
	// Read and discard (we don't expect OUT data on EP0 for HID)
	words := (bcnt + 3) / 4
	for i := 0; i < words; i++ {
		_ = ureg(USB_FIFO0).Get()
	}
}

// readEP1Data reads EP1 data (HID packet)
func readEP1Data(bcnt int) {
	// Debug: show EP1 data received with byte count
	debugShowUSBEvent(12) // HID - shows we got EP1 data

	if bcnt != 64 {
		// Invalid HID packet size - still need to drain FIFO
		words := (bcnt + 3) / 4
		for i := 0; i < words; i++ {
			_ = ureg(USB_FIFO0).Get() // All RX data comes through FIFO0
		}
		return
	}

	// Read 64 bytes from shared RX FIFO (FIFO0)
	for i := 0; i < 16; i++ {
		w := ureg(USB_FIFO0).Get() // All RX data comes through FIFO0
		ep1RxBuf[i*4+0] = uint8(w)
		ep1RxBuf[i*4+1] = uint8(w >> 8)
		ep1RxBuf[i*4+2] = uint8(w >> 16)
		ep1RxBuf[i*4+3] = uint8(w >> 24)
	}

	ep1RxReady = true
	// Note: EP1 OUT will be re-enabled in the OUT_COMP handler (pktsts=0x03)
}

// handleInEndpoints handles IN endpoint interrupts
func handleInEndpoints() {
	daint := ureg(USB_DAINT).Get()

	// EP0 IN
	if daint&(1<<0) != 0 {
		diepint := ureg(USB_DIEPINT0).Get()

		if diepint&(1<<0) != 0 { // Transfer complete
			// Send more data if pending
			if ep0TxOffset < ep0TxLen {
				ep0SendNextChunk()
			} else {
				// Transfer complete, re-enable EP0 OUT for status/next SETUP
				setupEP0()
			}
		}

		ureg(USB_DIEPINT0).Set(diepint) // Clear interrupts
	}

	// EP1 IN
	if daint&(1<<1) != 0 {
		diepint := ureg(USB_DIEPINT1).Get()

		if diepint&(1<<0) != 0 { // Transfer complete
			ep1TxPending = false
			debugShowUSBEvent(15) // DONE
		}

		ureg(USB_DIEPINT1).Set(diepint)
	}
}

// handleOutEndpoints handles OUT endpoint interrupts
func handleOutEndpoints() {
	daint := ureg(USB_DAINT).Get()

	// EP0 OUT
	if daint&(1<<16) != 0 {
		doepint := ureg(USB_DOEPINT0).Get()

		if doepint&(1<<3) != 0 { // SETUP done
			// Re-enable EP0 OUT for next SETUP
			setupEP0()
		}

		ureg(USB_DOEPINT0).Set(doepint)
	}

	// EP1 OUT
	if daint&(1<<17) != 0 {
		doepint := ureg(USB_DOEPINT1).Get()

		if doepint&(1<<0) != 0 { // Transfer complete
			// Re-enable EP1 OUT
			ureg(USB_DOEPTSIZ1).Set((1 << 19) | 64)
			ureg(USB_DOEPCTL1).Set(ureg(USB_DOEPCTL1).Get() | (1 << 31) | (1 << 26))
		}

		ureg(USB_DOEPINT1).Set(doepint)
	}
}

// ep1SendPacket sends HID packet on EP1 IN
func ep1SendPacket(data *[64]byte) bool {
	if ep1TxPending || !usbConfigured {
		return false
	}

	// Configure EP1 IN transfer size
	ureg(USB_DIEPTSIZ1).Set((1 << 19) | 64) // PKTCNT=1, XFRSIZ=64

	// Enable endpoint FIRST (matching C firmware order)
	ureg(USB_DIEPCTL1).SetBits((1 << 31) | (1 << 26)) // EPENA, CNAK

	// Then write data to FIFO
	for i := 0; i < 16; i++ {
		w := uint32(data[i*4+0]) |
			uint32(data[i*4+1])<<8 |
			uint32(data[i*4+2])<<16 |
			uint32(data[i*4+3])<<24
		ureg(USB_FIFO1).Set(w)
	}

	ep1TxPending = true

	// Debug: show we sent a packet
	debugShowUSBEvent(14) // TX

	return true
}

// ep1HasPacket checks if HID packet is available
func ep1HasPacket() bool {
	return ep1RxReady
}

// ep1GetPacket gets received HID packet
func ep1GetPacket() *[64]byte {
	if !ep1RxReady {
		return nil
	}
	ep1RxReady = false
	return &ep1RxBuf
}

// isConfigured checks if device is configured
func isConfigured() bool {
	return usbConfigured
}
