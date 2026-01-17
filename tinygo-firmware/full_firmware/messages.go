package main

// Message buffer sizes
const (
	MsgInSize   = 12 * 1024       // 12KB input buffer
	MsgOutSize  = 12 * 1024       // 12KB output buffer
	MsgOutSlots = MsgOutSize / 64 // Number of 64-byte slots
)

// Read state machine states
const (
	ReadStateIdle = iota
	ReadStateReading
)

// Message reader for reassembling multi-packet messages
type MsgReader struct {
	state   int
	msgID   uint16
	msgSize uint32
	msgPos  uint32
	buffer  [MsgInSize]byte
}

// Message writer with circular buffer for output
type MsgWriter struct {
	buffer [MsgOutSize]byte
	start  uint32 // Start of data (read position)
	end    uint32 // End of data (write position)
	cur    uint32 // Current position within 64-byte slot
}

// Global message reader and writer
var (
	msgReader MsgReader
	msgWriter MsgWriter
)

// ReadPacket processes a 64-byte USB HID packet
// Returns true if a complete message is ready
func (r *MsgReader) ReadPacket(buf *[64]byte) bool {
	if r.state == ReadStateIdle {
		// Expecting start of new message
		if buf[0] != '?' || buf[1] != '#' || buf[2] != '#' {
			// Invalid start, discard
			return false
		}

		// Parse header
		r.msgID = uint16(buf[3])<<8 | uint16(buf[4])
		r.msgSize = uint32(buf[5])<<24 | uint32(buf[6])<<16 | uint32(buf[7])<<8 | uint32(buf[8])

		// Validate message size
		if r.msgSize > MsgInSize {
			println("Message too big:", r.msgSize)
			return false
		}

		// Copy initial payload (bytes 9-63 = 55 bytes)
		r.msgPos = 0
		for i := 9; i < 64 && r.msgPos < r.msgSize; i++ {
			r.buffer[r.msgPos] = buf[i]
			r.msgPos++
		}

		if r.msgPos >= r.msgSize {
			// Complete message in single packet
			return true
		}

		r.state = ReadStateReading
		return false
	}

	// ReadStateReading - continuation packet
	if buf[0] != '?' {
		// Invalid continuation, reset
		r.state = ReadStateIdle
		return false
	}

	// Copy payload (bytes 1-63 = 63 bytes)
	for i := 1; i < 64 && r.msgPos < r.msgSize; i++ {
		r.buffer[r.msgPos] = buf[i]
		r.msgPos++
	}

	if r.msgPos >= r.msgSize {
		// Message complete
		r.state = ReadStateIdle
		return true
	}

	return false
}

// GetMessage returns the message ID and payload after ReadPacket returns true
func (r *MsgReader) GetMessage() (uint16, []byte) {
	return r.msgID, r.buffer[:r.msgSize]
}

// Reset clears the reader state
func (r *MsgReader) Reset() {
	r.state = ReadStateIdle
	r.msgPos = 0
}

// append adds a byte to the output buffer
func (w *MsgWriter) append(c byte) {
	if w.cur == 0 {
		// Start new packet with '?'
		w.buffer[w.end*64] = '?'
		w.cur = 1
	}
	w.buffer[w.end*64+w.cur] = c
	w.cur++
	if w.cur == 64 {
		// Packet full, advance to next slot
		w.cur = 0
		w.end = (w.end + 1) % MsgOutSlots
	}
}

// pad fills the rest of the current packet with zeros
func (w *MsgWriter) pad() {
	if w.cur == 0 {
		return
	}
	for w.cur < 64 {
		w.buffer[w.end*64+w.cur] = 0
		w.cur++
	}
	w.cur = 0
	w.end = (w.end + 1) % MsgOutSlots
}

// WriteMessage writes a message with the wire protocol framing
// Format: '?' '#' '#' + msg_id (2 bytes BE) + length (4 bytes BE) + payload
func (w *MsgWriter) WriteMessage(msgID uint16, payload []byte) {
	// Write header marker (in place of first '?')
	// Actually the first byte of first packet is '?', then ## comes
	// Looking at the C code more carefully:
	// First packet: ? ## msg_id(2) length(4) payload
	// So append writes: # # msg_id_hi msg_id_lo len[3] len[2] len[1] len[0] payload...

	w.append('#')
	w.append('#')
	w.append(byte(msgID >> 8))
	w.append(byte(msgID))

	length := uint32(len(payload))
	w.append(byte(length >> 24))
	w.append(byte(length >> 16))
	w.append(byte(length >> 8))
	w.append(byte(length))

	// Write payload
	for _, b := range payload {
		w.append(b)
	}

	// Pad to 64-byte boundary
	w.pad()
}

// HasData returns true if there are packets to send
func (w *MsgWriter) HasData() bool {
	return w.start != w.end
}

// NextPacket returns the next 64-byte packet to send
// Returns nil if no data available
func (w *MsgWriter) NextPacket() *[64]byte {
	if w.start == w.end {
		return nil
	}

	// Get pointer to the packet
	offset := w.start * 64
	packet := (*[64]byte)(w.buffer[offset : offset+64])

	// Advance start pointer
	w.start = (w.start + 1) % MsgOutSlots

	// Return a copy to avoid data races
	var result [64]byte
	copy(result[:], packet[:])
	return &result
}

// Clear resets the writer
func (w *MsgWriter) Clear() {
	w.start = 0
	w.end = 0
	w.cur = 0
}

// Helper function to send a message via the global writer
func msgWrite(msgID uint16, payload []byte) {
	msgWriter.WriteMessage(msgID, payload)
}

// Process incoming USB packets and dispatch messages
func msgPoll() {
	// Check for incoming HID packet
	if ep1HasPacket() {
		packet := ep1GetPacket()
		if packet != nil {
			// Process packet
			if msgReader.ReadPacket(packet) {
				// Complete message received
				msgID, data := msgReader.GetMessage()
				println("Message received: ID=", msgID, "len=", len(data))

				// Dispatch to handler
				dispatchMessage(msgID, data)
			}
		}
	}

	// Send outgoing packets
	if msgWriter.HasData() {
		packet := msgWriter.NextPacket()
		if packet != nil {
			if ep1SendPacket(packet) {
				println("Sent packet")
			}
		}
	}
}
