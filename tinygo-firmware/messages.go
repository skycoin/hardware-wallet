package main

// Message protocol constants
const (
	MSG_HEADER_MAGIC = 0x3F2323 // "?##"
	MSG_IN_SIZE      = 4096     // Max incoming message size
	MSG_OUT_SIZE     = 12288    // Output buffer size (12KB)
)

// Message type IDs (from protobuf definitions)
const (
	MessageType_Initialize      uint16 = 0
	MessageType_Ping            uint16 = 1
	MessageType_Success         uint16 = 2
	MessageType_Failure         uint16 = 3
	MessageType_ChangePin       uint16 = 4
	MessageType_WipeDevice      uint16 = 5
	MessageType_GetEntropy      uint16 = 9
	MessageType_Entropy         uint16 = 10
	MessageType_LoadDevice      uint16 = 13
	MessageType_ResetDevice     uint16 = 14
	MessageType_Features        uint16 = 17
	MessageType_PinMatrixRequest uint16 = 18
	MessageType_PinMatrixAck    uint16 = 19
	MessageType_Cancel          uint16 = 20
	MessageType_ApplySettings   uint16 = 25
	MessageType_ButtonRequest   uint16 = 26
	MessageType_ButtonAck       uint16 = 27
	MessageType_BackupDevice    uint16 = 34
	MessageType_EntropyRequest  uint16 = 35
	MessageType_EntropyAck      uint16 = 36
	MessageType_RecoveryDevice  uint16 = 45
	MessageType_WordRequest     uint16 = 46
	MessageType_WordAck         uint16 = 47
	MessageType_GetFeatures     uint16 = 55
	MessageType_SetMnemonic                uint16 = 113
	MessageType_SkycoinAddress             uint16 = 114
	MessageType_SkycoinCheckMessageSignature uint16 = 115
	MessageType_SkycoinSignMessage         uint16 = 116
	MessageType_ResponseSkycoinAddress     uint16 = 117
	MessageType_ResponseSkycoinSignMessage uint16 = 118
	MessageType_GenerateMnemonic           uint16 = 119
	MessageType_TransactionSign            uint16 = 122
	MessageType_ResponseTransactionSign    uint16 = 123
)

// Message read state
const (
	READSTATE_IDLE = iota
	READSTATE_READING
)

// Incoming message buffer
var (
	msgReadState  int
	msgInBuffer   [MSG_IN_SIZE]byte
	msgInID       uint16
	msgInSize     uint32
	msgInPos      uint32
)

// Outgoing message circular buffer
var (
	msgOutBuffer [MSG_OUT_SIZE]byte
	msgOutStart  uint32 // Read position (in 64-byte packets)
	msgOutEnd    uint32 // Write position (in 64-byte packets)
	msgOutCur    uint32 // Current position within packet being written
)

// msgReadPacket processes a 64-byte HID packet
// Returns true if a complete message is ready for processing
func msgReadPacket(pkt *[64]byte) bool {
	if msgReadState == READSTATE_IDLE {
		// Check for valid header: ?##
		if pkt[0] != '?' || pkt[1] != '#' || pkt[2] != '#' {
			return false
		}

		// Parse message ID (big-endian)
		msgInID = uint16(pkt[3])<<8 | uint16(pkt[4])

		// Parse message size (big-endian)
		msgInSize = uint32(pkt[5])<<24 | uint32(pkt[6])<<16 | uint32(pkt[7])<<8 | uint32(pkt[8])

		// Validate size
		if msgInSize > MSG_IN_SIZE {
			// Message too big - send failure
			sendFailure(1, "Message too big")
			return false
		}

		// Copy payload from first packet (bytes 9-63 = 55 bytes)
		copyLen := uint32(55)
		if copyLen > msgInSize {
			copyLen = msgInSize
		}
		for i := uint32(0); i < copyLen; i++ {
			msgInBuffer[i] = pkt[9+i]
		}
		msgInPos = copyLen

		if msgInPos >= msgInSize {
			// Complete message in single packet
			msgReadState = READSTATE_IDLE
			return true
		}

		msgReadState = READSTATE_READING
		return false
	}

	// READSTATE_READING - continuation packet
	// Check for continuation marker
	if pkt[0] != '?' {
		// Invalid continuation - reset
		msgReadState = READSTATE_IDLE
		return false
	}

	// Copy payload (bytes 1-63 = 63 bytes)
	remaining := msgInSize - msgInPos
	copyLen := uint32(63)
	if copyLen > remaining {
		copyLen = remaining
	}
	for i := uint32(0); i < copyLen; i++ {
		msgInBuffer[msgInPos+i] = pkt[1+i]
	}
	msgInPos += copyLen

	if msgInPos >= msgInSize {
		// Complete message
		msgReadState = READSTATE_IDLE
		return true
	}

	return false
}

// msgOutAppend appends a byte to the output buffer
func msgOutAppend(b byte) {
	if msgOutCur == 0 {
		// Start new packet with '?' marker
		msgOutBuffer[msgOutEnd*64] = '?'
		msgOutCur = 1
	}
	msgOutBuffer[msgOutEnd*64+msgOutCur] = b
	msgOutCur++
	if msgOutCur == 64 {
		msgOutCur = 0
		msgOutEnd = (msgOutEnd + 1) % (MSG_OUT_SIZE / 64)
	}
}

// msgOutPad pads current packet to 64 bytes
func msgOutPad() {
	if msgOutCur == 0 {
		return
	}
	for msgOutCur < 64 {
		msgOutBuffer[msgOutEnd*64+msgOutCur] = 0
		msgOutCur++
	}
	msgOutCur = 0
	msgOutEnd = (msgOutEnd + 1) % (MSG_OUT_SIZE / 64)
}

// msgWrite writes a message to the output buffer
func msgWrite(msgID uint16, data []byte) {
	dataLen := uint32(len(data))

	// Write header: ##
	msgOutAppend('#')
	msgOutAppend('#')

	// Write message ID (big-endian)
	msgOutAppend(byte(msgID >> 8))
	msgOutAppend(byte(msgID))

	// Write length (big-endian)
	msgOutAppend(byte(dataLen >> 24))
	msgOutAppend(byte(dataLen >> 16))
	msgOutAppend(byte(dataLen >> 8))
	msgOutAppend(byte(dataLen))

	// Write payload
	for i := uint32(0); i < dataLen; i++ {
		msgOutAppend(data[i])
	}

	// Pad final packet
	msgOutPad()
}

// msgHasPendingOutput returns true if there are packets to send
func msgHasPendingOutput() bool {
	return msgOutStart != msgOutEnd
}

// msgGetNextPacket gets the next output packet (returns nil if none)
func msgGetNextPacket() *[64]byte {
	if msgOutStart == msgOutEnd {
		return nil
	}

	offset := msgOutStart * 64
	msgOutStart = (msgOutStart + 1) % (MSG_OUT_SIZE / 64)

	return (*[64]byte)(msgOutBuffer[offset : offset+64])
}

// sendSuccess sends a Success message
func sendSuccess(message string) {
	var buf [128]byte
	n := pbEncodeSuccess(buf[:], message)
	msgWrite(MessageType_Success, buf[:n])
}

// sendFailure sends a Failure message
func sendFailure(code uint32, message string) {
	var buf [128]byte
	n := pbEncodeFailure(buf[:], code, message)
	msgWrite(MessageType_Failure, buf[:n])
}
