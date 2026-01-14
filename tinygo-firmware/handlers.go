package main

// Global buffer for encoding protobuf messages (avoid stack overflow)
var pbEncodeBuf [512]byte

// PIN state machine
const (
	PIN_STATE_IDLE = iota
	PIN_STATE_VERIFY
	PIN_STATE_CHANGE_OLD
	PIN_STATE_CHANGE_NEW1
	PIN_STATE_CHANGE_NEW2
)

var pinState = PIN_STATE_IDLE
var pinNewFirst [10]byte
var pinNewFirstLen int

// Mnemonic generation state machine
const (
	MNEMONIC_STATE_IDLE = iota
	MNEMONIC_STATE_WAIT_ENTROPY
	MNEMONIC_STATE_BACKUP
)

var mnemonicState = MNEMONIC_STATE_IDLE
var mnemonicWordCount = 12
var mnemonicBackupIndex = 0
var pendingMnemonic [512]byte // Buffer for generated mnemonic
var pendingMnemonicLen = 0

// dispatchMessage handles an incoming message based on its type
func dispatchMessage() {
	debugShowMsgID(msgInID)
	// Also show first 8 bytes of payload for debugging
	debugShowPayload(msgInBuffer[:], msgInSize)
	switch msgInID {
	case MessageType_Initialize:
		handleInitialize()

	case MessageType_GetFeatures:
		handleGetFeatures()

	case MessageType_Ping:
		handlePing()

	case MessageType_ChangePin:
		handleChangePin()

	case MessageType_PinMatrixAck:
		handlePinMatrixAck()

	case MessageType_Cancel:
		handleCancel()

	case MessageType_WipeDevice:
		handleWipeDevice()

	case MessageType_GenerateMnemonic:
		handleGenerateMnemonic()

	case MessageType_SetMnemonic:
		handleSetMnemonic()

	case MessageType_GetEntropy:
		handleGetEntropy()

	case MessageType_EntropyAck:
		handleEntropyAck()

	case MessageType_BackupDevice:
		handleBackupDevice()

	case MessageType_ButtonAck:
		handleButtonAck()

	case MessageType_RecoveryDevice:
		handleRecoveryDevice()

	case MessageType_WordAck:
		handleWordAck()

	case MessageType_SkycoinAddress:
		handleSkycoinAddress()

	case MessageType_SkycoinSignMessage:
		handleSkycoinSignMessage()

	case MessageType_TransactionSign:
		handleTransactionSign()

	case MessageType_SkycoinCheckMessageSignature:
		handleSkycoinCheckMessageSignature()

	case MessageType_ApplySettings:
		handleApplySettings()

	default:
		// Unknown message type
		sendFailure(FailureType_UnexpectedMessage, "Unknown message")
	}
}

// hexDigit converts 0-15 to hex char
func hexDigit(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'A' + n - 10
}

// debugShowPayload shows first bytes of message payload
func debugShowPayload(data []byte, size uint32) {
	// Display on line 24 and 34 (below msgID debug)
	x := 0
	y := 24
	// Show size
	oledDrawChar(x, y, 'S')
	x += oledDrawChar(x, y, 'z')
	x += oledDrawChar(x, y, ':')
	val := int(size)
	if val == 0 {
		x += oledDrawChar(x, y, '0')
	} else {
		var digits [5]byte
		dpos := 4
		for val > 0 && dpos >= 0 {
			digits[dpos] = '0' + byte(val%10)
			val /= 10
			dpos--
		}
		for i := dpos + 1; i <= 4; i++ {
			x += oledDrawChar(x, y, digits[i])
		}
	}
	// Show first 8 bytes of payload as hex
	y = 34
	x = 0
	showLen := 8
	if int(size) < showLen {
		showLen = int(size)
	}
	for i := 0; i < showLen; i++ {
		x += oledDrawChar(x, y, hexDigit(data[i]>>4))
		x += oledDrawChar(x, y, hexDigit(data[i]&0xF))
	}
	oledRefresh()
}

// debugShowMsgID shows the message ID on display using direct char output
func debugShowMsgID(id uint16) {
	oledClear()
	// Draw "ID:" manually
	x := 0
	x += oledDrawChar(x, 0, 'I')
	x += oledDrawChar(x, 0, 'D')
	x += oledDrawChar(x, 0, ':')
	// Draw hex value
	x += oledDrawChar(x, 0, '0')
	x += oledDrawChar(x, 0, 'x')
	x += oledDrawChar(x, 0, hexDigit(byte(id>>12)&0xF))
	x += oledDrawChar(x, 0, hexDigit(byte(id>>8)&0xF))
	x += oledDrawChar(x, 0, hexDigit(byte(id>>4)&0xF))
	x += oledDrawChar(x, 0, hexDigit(byte(id)&0xF))
	// Draw decimal on second line
	x = 0
	x += oledDrawChar(x, 10, '(')
	// Convert to decimal digits manually
	val := int(id)
	if val == 0 {
		x += oledDrawChar(x, 10, '0')
	} else {
		var digits [5]byte
		dpos := 4
		for val > 0 && dpos >= 0 {
			digits[dpos] = '0' + byte(val%10)
			val /= 10
			dpos--
		}
		for i := dpos + 1; i <= 4; i++ {
			x += oledDrawChar(x, 10, digits[i])
		}
	}
	x += oledDrawChar(x, 10, ')')
	oledRefresh()
}

// handleInitialize handles the Initialize message
// This is sent when the host first connects to get device info
func handleInitialize() {
	// Clear any session state (none for now)

	// Respond with Features
	handleGetFeatures()
}

// handleGetFeatures handles the GetFeatures message
func handleGetFeatures() {
	// Use global buffer to avoid stack overflow
	n := pbEncodeFeatures(pbEncodeBuf[:])
	msgWrite(MessageType_Features, pbEncodeBuf[:n])
}

// debugShowOutBytes shows first bytes of output buffer (disabled)
func debugShowOutBytes() {
}

// debugShowPayloadSize shows the protobuf payload size (disabled)
func debugShowPayloadSize(size int) {
	_ = size
}

// handlePing handles the Ping message
// Supports test commands when message starts with "TEST:"
func handlePing() {
	// Decode the ping message to get the echo bytes (NOT string!)
	message := pbDecodePingBytes(msgInBuffer[:msgInSize])

	// Debug: show message length and first 5 chars on OLED
	oledClear()
	oledDrawString(0, 0, "MSG:")
	oledDrawChar(32, 0, '0'+byte(len(message)/10))
	oledDrawChar(40, 0, '0'+byte(len(message)%10))
	// Show first 5 bytes
	for i := 0; i < 5 && i < len(message); i++ {
		oledDrawChar(i*8, 10, message[i])
	}
	oledRefresh()
	usbDelay(2000000)

	// Check for test commands - use byte comparison
	if len(message) > 5 {
		isTest := message[0] == 'T' && message[1] == 'E' && message[2] == 'S' && message[3] == 'T' && message[4] == ':'
		if isTest {
			handleTestCommandBytes(message[5:])
			return
		}
	}

	// Echo the message back using byte slice (no string conversion!)
	sendSuccessBytes(message)
}

// Response buffer for test commands - avoids string allocation
var testResultBuf [128]byte

// Byte slice literals for test command prefixes
// Using byte slices instead of strings to avoid any string operations in TinyGo
var (
	prefixSHA256  = []byte{'S', 'H', 'A', '2', '5', '6', ':'}
	prefixRIPEMD  = []byte{'R', 'I', 'P', 'E', 'M', 'D', ':'}
	prefixB58     = []byte{'B', '5', '8', ':'}
	prefixSQR     = []byte{'S', 'Q', 'R', ':'}
	prefixMUL     = []byte{'M', 'U', 'L', ':'}
	prefixPK1     = []byte{'P', 'K', '1', ':'}
	prefixPK2     = []byte{'P', 'K', '2', ':'}
	prefixECMULT  = []byte{'E', 'C', 'M', 'U', 'L', 'T', ':'}
	prefixECINF   = []byte{'E', 'C', 'M', 'U', 'L', 'T', ':', 'I', 'N', 'F'}
	prefixGPOINT  = []byte{'G', 'P', 'O', 'I', 'N', 'T', ':'}
	prefixADDR    = []byte{'A', 'D', 'D', 'R', ':'}
	prefixADDRF   = []byte{'A', 'D', 'D', 'R', ':', 'F', 'A', 'I', 'L'}
	prefixUNKNOWN = []byte{'U', 'N', 'K', 'N', 'O', 'W', 'N', ':'}
	// Debug test pattern - "ABCD1234" in bytes
	debugPattern  = []byte{'A', 'B', 'C', 'D', '1', '2', '3', '4'}
)

// copyBytes copies a byte slice into buf, returns bytes written
func copyBytes(buf []byte, src []byte) int {
	for i := 0; i < len(src); i++ {
		buf[i] = src[i]
	}
	return len(src)
}

// hexCharsBytes is used for hex encoding without string operations
var hexCharsBytes = []byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}

// copyHexBytes writes hex encoding of data into buf, returns bytes written
func copyHexBytes(buf []byte, data []byte) int {
	n := len(data)
	if n > 32 {
		n = 32
	}
	for i := 0; i < n; i++ {
		buf[i*2] = hexCharsBytes[data[i]>>4]
		buf[i*2+1] = hexCharsBytes[data[i]&0x0f]
	}
	return n * 2
}

// copyFieldHex writes hex encoding of field's low 32 bits into buf
func copyFieldHex(buf []byte, f *Field) int {
	val := f.n[0]
	for i := 7; i >= 0; i-- {
		buf[i] = hexCharsBytes[val&0x0f]
		val >>= 4
	}
	return 8
}

// bytesEqual compares two byte slices for equality
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Test command names as byte slices (no string conversion needed)
var (
	cmdDEBUG   = []byte{'D', 'E', 'B', 'U', 'G'}
	cmdLITERAL = []byte{'L', 'I', 'T', 'E', 'R', 'A', 'L'}
	cmdA       = []byte{'A'}
	cmdABC     = []byte{'A', 'B', 'C'}
	cmdRAW     = []byte{'R', 'A', 'W'}
	cmdDIRECT  = []byte{'D', 'I', 'R', 'E', 'C', 'T'}
	cmdECHO    = []byte{'E', 'C', 'H', 'O'}
	cmdFIXED   = []byte{'F', 'I', 'X', 'E', 'D'}
	cmdSHA256  = []byte{'S', 'H', 'A', '2', '5', '6'}
	cmdRIPEMD  = []byte{'R', 'I', 'P', 'E', 'M', 'D'}
	cmdB58     = []byte{'B', '5', '8'}
	cmdSQR     = []byte{'S', 'Q', 'R'}
	cmdMUL     = []byte{'M', 'U', 'L'}
	cmdPUBKEY1 = []byte{'P', 'U', 'B', 'K', 'E', 'Y', '1'}
	cmdPUBKEY2 = []byte{'P', 'U', 'B', 'K', 'E', 'Y', '2'}
	cmdECMULT  = []byte{'E', 'C', 'M', 'U', 'L', 'T'}
	cmdGPOINT  = []byte{'G', 'P', 'O', 'I', 'N', 'T'}
	cmdADDR    = []byte{'A', 'D', 'D', 'R'}
)

// handleTestCommandBytes runs crypto test commands using byte slice input
// Commands:
//   SHA256 - SHA256("abc"), expect ba7816bf...
//   RIPEMD - RIPEMD160("abc"), expect 8eb208f7...
//   B58    - Base58Check([0x00,0x00...]), expect 1111...
//   PUBKEY1 - pubkey from seckey=1, expect G point
//   PUBKEY2 - pubkey from seckey=2
//   SQR    - square 2, expect 4
//   MUL    - multiply 3*5, expect 15
//   ADDR   - address from test mnemonic
func handleTestCommandBytes(cmd []byte) {
	n := 0 // position in testResultBuf

	if bytesEqual(cmd, cmdDEBUG) {
		// Simple debug test - return fixed pattern "ABCD1234"
		n += copyBytes(testResultBuf[n:], debugPattern)
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdLITERAL) {
		// Test using sendSuccess with literal string (bypasses byte buffer)
		sendSuccess("LITERAL:OK")
		return
	}

	if bytesEqual(cmd, cmdA) {
		// Single byte test
		testResultBuf[0] = 'A'
		sendSuccessBytes(testResultBuf[:1])
		return
	}

	if bytesEqual(cmd, cmdABC) {
		// Three byte test
		testResultBuf[0] = 'A'
		testResultBuf[1] = 'B'
		testResultBuf[2] = 'C'
		sendSuccessBytes(testResultBuf[:3])
		return
	}

	if bytesEqual(cmd, cmdRAW) {
		// Raw bytes sent directly via msgWrite - bypass all encoding
		// Send 4 bytes: 0x12, 0x02, 0x41, 0x42 = protobuf field 2, len 2, "AB"
		var rawBuf [4]byte
		rawBuf[0] = 0x12 // field 2, wire type 2
		rawBuf[1] = 0x02 // length 2
		rawBuf[2] = 0x41 // 'A'
		rawBuf[3] = 0x42 // 'B'
		msgWrite(MessageType_Success, rawBuf[:])
		return
	}

	if bytesEqual(cmd, cmdDIRECT) {
		// Bypass msgWrite completely - write directly to output buffer
		// Format: ## + msgID(2) + len(4) + payload + padding
		// This sends MessageType_Success (2) with payload "AB" (0x12 0x02 0x41 0x42)
		msgOutAppend('#')
		msgOutAppend('#')
		msgOutAppend(0x00) // msgID high byte
		msgOutAppend(0x02) // msgID low byte (MessageType_Success = 2)
		msgOutAppend(0x00) // length byte 0
		msgOutAppend(0x00) // length byte 1
		msgOutAppend(0x00) // length byte 2
		msgOutAppend(0x04) // length byte 3 (4 bytes)
		msgOutAppend(0x12) // protobuf field 2, wire type 2
		msgOutAppend(0x02) // length 2
		msgOutAppend(0x41) // 'A'
		msgOutAppend(0x42) // 'B'
		msgOutPad()
		return
	}

	if bytesEqual(cmd, cmdECHO) {
		// Echo back first 16 bytes of msgInBuffer as hex
		// This tests if input is being received correctly
		pos := 0
		testResultBuf[pos] = 'I'
		pos++
		testResultBuf[pos] = 'N'
		pos++
		testResultBuf[pos] = ':'
		pos++
		for i := 0; i < 16 && i < int(msgInSize); i++ {
			testResultBuf[pos] = hexCharsBytes[msgInBuffer[i]>>4]
			pos++
			testResultBuf[pos] = hexCharsBytes[msgInBuffer[i]&0x0f]
			pos++
		}
		sendSuccessBytes(testResultBuf[:pos])
		return
	}

	if bytesEqual(cmd, cmdFIXED) {
		// Test sending as Features type with our test data
		nn := pbEncodeString(pbEncodeBuf[:], Success_message, "TEST_OK")
		msgWrite(MessageType_Features, pbEncodeBuf[:nn])
		return
	}

	if bytesEqual(cmd, cmdSHA256) {
		// SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
		hash := sha256Sum([]byte("abc"))
		n += copyBytes(testResultBuf[n:], prefixSHA256)
		n += copyHexBytes(testResultBuf[n:], hash[:8])
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdRIPEMD) {
		// RIPEMD160("abc") = 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
		hash := ripemd160Sum([]byte("abc"))
		n += copyBytes(testResultBuf[n:], prefixRIPEMD)
		n += copyHexBytes(testResultBuf[n:], hash[:8])
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdB58) {
		// Base58 encode [0x00, 0x00, 0x00, 0x00, 0x01]
		data := []byte{0x00, 0x00, 0x00, 0x00, 0x01}
		encoded := base58EncodeToBytes(data)
		n += copyBytes(testResultBuf[n:], prefixB58)
		n += copyBytes(testResultBuf[n:], encoded)
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdSQR) {
		// Test squaring: 2^2 = 4
		var a, r Field
		a.SetInt(2)
		a.Sqr(&r)
		r.Normalize()
		n += copyBytes(testResultBuf[n:], prefixSQR)
		n += copyFieldHex(testResultBuf[n:], &r)
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdMUL) {
		// Test multiplication: 3 * 5 = 15
		var a, b, r Field
		a.SetInt(3)
		b.SetInt(5)
		a.Mul(&r, &b)
		r.Normalize()
		n += copyBytes(testResultBuf[n:], prefixMUL)
		n += copyFieldHex(testResultBuf[n:], &r)
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdPUBKEY1) {
		// Public key from secret key = 1 (should be generator G)
		var seckey [32]byte
		seckey[31] = 1
		pubkey := pubkeyFromSeckey(seckey[:])
		n += copyBytes(testResultBuf[n:], prefixPK1)
		n += copyHexBytes(testResultBuf[n:], pubkey[:8])
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdPUBKEY2) {
		// Public key from secret key = 2
		var seckey [32]byte
		seckey[31] = 2
		pubkey := pubkeyFromSeckey(seckey[:])
		n += copyBytes(testResultBuf[n:], prefixPK2)
		n += copyHexBytes(testResultBuf[n:], pubkey[:8])
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdECMULT) {
		// Test ECmultGen directly with seckey=1
		var seckey [32]byte
		seckey[31] = 1
		var xyz XYZ
		ECmultGen(&xyz, seckey[:])
		var xy XY
		xy.SetXYZ(&xyz)
		if xy.Infinity {
			n += copyBytes(testResultBuf[n:], prefixECINF)
		} else {
			var xBytes [32]byte
			xy.X.GetB32(xBytes[:])
			n += copyBytes(testResultBuf[n:], prefixECMULT)
			n += copyHexBytes(testResultBuf[n:], xBytes[:8])
		}
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdGPOINT) {
		// Get generator point X coordinate
		initSecp256k1G()
		var xBytes [32]byte
		secp256k1G.X.GetB32(xBytes[:])
		n += copyBytes(testResultBuf[n:], prefixGPOINT)
		n += copyHexBytes(testResultBuf[n:], xBytes[:8])
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdADDR) {
		// Test full address generation with test mnemonic
		mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		addrBytes := deriveAddressAtIndexBytes(mnemonic, 0)
		if len(addrBytes) == 0 {
			n += copyBytes(testResultBuf[n:], prefixADDRF)
		} else {
			n += copyBytes(testResultBuf[n:], prefixADDR)
			maxLen := 16
			if len(addrBytes) < maxLen {
				maxLen = len(addrBytes)
			}
			n += copyBytes(testResultBuf[n:], addrBytes[:maxLen])
		}
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	// Unknown command - echo it back
	n += copyBytes(testResultBuf[n:], prefixUNKNOWN)
	n += copyBytes(testResultBuf[n:], cmd)
	sendSuccessBytes(testResultBuf[:n])
}

// hexBuf is a fixed buffer for hex encoding
var hexBuf [64]byte

// hexBytes converts bytes to hex string (max 32 bytes input)
func hexBytes(data []byte) string {
	const hexChars = "0123456789abcdef"
	n := len(data)
	if n > 32 {
		n = 32
	}
	for i := 0; i < n; i++ {
		hexBuf[i*2] = hexChars[data[i]>>4]
		hexBuf[i*2+1] = hexChars[data[i]&0x0f]
	}
	return string(hexBuf[:n*2])
}

// fieldHexBuf is a fixed buffer for field hex encoding
var fieldHexBuf [8]byte

// fieldToHex converts a field element to hex (just low 32 bits for testing)
func fieldToHex(f *Field) string {
	val := f.n[0]
	const hexChars = "0123456789abcdef"
	for i := 7; i >= 0; i-- {
		fieldHexBuf[i] = hexChars[val&0x0f]
		val >>= 4
	}
	return string(fieldHexBuf[:])
}

// handleChangePin handles the ChangePin message
func handleChangePin() {
	storageInit()

	if storageHasPIN() {
		// Need to verify current PIN first
		pinState = PIN_STATE_CHANGE_OLD
		sendPinMatrixRequest(PinMatrixRequestType_Current)
	} else {
		// No current PIN, go straight to setting new one
		pinState = PIN_STATE_CHANGE_NEW1
		sendPinMatrixRequest(PinMatrixRequestType_NewFirst)
	}
}

// handlePinMatrixAck handles the PinMatrixAck message (PIN entry response)
func handlePinMatrixAck() {
	// Check if device is locked out due to too many failures
	if storagePINLockedOut() {
		pinState = PIN_STATE_IDLE
		sendFailure(FailureType_PinInvalid, "Too many failures. Wipe required.")
		return
	}

	// Apply delay based on failure count (exponential backoff)
	delay := storagePINDelay()
	if delay > 0 {
		// Show delay message on OLED
		oledClear()
		oledDrawString(4, 20, "PIN delay...")
		oledDrawInt(4, 32, int(delay/1000000))
		oledDrawString(20, 32, "sec")
		oledRefresh()

		// Wait for the delay
		usbDelay(int(delay))
	}

	pin := pbDecodePinMatrixAck(msgInBuffer[:msgInSize])

	switch pinState {
	case PIN_STATE_VERIFY:
		// Verifying PIN for protected operation
		if storagePINCompare(pin) {
			storageResetPINFailures() // Reset on success
			sessionCachePIN()
			pinState = PIN_STATE_IDLE
			sendSuccess("")
		} else {
			failures := storageIncrementPINFailures()
			pinState = PIN_STATE_IDLE
			if failures >= PIN_MAX_ATTEMPTS {
				sendFailure(FailureType_PinInvalid, "Device locked. Wipe required.")
			} else {
				sendFailure(FailureType_PinInvalid, "Invalid PIN")
			}
		}

	case PIN_STATE_CHANGE_OLD:
		// Verifying old PIN for change
		if storagePINCompare(pin) {
			storageResetPINFailures() // Reset on success
			pinState = PIN_STATE_CHANGE_NEW1
			sendPinMatrixRequest(PinMatrixRequestType_NewFirst)
		} else {
			failures := storageIncrementPINFailures()
			pinState = PIN_STATE_IDLE
			if failures >= PIN_MAX_ATTEMPTS {
				sendFailure(FailureType_PinInvalid, "Device locked. Wipe required.")
			} else {
				sendFailure(FailureType_PinInvalid, "Invalid PIN")
			}
		}

	case PIN_STATE_CHANGE_NEW1:
		// First entry of new PIN
		pinNewFirstLen = len(pin)
		if pinNewFirstLen > 9 {
			pinNewFirstLen = 9
		}
		copy(pinNewFirst[:], pin)
		pinState = PIN_STATE_CHANGE_NEW2
		sendPinMatrixRequest(PinMatrixRequestType_NewSecond)

	case PIN_STATE_CHANGE_NEW2:
		// Second entry of new PIN - verify match
		if len(pin) == pinNewFirstLen {
			match := true
			for i := 0; i < pinNewFirstLen; i++ {
				if pin[i] != pinNewFirst[i] {
					match = false
					break
				}
			}
			if match {
				// PINs match - save new PIN
				storageSetPIN(string(pinNewFirst[:pinNewFirstLen]))
				pinState = PIN_STATE_IDLE
				// Clear cached PIN data
				for i := range pinNewFirst {
					pinNewFirst[i] = 0
				}
				pinNewFirstLen = 0
				sendSuccess("PIN changed")
			} else {
				pinState = PIN_STATE_IDLE
				sendFailure(FailureType_PinMismatch, "PIN mismatch")
			}
		} else {
			pinState = PIN_STATE_IDLE
			sendFailure(FailureType_PinMismatch, "PIN mismatch")
		}

	default:
		pinState = PIN_STATE_IDLE
		sendFailure(FailureType_UnexpectedMessage, "Unexpected PIN")
	}
}

// handleCancel handles the Cancel message
func handleCancel() {
	pinState = PIN_STATE_IDLE
	// Clear any pending PIN data
	for i := range pinNewFirst {
		pinNewFirst[i] = 0
	}
	pinNewFirstLen = 0
	sendFailure(FailureType_ActionCancelled, "Cancelled")
}

// handleWipeDevice handles the WipeDevice message
func handleWipeDevice() {
	// Wipe storage - no PIN verification required (device reset)
	storageWipe()
	sendSuccess("Device wiped")
}

// sendPinMatrixRequest sends a PinMatrixRequest message
func sendPinMatrixRequest(pinType uint32) {
	var buf [8]byte
	n := pbEncodePinMatrixRequest(buf[:], pinType)
	msgWrite(MessageType_PinMatrixRequest, buf[:n])
}

// requirePIN checks if PIN is required and starts verification if needed
// Returns true if operation can proceed, false if waiting for PIN
func requirePIN() bool {
	storageInit()
	if !storageHasPIN() {
		return true // No PIN set
	}
	if sessionIsPINcached() {
		return true // PIN already verified this session
	}
	// Need PIN verification
	pinState = PIN_STATE_VERIFY
	sendPinMatrixRequest(PinMatrixRequestType_Current)
	return false
}

// handleGenerateMnemonic handles the GenerateMnemonic message
func handleGenerateMnemonic() {
	storageInit()

	// Check if device is already initialized
	if storageIsInitialized() {
		sendFailure(FailureType_UnexpectedMessage, "Already initialized")
		return
	}

	// Get word count from message
	wordCount := pbDecodeGenerateMnemonic(msgInBuffer[:msgInSize])
	if wordCount != 12 && wordCount != 24 {
		wordCount = 12
	}

	// Generate entropy using hardware RNG
	entropySize := 16 // 128 bits for 12 words
	if wordCount == 24 {
		entropySize = 32 // 256 bits for 24 words
	}
	// Use fixed buffer from bip39.go
	getEntropy(entropyBuffer[:entropySize])
	entropy := entropyBuffer[:entropySize]

	// Debug: show raw entropy and wordlist check
	oledClear()
	x := 0
	// Line 0: "E:" + first 4 bytes of entropy in hex
	x += oledDrawChar(x, 0, 'E')
	x += oledDrawChar(x, 0, ':')
	for i := 0; i < 4; i++ {
		x += oledDrawChar(x, 0, hexDigit(entropy[i]>>4))
		x += oledDrawChar(x, 0, hexDigit(entropy[i]&0xF))
	}

	// Line 10: "W:" + first word from bip39Words (should be "abandon")
	x = 0
	x += oledDrawChar(x, 10, 'W')
	x += oledDrawChar(x, 10, ':')
	firstWord := bip39Words[0]
	for i := 0; i < len(firstWord) && i < 10; i++ {
		x += oledDrawChar(x, 10, firstWord[i])
	}

	// Line 20: "N:" + number of words in bip39Words
	x = 0
	x += oledDrawChar(x, 20, 'N')
	x += oledDrawChar(x, 20, ':')
	numWords := len(bip39Words)
	if numWords == 0 {
		x += oledDrawChar(x, 20, '0')
	} else {
		var digits [5]byte
		dpos := 4
		for numWords > 0 && dpos >= 0 {
			digits[dpos] = '0' + byte(numWords%10)
			numWords /= 10
			dpos--
		}
		for i := dpos + 1; i <= 4; i++ {
			x += oledDrawChar(x, 20, digits[i])
		}
	}

	oledRefresh()
	// Wait 3 seconds to see debug
	usbDelay(3000000)

	// Generate mnemonic from entropy
	mnemonic := entropyToMnemonic(entropy)

	// Debug screen 2: show mnemonic result
	oledClear()
	// Line 0: "L:" + mnemonic length
	x = 0
	x += oledDrawChar(x, 0, 'L')
	x += oledDrawChar(x, 0, ':')
	mlen := len(mnemonic)
	if mlen == 0 {
		x += oledDrawChar(x, 0, '0')
	} else {
		var digits [3]byte
		dpos := 2
		for mlen > 0 && dpos >= 0 {
			digits[dpos] = '0' + byte(mlen%10)
			mlen /= 10
			dpos--
		}
		for i := dpos + 1; i <= 2; i++ {
			x += oledDrawChar(x, 0, digits[i])
		}
	}
	// Line 10: first 16 chars of mnemonic
	x = 0
	for i := 0; i < 16 && i < len(mnemonic); i++ {
		x += oledDrawChar(x, 10, mnemonic[i])
	}
	// Line 20: next 16 chars of mnemonic (chars 16-31)
	x = 0
	for i := 16; i < 32 && i < len(mnemonic); i++ {
		x += oledDrawChar(x, 20, mnemonic[i])
	}
	oledRefresh()
	// Wait 3 seconds to see debug
	usbDelay(3000000)

	// Store mnemonic in flash (mark needs_backup = true)
	storageSetMnemonic(mnemonic)
	storageSetNeedsBackup(true)

	// Update display to show initialized
	layoutHome()

	// Send success
	sendSuccess("Mnemonic successfully configured")
}

// sendEntropyRequest sends an EntropyRequest message
func sendEntropyRequest(size uint32) {
	var buf [8]byte
	n := pbEncodeEntropyRequest(buf[:], size)
	msgWrite(MessageType_EntropyRequest, buf[:n])
}

// handleEntropyAck handles the EntropyAck message (entropy from host)
func handleEntropyAck() {
	if mnemonicState != MNEMONIC_STATE_WAIT_ENTROPY {
		sendFailure(FailureType_UnexpectedMessage, "Unexpected entropy")
		return
	}

	// Get host entropy
	hostEntropy := pbDecodeEntropyAck(msgInBuffer[:msgInSize])

	// Generate device entropy
	entropySize := 16
	if mnemonicWordCount == 24 {
		entropySize = 32
	}
	deviceEntropy := make([]byte, entropySize)
	getEntropy(deviceEntropy)

	// Mix entropy: XOR host entropy with device entropy
	mixedEntropy := make([]byte, entropySize)
	for i := 0; i < entropySize; i++ {
		if i < len(hostEntropy) {
			mixedEntropy[i] = deviceEntropy[i] ^ hostEntropy[i]
		} else {
			mixedEntropy[i] = deviceEntropy[i]
		}
	}

	// Generate mnemonic from mixed entropy
	mnemonic := entropyToMnemonic(mixedEntropy)
	pendingMnemonicLen = copy(pendingMnemonic[:], mnemonic)

	// Store mnemonic in flash (but mark needs_backup = true)
	storageSetMnemonic(mnemonic)
	storageSetNeedsBackup(true)

	mnemonicState = MNEMONIC_STATE_IDLE

	// Send success with mnemonic (for debug/testing - real implementation should show on screen)
	sendSuccess("Mnemonic generated")
}

// handleSetMnemonic handles the SetMnemonic message (import mnemonic)
func handleSetMnemonic() {
	storageInit()

	// Check if device is already initialized
	if storageIsInitialized() {
		sendFailure(FailureType_UnexpectedMessage, "Already initialized")
		return
	}

	// Get mnemonic from message
	mnemonic := pbDecodeSetMnemonic(msgInBuffer[:msgInSize])

	// Validate mnemonic
	if !validateMnemonic(mnemonic) {
		sendFailure(FailureType_DataError, "Invalid mnemonic")
		return
	}

	// Store mnemonic
	storageSetMnemonic(mnemonic)
	storageSetNeedsBackup(false) // Imported = already backed up

	sendSuccess("Mnemonic set")
}

// handleGetEntropy handles the GetEntropy message
func handleGetEntropy() {
	// GetEntropy returns raw entropy from hardware RNG
	// Size is specified in the message (default 32 bytes)
	size := 32

	entropy := make([]byte, size)
	getEntropy(entropy)

	var buf [64]byte
	n := pbEncodeEntropy(buf[:], entropy)
	msgWrite(MessageType_Entropy, buf[:n])
}

// handleBackupDevice handles the BackupDevice message
func handleBackupDevice() {
	storageInit()

	// Check if device is initialized
	if !storageIsInitialized() {
		sendFailure(FailureType_NotInitialized, "Not initialized")
		return
	}

	// Check if backup is needed
	if !storageNeedsBackup() {
		sendFailure(FailureType_UnexpectedMessage, "Already backed up")
		return
	}

	// Start backup process - show words one at a time
	mnemonicBackupIndex = 0
	mnemonicState = MNEMONIC_STATE_BACKUP

	// Get mnemonic from storage
	mnemonic := storageGetMnemonic()
	pendingMnemonicLen = copy(pendingMnemonic[:], mnemonic)

	// Send button request to start backup
	sendButtonRequest(ButtonRequestType_ConfirmWord)
}

// sendButtonRequest sends a ButtonRequest message
func sendButtonRequest(code uint32) {
	var buf [8]byte
	n := pbEncodeButtonRequest(buf[:], code)
	msgWrite(MessageType_ButtonRequest, buf[:n])
}

// handleButtonAck handles the ButtonAck message
func handleButtonAck() {
	// Check address confirmation state
	if addrState == ADDR_STATE_WAIT_BUTTON {
		// User confirmed - send all pending addresses
		sendAllSkycoinAddresses()
		return
	}

	if mnemonicState == MNEMONIC_STATE_BACKUP {
		// Show next word
		words := splitMnemonic(string(pendingMnemonic[:pendingMnemonicLen]))
		if mnemonicBackupIndex < len(words) {
			// Display word on OLED
			displayBackupWord(mnemonicBackupIndex+1, words[mnemonicBackupIndex])
			mnemonicBackupIndex++

			if mnemonicBackupIndex < len(words) {
				// More words to show
				sendButtonRequest(ButtonRequestType_ConfirmWord)
			} else {
				// All words shown
				storageSetNeedsBackup(false)
				mnemonicState = MNEMONIC_STATE_IDLE
				clearBackupDisplay()
				sendSuccess("Backup complete")
			}
		}
		return
	}

	// Unexpected ButtonAck
	sendFailure(FailureType_UnexpectedMessage, "Unexpected button ack")
}

// displayBackupWord shows a backup word on the OLED
func displayBackupWord(index int, word string) {
	// Clear display area
	for y := 16; y < 64; y++ {
		for x := 0; x < 128; x++ {
			oledSetPixel(x, y, false)
		}
	}

	// Show word number
	oledDrawString(4, 24, "Word")
	oledDrawInt(36, 24, index)
	oledDrawString(48, 24, "of")
	oledDrawInt(68, 24, mnemonicWordCount)

	// Show the word
	oledDrawString(4, 40, word)

	oledRefresh()
}

// clearBackupDisplay clears the backup word display
func clearBackupDisplay() {
	for y := 16; y < 64; y++ {
		for x := 0; x < 128; x++ {
			oledSetPixel(x, y, false)
		}
	}
	oledDrawString(4, 32, "Backup complete!")
	oledRefresh()
}

// Address generation state for button confirmation flow
const (
	ADDR_STATE_IDLE = iota
	ADDR_STATE_WAIT_BUTTON
)

var addrState = ADDR_STATE_IDLE
var pendingAddresses [10]string // Max 10 addresses
var pendingAddressCount = 0

// handleSkycoinAddress handles the SkycoinAddress message
func handleSkycoinAddress() {
	storageInit()

	// Check if device is initialized
	if !storageIsInitialized() {
		sendFailure(FailureType_NotInitialized, "Not initialized")
		return
	}

	// Check PIN if required
	if !requirePIN() {
		return // Waiting for PIN
	}

	// Decode message fields
	addressN, startIndex, confirmAddress := pbDecodeSkycoinAddress(msgInBuffer[:msgInSize])

	// Limit addressN to reasonable value
	if addressN <= 0 {
		addressN = 1
	}
	if addressN > 10 {
		addressN = 10
	}

	// Get mnemonic from storage
	mnemonic := storageGetMnemonic()
	if mnemonic == "" {
		sendFailure(FailureType_NotInitialized, "No mnemonic")
		return
	}

	// Debug: show mnemonic info using direct char output
	oledClear()
	// Show raw MnemonicLen from storage
	x := 0
	x += oledDrawChar(x, 0, 'L')
	x += oledDrawChar(x, 0, 'e')
	x += oledDrawChar(x, 0, 'n')
	x += oledDrawChar(x, 0, ':')
	mlen := int(storage.MnemonicLen)
	if mlen == 0 {
		x += oledDrawChar(x, 0, '0')
	} else {
		var digits [3]byte
		dpos := 2
		for mlen > 0 && dpos >= 0 {
			digits[dpos] = '0' + byte(mlen%10)
			mlen /= 10
			dpos--
		}
		for i := dpos + 1; i <= 2; i++ {
			x += oledDrawChar(x, 0, digits[i])
		}
	}
	// Show first 10 chars of mnemonic on second line
	x = 0
	for i := 0; i < 10 && i < len(mnemonic); i++ {
		x += oledDrawChar(x, 10, mnemonic[i])
	}
	oledRefresh()

	// Generate all requested addresses
	pendingAddressCount = 0

	for i := 0; i < addressN; i++ {
		address := deriveAddressAtIndex(mnemonic, startIndex+i)
		if address == "" {
			// Debug: show which step failed
			oledDrawString(0, 16, "Derive FAILED")
			oledDrawString(0, 24, "idx:")
			oledDrawString(32, 24, intToStr(startIndex+i))
			oledDrawString(0, 32, "pk:")
			oledDrawChar(24, 32, '0'+debugPubkeyState)
			oledDrawString(32, 32, " ecdh:")
			oledDrawChar(72, 32, '0'+debugEcdhState)
			oledDrawString(0, 42, "decomp:")
			oledDrawChar(56, 42, '0'+debugDecompressState)
			oledRefresh()
			// Include debug state in failure message using switch
			// debugDecompressState: 0=not called, 1=len, 2=prefix, 3=isvalid fail, 4=ok, 5=sqrt fail, 6=sqrt4 fail
			// Use constant strings to avoid encoding issues
			if debugDecompressState == 1 {
				sendFailure(FailureType_ProcessError, "dec len")
			} else if debugDecompressState == 2 {
				sendFailure(FailureType_ProcessError, "dec pre")
			} else if debugDecompressState == 3 {
				sendFailure(FailureType_ProcessError, "IsValid")
			} else if debugDecompressState == 4 {
				sendFailure(FailureType_ProcessError, "dec ok")
			} else if debugDecompressState == 5 {
				sendFailure(FailureType_ProcessError, "Sqrt bad")
			} else if debugDecompressState == 6 {
				sendFailure(FailureType_ProcessError, "Sqrt4 bad")
			} else if debugDecompressState == 7 {
				sendFailure(FailureType_ProcessError, "Sqr2 bad")
			} else if debugDecompressState == 8 {
				sendFailure(FailureType_ProcessError, "SetInt bad")
			} else if debugEcdhState == 3 {
				sendFailure(FailureType_ProcessError, "ecdh inf")
			} else {
				sendFailure(FailureType_ProcessError, "unknown")
			}
			return
		}
		pendingAddresses[i] = address
		pendingAddressCount++
	}

	// Display first address on OLED
	if pendingAddressCount > 0 {
		displayAddress(pendingAddresses[0])
	}

	// If confirmAddress is set, send ButtonRequest and wait for ButtonAck
	if confirmAddress {
		addrState = ADDR_STATE_WAIT_BUTTON
		sendButtonRequest(ButtonRequestType_Address)
		return
	}

	// No confirmation needed - send addresses directly
	sendAllSkycoinAddresses()
}

// sendAllSkycoinAddresses sends all pending addresses
func sendAllSkycoinAddresses() {
	// Encode all addresses in response
	var buf [512]byte
	n := 0
	for i := 0; i < pendingAddressCount; i++ {
		n += pbEncodeString(buf[n:], ResponseSkycoinAddress_addresses, pendingAddresses[i])
	}

	msgWrite(MessageType_ResponseSkycoinAddress, buf[:n])
	addrState = ADDR_STATE_IDLE
}

// intToStr converts int to string (simple implementation)
func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [10]byte
	i := 9
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 && i >= 0 {
		buf[i] = '0' + byte(n%10)
		n /= 10
		i--
	}
	if neg && i >= 0 {
		buf[i] = '-'
		i--
	}
	return string(buf[i+1:])
}

// displayAddress shows an address on the OLED display
func displayAddress(address string) {
	// Clear display area
	for y := 16; y < 64; y++ {
		for x := 0; x < 128; x++ {
			oledSetPixel(x, y, false)
		}
	}

	oledDrawString(4, 24, "Address:")

	// Show address in parts (it's too long for one line)
	if len(address) > 16 {
		oledDrawString(4, 36, address[:16])
		if len(address) > 32 {
			oledDrawString(4, 48, address[16:32])
		} else {
			oledDrawString(4, 48, address[16:])
		}
	} else {
		oledDrawString(4, 36, address)
	}

	oledRefresh()
}

// handleSkycoinSignMessage handles the SkycoinSignMessage message
func handleSkycoinSignMessage() {
	storageInit()

	// Check if device is initialized
	if !storageIsInitialized() {
		sendFailure(FailureType_NotInitialized, "Not initialized")
		return
	}

	// Check PIN if required
	if !requirePIN() {
		return // Waiting for PIN
	}

	// Decode the message
	addrIndex, message := pbDecodeSkycoinSignMessage(msgInBuffer[:msgInSize])

	// Get mnemonic from storage
	mnemonic := storageGetMnemonic()
	if mnemonic == "" {
		sendFailure(FailureType_NotInitialized, "No mnemonic")
		return
	}

	// Derive key at specified index
	seckey := deriveSecretKeyAtIndex(mnemonic, addrIndex)
	if seckey == nil {
		sendFailure(FailureType_ProcessError, "Key derivation failed")
		return
	}

	// Get address to display for confirmation
	address := skycoinAddressFromSeckey(seckey)

	// Show confirmation dialog
	layoutConfirmSign("Sign message?", address)

	// Wait for button confirmation
	if !waitForButton(false) {
		sendFailure(FailureType_ActionCancelled, "Cancelled")
		return
	}

	// Determine if message is already a hex digest
	var digest [32]byte
	if isHexDigit(message) {
		// Message is a hex-encoded SHA256 digest
		digestBytes := hexToBytes(message)
		if len(digestBytes) == 32 {
			copy(digest[:], digestBytes)
		} else {
			// Invalid hex, hash the message instead
			digest = sha256Sum([]byte(message))
		}
	} else {
		// Hash the message
		digest = sha256Sum([]byte(message))
	}

	// Sign the digest
	sig := ecdsaSignDigest(seckey, digest[:])

	// Check if signature is valid (not all zeros)
	allZero := true
	for i := 0; i < 65; i++ {
		if sig[i] != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		sendFailure(FailureType_ProcessError, "Signature failed")
		return
	}

	// Convert to hex string (130 chars = 65 bytes * 2)
	sigHex := bytesToHex(sig[:])

	// Display on OLED
	displaySignature(sigHex)

	// Send response
	sendSkycoinSignMessageResponse(sigHex)
}

// displaySignature shows a signature on the OLED display
func displaySignature(sigHex string) {
	// Clear display area
	for y := 16; y < 64; y++ {
		for x := 0; x < 128; x++ {
			oledSetPixel(x, y, false)
		}
	}

	oledDrawString(4, 24, "Signed!")

	// Show first part of signature
	if len(sigHex) > 20 {
		oledDrawString(4, 36, sigHex[:20])
	}
	if len(sigHex) > 40 {
		oledDrawString(4, 48, sigHex[20:40])
	}

	oledRefresh()
}

// sendSkycoinSignMessageResponse sends a ResponseSkycoinSignMessage
func sendSkycoinSignMessageResponse(sigHex string) {
	var buf [140]byte // 130 hex chars + overhead
	n := pbEncodeSkycoinSignMessageResponse(buf[:], sigHex)
	msgWrite(MessageType_ResponseSkycoinSignMessage, buf[:n])
}

// handleSkycoinCheckMessageSignature handles the SkycoinCheckMessageSignature message
// Verifies that a signature was produced by the private key corresponding to an address
func handleSkycoinCheckMessageSignature() {
	// Decode the message
	expectedAddress, message, sigHex := pbDecodeSkycoinCheckMessageSignature(msgInBuffer[:msgInSize])

	if expectedAddress == "" || sigHex == "" {
		sendFailure(FailureType_DataError, "Missing address or signature")
		return
	}

	// Convert signature from hex to bytes (65 bytes)
	if len(sigHex) != 130 {
		sendFailure(FailureType_DataError, "Invalid signature length")
		return
	}
	sigBytes := hexToBytes(sigHex)
	if sigBytes == nil || len(sigBytes) != 65 {
		sendFailure(FailureType_DataError, "Invalid signature hex")
		return
	}

	// Determine if message is already a hex digest
	var digest [32]byte
	if isHexDigit(message) {
		// Message is a hex-encoded SHA256 digest
		digestBytes := hexToBytes(message)
		if len(digestBytes) == 32 {
			copy(digest[:], digestBytes)
		} else {
			// Invalid hex, hash the message instead
			digest = sha256Sum([]byte(message))
		}
	} else {
		// Hash the message
		digest = sha256Sum([]byte(message))
	}

	// Recover public key from signature
	recoveredPubkey := ecdsaRecoverPubkey(sigBytes, digest[:])
	if recoveredPubkey == nil {
		sendFailure(FailureType_InvalidSignature, "Cannot recover public key")
		return
	}

	// Generate address from recovered public key
	recoveredAddress := skycoinAddressFromPubkey(recoveredPubkey)
	if recoveredAddress == "" {
		sendFailure(FailureType_ProcessError, "Cannot generate address")
		return
	}

	// Compare addresses
	if recoveredAddress != expectedAddress {
		sendFailure(FailureType_InvalidSignature, "Address mismatch")
		return
	}

	// Signature is valid
	sendSuccess("Signature is valid")
}

// handleApplySettings handles the ApplySettings message
// Allows setting device label, language, and passphrase protection
func handleApplySettings() {
	storageInit()

	// Check PIN if required
	if !requirePIN() {
		return // Waiting for PIN
	}

	// Decode the message
	language, label, usePassphrase, hasLanguage, hasLabel, hasUsePassphrase := pbDecodeApplySettings(msgInBuffer[:msgInSize])

	// Check at least one field is provided
	if !hasLanguage && !hasLabel && !hasUsePassphrase {
		sendFailure(FailureType_DataError, "No settings provided")
		return
	}

	// Apply label if provided
	if hasLabel {
		storageSetLabel(label)
	}

	// Apply language if provided (validate it's "english" or "en")
	if hasLanguage {
		// Only validate - we accept "english", "en", or "en-US"
		if language != "english" && language != "en" && language != "en-US" {
			sendFailure(FailureType_DataError, "Invalid language")
			return
		}
		storageSetLanguage(language)
	}

	// Apply passphrase protection if provided
	if hasUsePassphrase {
		storageSetPassphraseProtection(usePassphrase)
	}

	sendSuccess("Settings applied")
}
