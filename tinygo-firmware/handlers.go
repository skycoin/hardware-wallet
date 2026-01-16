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
var pinTranslated [10]byte // Buffer for translated PIN to avoid string conversion
var pinTranslatedLen int

// Pending operation state - saved when PIN verification is needed
const (
	PENDING_OP_NONE = iota
	PENDING_OP_SKYCOIN_ADDRESS
	PENDING_OP_SIGN_MESSAGE
	PENDING_OP_TRANSACTION_SIGN
)

var pendingOperation = PENDING_OP_NONE

// Button state machine for pending confirmations
const (
	BTN_STATE_IDLE         = iota
	BTN_STATE_WIPE_CONFIRM // Waiting for wipe confirmation
)

var btnState = BTN_STATE_IDLE

// Mnemonic generation state machine
const (
	MNEMONIC_STATE_IDLE = iota
	MNEMONIC_STATE_WAIT_ENTROPY
	MNEMONIC_STATE_BACKUP_WAIT_ACK // Waiting for ButtonAck from host
	MNEMONIC_STATE_BACKUP_WAIT_BTN // Got ButtonAck, waiting for physical button
)

var mnemonicState = MNEMONIC_STATE_IDLE
var mnemonicWordCount = 12
var mnemonicBackupIndex = 0
var mnemonicBackupPass = 0    // 0 = "Write down", 1 = "Check"
var pendingMnemonic [512]byte // Buffer for generated mnemonic
var pendingMnemonicLen = 0
var pendingMnemonicWordCount = 0

// Word storage using byte buffers (TinyGo string arrays don't work)
var backupWordBufs [24][10]byte // Max 24 words, max 9 chars + null
var backupWordLens [24]int

// Fixed buffers for entropy mixing (avoid make() allocation)
var entropyAckDeviceBuf [32]byte
var entropyAckMixedBuf [32]byte

// dispatchMessage handles an incoming message based on its type
func dispatchMessage() {
	if DebugMode {
		debugShowMsgID(msgInID)
		// Also show first 8 bytes of payload for debugging
		debugShowPayload(msgInBuffer[:], msgInSize)
	}
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

	case MessageType_GetEntropy: // Same as GetRawEntropy (both are message type 9)
		handleGetRawEntropy()

	case MessageType_GetMixedEntropy:
		handleGetMixedEntropy()

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

	case MessageType_LoadDevice:
		handleLoadDevice()

	case MessageType_ResetDevice:
		handleResetDevice()

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

// testMnemBuf is a global buffer for test mnemonic generation
// (local [256]byte could cause stack overflow in TinyGo bare-metal mode)
var testMnemBuf [256]byte

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
	debugPattern = []byte{'A', 'B', 'C', 'D', '1', '2', '3', '4'}
)

// copyBytes copies a byte slice into buf, returns bytes written
func copyBytes(buf []byte, src []byte) int {
	for i := 0; i < len(src); i++ {
		buf[i] = src[i]
	}
	return len(src)
}

// copyIntBytes writes decimal representation of an int to buf, returns bytes written
func copyIntBytes(buf []byte, val int) int {
	if val == 0 {
		buf[0] = '0'
		return 1
	}
	neg := val < 0
	if neg {
		val = -val
	}
	// Find number of digits
	temp := val
	digits := 0
	for temp > 0 {
		digits++
		temp /= 10
	}
	// Write digits from right to left
	n := digits
	if neg {
		n++
	}
	for i := n - 1; i >= 0; i-- {
		if neg && i == 0 {
			buf[i] = '-'
		} else {
			buf[i] = '0' + byte(val%10)
			val /= 10
		}
	}
	return n
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
	cmdADDRDBG = []byte{'A', 'D', 'D', 'R', 'D', 'B', 'G'}
	cmdPBTEST  = []byte{'P', 'B', 'T', 'E', 'S', 'T'}
	cmdDECOMP  = []byte{'D', 'E', 'C', 'O', 'M', 'P'}
	cmdECDH    = []byte{'E', 'C', 'D', 'H'}
	cmdSTEP1   = []byte{'S', 'T', 'E', 'P', '1'}
	cmdSECP    = []byte{'S', 'E', 'C', 'P'}
	cmdVALID   = []byte{'V', 'A', 'L', 'I', 'D'}
	cmdLOOP    = []byte{'L', 'O', 'O', 'P'}
	cmdBENCH   = []byte{'B', 'E', 'N', 'C', 'H'}
	cmdINV     = []byte{'I', 'N', 'V'}
	cmdDBL     = []byte{'D', 'B', 'L'}
	cmdLOOP2   = []byte{'L', 'O', 'O', 'P', '2'}
	cmdECM     = []byte{'E', 'C', 'M'}
	cmdSETXYZ  = []byte{'S', 'E', 'T', 'X', 'Y', 'Z'}
	cmdVMNEM   = []byte{'V', 'M', 'N', 'E', 'M'}
	cmdSECPV   = []byte{'S', 'E', 'C', 'P', 'V'}      // secp256k1sum with "seed" test vector
	cmdSECPD   = []byte{'S', 'E', 'C', 'P', 'D'}      // secp256k1sum debug - show intermediate values
	cmdPKTEST  = []byte{'P', 'K', 'T', 'E', 'S', 'T'} // test pubkey from C test vector seckey
	cmdPK3     = []byte{'P', 'K', '3'}                // test pubkey from seckey=3
	cmdPK4     = []byte{'P', 'K', '4'}                // test pubkey from seckey=4 (only uses Double)
	cmdDBL2    = []byte{'D', 'B', 'L', '2'}           // debug: Double(G) then Double(2G) step by step
)

// handleTestCommandBytes runs crypto test commands using byte slice input
// Commands:
//
//	SHA256 - SHA256("abc"), expect ba7816bf...
//	RIPEMD - RIPEMD160("abc"), expect 8eb208f7...
//	B58    - Base58Check([0x00,0x00...]), expect 1111...
//	PUBKEY1 - pubkey from seckey=1, expect G point
//	PUBKEY2 - pubkey from seckey=2
//	SQR    - square 2, expect 4
//	MUL    - multiply 3*5, expect 15
//	ADDR   - address from test mnemonic
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

	// ADDR1 - test address from seckey=1
	if len(cmd) == 5 && cmd[0] == 'A' && cmd[1] == 'D' && cmd[2] == 'D' && cmd[3] == 'R' && cmd[4] == '1' {
		var seckey [32]byte
		seckey[31] = 1
		addrBytes := skycoinAddressFromSeckeyBytes(seckey[:])
		if len(addrBytes) == 0 {
			testResultBuf[n] = 'A'
			n++
			testResultBuf[n] = '1'
			n++
			testResultBuf[n] = ':'
			n++
			testResultBuf[n] = 'F'
			n++
			testResultBuf[n] = 'A'
			n++
			testResultBuf[n] = 'I'
			n++
			testResultBuf[n] = 'L'
			n++
		} else {
			testResultBuf[n] = 'A'
			n++
			testResultBuf[n] = '1'
			n++
			testResultBuf[n] = ':'
			n++
			maxLen := 16
			if len(addrBytes) < maxLen {
				maxLen = len(addrBytes)
			}
			n += copyBytes(testResultBuf[n:], addrBytes[:maxLen])
		}
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	// DKPI - test deterministicKeyPairIterator directly with mnemonic
	if len(cmd) == 4 && cmd[0] == 'D' && cmd[1] == 'K' && cmd[2] == 'P' && cmd[3] == 'I' {
		mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		seed := []byte(mnemonic)
		var nextSeed [32]byte
		var sk [32]byte
		var pk [33]byte
		ok := deterministicKeyPairIterator(seed, nextSeed[:], sk[:], pk[:])
		testResultBuf[n] = 'D'
		n++
		testResultBuf[n] = 'K'
		n++
		testResultBuf[n] = 'P'
		n++
		testResultBuf[n] = 'I'
		n++
		testResultBuf[n] = ':'
		n++
		if ok {
			testResultBuf[n] = 'O'
			n++
			testResultBuf[n] = 'K'
			n++
			testResultBuf[n] = ':'
			n++
			// Show first 4 bytes of seckey
			n += copyHexBytes(testResultBuf[n:], sk[:4])
		} else {
			testResultBuf[n] = 'F'
			n++
			testResultBuf[n] = ':'
			n++
			testResultBuf[n] = 'S'
			n++
			testResultBuf[n] = '0' + debugSecp256k1SumState
			n++
			testResultBuf[n] = 'P'
			n++
			testResultBuf[n] = '0' + debugPubkeyState
			n++
			testResultBuf[n] = 'E'
			n++
			testResultBuf[n] = '0' + debugEcdhState
			n++
		}
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

	if bytesEqual(cmd, cmdDECOMP) {
		// Test point decompression: decompress pubkey for seckey=1 (the generator)
		// First get compressed pubkey for seckey=1
		var seckey1 [32]byte
		seckey1[31] = 1
		pk := pubkeyFromSeckey(seckey1[:])
		// Now decompress it
		xy, ok := decompressPubkey(pk[:])
		testResultBuf[n] = 'D'
		n++
		testResultBuf[n] = 'C'
		n++
		testResultBuf[n] = ':'
		n++
		if !ok {
			testResultBuf[n] = 'F'
			n++
			testResultBuf[n] = 'A'
			n++
			testResultBuf[n] = 'I'
			n++
			testResultBuf[n] = 'L'
			n++
			testResultBuf[n] = '0' + debugDecompressState
			n++
		} else {
			testResultBuf[n] = 'O'
			n++
			testResultBuf[n] = 'K'
			n++
			// Show first 4 bytes of X
			var xBytes [32]byte
			xy.X.GetB32(xBytes[:])
			n += copyHexBytes(testResultBuf[n:], xBytes[:4])
		}
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdECDH) {
		// Test ECDH: multiply pubkey2 by seckey1
		// seckey1 = 1, pubkey2 = pubkey for seckey=2
		var seckey1 [32]byte
		seckey1[31] = 1
		var seckey2 [32]byte
		seckey2[31] = 2
		pk2 := pubkeyFromSeckey(seckey2[:])
		result := ecdh(pk2[:], seckey1[:])
		testResultBuf[n] = 'E'
		n++
		testResultBuf[n] = 'C'
		n++
		testResultBuf[n] = 'D'
		n++
		testResultBuf[n] = 'H'
		n++
		testResultBuf[n] = ':'
		n++
		if result == nil {
			testResultBuf[n] = 'F'
			n++
			testResultBuf[n] = '0' + debugEcdhState
			n++
		} else {
			n += copyHexBytes(testResultBuf[n:], result[:8])
		}
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdVALID) {
		// Test seckeyIsValid with SHA256("test")
		testHash := sha256Sum([]byte("test"))
		valid := seckeyIsValid(testHash[:])
		testResultBuf[n] = 'V'
		n++
		testResultBuf[n] = 'A'
		n++
		testResultBuf[n] = 'L'
		n++
		testResultBuf[n] = ':'
		n++
		if valid {
			testResultBuf[n] = 'Y'
			n++
			testResultBuf[n] = 'E'
			n++
			testResultBuf[n] = 'S'
			n++
		} else {
			testResultBuf[n] = 'N'
			n++
			testResultBuf[n] = 'O'
			n++
		}
		// Show first 4 bytes of hash
		n += copyHexBytes(testResultBuf[n:], testHash[:4])
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdLOOP) {
		// Test the hash-until-valid loop with counter
		testHash := sha256Sum([]byte("test"))
		var sk [32]byte
		copy(sk[:], testHash[:])
		iterations := 0
		for iterations < 100 { // Limit to 100 iterations
			hash := sha256Sum(sk[:])
			copy(sk[:], hash[:])
			iterations++
			if seckeyIsValid(sk[:]) {
				break
			}
		}
		testResultBuf[n] = 'L'
		n++
		testResultBuf[n] = 'O'
		n++
		testResultBuf[n] = 'O'
		n++
		testResultBuf[n] = 'P'
		n++
		testResultBuf[n] = ':'
		n++
		// Show iteration count
		testResultBuf[n] = hexDigit(byte(iterations / 10))
		n++
		testResultBuf[n] = hexDigit(byte(iterations % 10))
		n++
		// Show if we found a valid key
		if seckeyIsValid(sk[:]) {
			testResultBuf[n] = 'V'
			n++
		} else {
			testResultBuf[n] = 'X'
			n++
		}
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdSTEP1) {
		// Test deterministicKeyPairIteratorStep with a fixed hash
		testHash := sha256Sum([]byte("test"))
		var sk [32]byte
		var pk [33]byte
		ok := deterministicKeyPairIteratorStep(testHash[:], sk[:], pk[:])
		testResultBuf[n] = 'S'
		n++
		testResultBuf[n] = 'T'
		n++
		testResultBuf[n] = 'E'
		n++
		testResultBuf[n] = 'P'
		n++
		testResultBuf[n] = ':'
		n++
		if !ok {
			testResultBuf[n] = 'F'
			n++
			testResultBuf[n] = 'A'
			n++
			testResultBuf[n] = 'I'
			n++
			testResultBuf[n] = 'L'
			n++
		} else {
			// Show pubkey prefix and first 4 bytes of X
			n += copyHexBytes(testResultBuf[n:], pk[:5])
		}
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdSECP) {
		// Test secp256k1Sum with short seed
		seed := []byte("test")
		result := secp256k1Sum(seed)
		testResultBuf[n] = 'S'
		n++
		testResultBuf[n] = 'E'
		n++
		testResultBuf[n] = 'C'
		n++
		testResultBuf[n] = 'P'
		n++
		testResultBuf[n] = ':'
		n++
		if result == nil {
			testResultBuf[n] = 'F'
			n++
			testResultBuf[n] = 'A'
			n++
			testResultBuf[n] = 'I'
			n++
			testResultBuf[n] = 'L'
			n++
		} else {
			n += copyHexBytes(testResultBuf[n:], result[:8])
		}
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdBENCH) {
		// Benchmark: self-assignment Mul like Inv uses: a.Mul(&a, &b)
		var a, b Field
		a.SetInt(1)
		b.SetInt(2)
		a.Mul(&a, &b) // a = a * b (self-assignment)
		a.Normalize()
		testResultBuf[n] = 'B'
		n++
		testResultBuf[n] = 'E'
		n++
		testResultBuf[n] = 'N'
		n++
		testResultBuf[n] = 'C'
		n++
		testResultBuf[n] = 'H'
		n++
		testResultBuf[n] = ':'
		n++
		n += copyFieldHex(testResultBuf[n:], &a)
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdINV) {
		// Test Inv(1) using the actual Inv function
		var fd, result Field
		fd.SetInt(1)
		fd.Inv(&result)
		result.Normalize()
		testResultBuf[n] = 'I'
		n++
		testResultBuf[n] = 'N'
		n++
		testResultBuf[n] = 'V'
		n++
		testResultBuf[n] = ':'
		n++
		n += copyFieldHex(testResultBuf[n:], &result)
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdDBL) {
		// Test single point Double (non-infinity)
		initSecp256k1G()
		var xyz XYZ
		xyz.SetXY(&secp256k1G)
		xyz.Double(&xyz)
		var xy XY
		xy.SetXYZ(&xyz)
		var xBytes [32]byte
		xy.X.GetB32(xBytes[:])
		testResultBuf[n] = 'D'
		n++
		testResultBuf[n] = 'B'
		n++
		testResultBuf[n] = 'L'
		n++
		testResultBuf[n] = ':'
		n++
		n += copyHexBytes(testResultBuf[n:], xBytes[:8])
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdSETXYZ) {
		// Test SetXYZ on result of ECmultGen with seckey=1
		var seckey [32]byte
		seckey[31] = 1
		var xyz XYZ
		ECmultGen(&xyz, seckey[:])
		// Now do SetXYZ
		var xy XY
		xy.SetXYZ(&xyz)
		var xBytes [32]byte
		xy.X.GetB32(xBytes[:])
		testResultBuf[n] = 'S'
		n++
		testResultBuf[n] = 'X'
		n++
		testResultBuf[n] = 'Y'
		n++
		testResultBuf[n] = 'Z'
		n++
		testResultBuf[n] = ':'
		n++
		n += copyHexBytes(testResultBuf[n:], xBytes[:8])
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdLOOP2) {
		// Test 256 iterations of Double on infinity point
		var r XYZ
		r.Infinity = true
		for i := 0; i < 256; i++ {
			r.Double(&r)
		}
		testResultBuf[n] = 'L'
		n++
		testResultBuf[n] = '2'
		n++
		testResultBuf[n] = ':'
		n++
		if r.Infinity {
			testResultBuf[n] = 'I'
			n++
			testResultBuf[n] = 'N'
			n++
			testResultBuf[n] = 'F'
			n++
		} else {
			testResultBuf[n] = 'P'
			n++
			testResultBuf[n] = 'T'
			n++
		}
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdECM) {
		// Test just ECmultGen (no SetXYZ conversion)
		var seckey [32]byte
		seckey[31] = 1
		var xyz XYZ
		ECmultGen(&xyz, seckey[:])
		testResultBuf[n] = 'E'
		n++
		testResultBuf[n] = 'C'
		n++
		testResultBuf[n] = 'M'
		n++
		testResultBuf[n] = ':'
		n++
		if xyz.Infinity {
			testResultBuf[n] = 'I'
			n++
			testResultBuf[n] = 'N'
			n++
			testResultBuf[n] = 'F'
			n++
		} else {
			// Show Z coordinate (should be 1)
			var zBytes [32]byte
			xyz.Z.GetB32(zBytes[:])
			n += copyHexBytes(testResultBuf[n:], zBytes[28:32])
		}
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdVMNEM) {
		// Test mnemonic validation with new offset-based approach
		mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

		testResultBuf[n] = 'V'
		n++
		testResultBuf[n] = 'M'
		n++
		testResultBuf[n] = ':'
		n++

		// Test splitMnemonicInto
		wordCount := splitMnemonicInto(mnemonic)
		testResultBuf[n] = 'C'
		n++
		testResultBuf[n] = '0' + byte(wordCount/10)
		n++
		testResultBuf[n] = '0' + byte(wordCount%10)
		n++
		testResultBuf[n] = ','
		n++

		// Test findWordIndexInMnemonic for first word (should be 0)
		if wordCount > 0 {
			idx0 := findWordIndexInMnemonic(mnemonic, splitMnemonicOffsets[0], splitMnemonicLengths[0])
			testResultBuf[n] = 'W'
			n++
			testResultBuf[n] = '0'
			n++
			testResultBuf[n] = '='
			n++
			if idx0 < 0 {
				testResultBuf[n] = 'N'
				n++
			} else {
				testResultBuf[n] = '0' + byte(idx0)
				n++
			}
			testResultBuf[n] = ','
			n++
		}

		// Test findWordIndexInMnemonic for last word "about" (should be 3)
		if wordCount >= 12 {
			idx11 := findWordIndexInMnemonic(mnemonic, splitMnemonicOffsets[11], splitMnemonicLengths[11])
			testResultBuf[n] = 'W'
			n++
			testResultBuf[n] = 'B'
			n++
			testResultBuf[n] = '='
			n++
			if idx11 < 0 {
				testResultBuf[n] = 'N'
				n++
			} else {
				testResultBuf[n] = '0' + byte(idx11)
				n++
			}
			testResultBuf[n] = ','
			n++
		}

		// Test full validation
		valid := validateMnemonic(mnemonic)
		testResultBuf[n] = 'V'
		n++
		testResultBuf[n] = '='
		n++
		if valid {
			testResultBuf[n] = 'Y'
			n++
		} else {
			testResultBuf[n] = 'N'
			n++
		}

		sendSuccessBytes(testResultBuf[:n])
		return
	}

	// GENM - test mnemonic generation directly using bytes-based approach
	if len(cmd) == 4 && cmd[0] == 'G' && cmd[1] == 'E' && cmd[2] == 'N' && cmd[3] == 'M' {
		testResultBuf[n] = 'G'
		n++
		testResultBuf[n] = 'M'
		n++
		testResultBuf[n] = ':'
		n++
		// Generate a test mnemonic from fixed entropy
		var testEntropy [16]byte
		// All zeros should give: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		// Use bytes-based approach to avoid string corruption
		// Use global testMnemBuf to avoid stack overflow
		mLen := entropyToMnemonicBytes(testEntropy[:], testMnemBuf[:])
		testResultBuf[n] = 'L'
		n++
		testResultBuf[n] = hexDigit(byte(mLen / 100))
		n++
		testResultBuf[n] = hexDigit(byte((mLen / 10) % 10))
		n++
		testResultBuf[n] = hexDigit(byte(mLen % 10))
		n++
		testResultBuf[n] = ','
		n++
		// Show first 20 chars
		showLen := 20
		if mLen < showLen {
			showLen = mLen
		}
		for i := 0; i < showLen; i++ {
			c := testMnemBuf[i]
			if c >= 32 && c < 127 {
				testResultBuf[n] = c
			} else {
				testResultBuf[n] = '?'
			}
			n++
		}
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	// MNEM - show stored mnemonic info for debugging
	if len(cmd) == 4 && cmd[0] == 'M' && cmd[1] == 'N' && cmd[2] == 'E' && cmd[3] == 'M' {
		storageInit()
		testResultBuf[n] = 'M'
		n++
		testResultBuf[n] = 'N'
		n++
		testResultBuf[n] = ':'
		n++
		// Show HasMnemonic flag
		testResultBuf[n] = 'H'
		n++
		if storageHasMnemonic() {
			testResultBuf[n] = '1'
		} else {
			testResultBuf[n] = '0'
		}
		n++
		testResultBuf[n] = ','
		n++
		// Show MnemonicLen
		testResultBuf[n] = 'L'
		n++
		mnemonicBytes, mnemonicLen := storageGetMnemonicBytes()
		testResultBuf[n] = hexDigit(byte(mnemonicLen / 100))
		n++
		testResultBuf[n] = hexDigit(byte((mnemonicLen / 10) % 10))
		n++
		testResultBuf[n] = hexDigit(byte(mnemonicLen % 10))
		n++
		testResultBuf[n] = ','
		n++
		// Show first 20 bytes as chars
		testResultBuf[n] = 'D'
		n++
		testResultBuf[n] = ':'
		n++
		showLen := 20
		if mnemonicLen < showLen {
			showLen = mnemonicLen
		}
		if mnemonicBytes != nil {
			for i := 0; i < showLen; i++ {
				c := mnemonicBytes[i]
				if c >= 32 && c < 127 {
					testResultBuf[n] = c
				} else {
					testResultBuf[n] = '?'
				}
				n++
			}
		}
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdADDR) {
		// Test full address generation with test mnemonic
		mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		addrBytes := deriveAddressAtIndexBytes(mnemonic, 0)
		if len(addrBytes) == 0 {
			// Report debug states on failure
			testResultBuf[n] = 'A'
			n++
			testResultBuf[n] = 'D'
			n++
			testResultBuf[n] = 'D'
			n++
			testResultBuf[n] = 'R'
			n++
			testResultBuf[n] = ':'
			n++
			testResultBuf[n] = 'F'
			n++
			testResultBuf[n] = ':'
			n++
			testResultBuf[n] = 'P'
			n++
			testResultBuf[n] = '0' + debugPubkeyState
			n++
			testResultBuf[n] = 'E'
			n++
			testResultBuf[n] = '0' + debugEcdhState
			n++
			testResultBuf[n] = 'D'
			n++
			testResultBuf[n] = '0' + debugDecompressState
			n++
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

	// CMP - compare string-based vs bytes-based address generation using same hardcoded mnemonic
	if len(cmd) == 3 && cmd[0] == 'C' && cmd[1] == 'M' && cmd[2] == 'P' {
		mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		mnemonicBytes := []byte(mnemonic)
		mnemonicLen := len(mnemonic)

		// Old string-based path
		addr1 := deriveAddressAtIndexBytes(mnemonic, 0)

		// New bytes-based path
		addr2 := deriveAddressAtIndexFromBytes(mnemonicBytes, mnemonicLen, 0)

		n += copyBytes(testResultBuf[n:], []byte{'C', 'M', 'P', ':'})

		// Show string-based result (first 12 chars)
		n += copyBytes(testResultBuf[n:], []byte{'S', '='})
		showLen := 12
		if len(addr1) < showLen {
			showLen = len(addr1)
		}
		for i := 0; i < showLen; i++ {
			testResultBuf[n] = addr1[i]
			n++
		}

		n += copyBytes(testResultBuf[n:], []byte{','})

		// Show bytes-based result (first 12 chars)
		n += copyBytes(testResultBuf[n:], []byte{'B', '='})
		showLen = 12
		if len(addr2) < showLen {
			showLen = len(addr2)
		}
		for i := 0; i < showLen; i++ {
			testResultBuf[n] = addr2[i]
			n++
		}

		sendSuccessBytes(testResultBuf[:n])
		return
	}

	// STOR - compare stored mnemonic vs expected, and generate address from stored
	if len(cmd) == 4 && cmd[0] == 'S' && cmd[1] == 'T' && cmd[2] == 'O' && cmd[3] == 'R' {
		expected := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		storageInit()
		storedBytes, storedLen := storageGetMnemonicBytes()

		n += copyBytes(testResultBuf[n:], []byte{'S', 'T', 'O', 'R', ':'})

		// Show stored length vs expected length
		n += copyBytes(testResultBuf[n:], []byte{'L', '='})
		n += copyIntBytes(testResultBuf[n:], storedLen)
		n += copyBytes(testResultBuf[n:], []byte{'/', '9', '3', ','})

		// Compare first 20 bytes
		match := true
		if storedLen != len(expected) {
			match = false
		} else if storedBytes != nil {
			for i := 0; i < 20 && i < storedLen; i++ {
				if storedBytes[i] != expected[i] {
					match = false
					break
				}
			}
		} else {
			match = false
		}
		n += copyBytes(testResultBuf[n:], []byte{'M', '='})
		if match {
			testResultBuf[n] = 'Y'
		} else {
			testResultBuf[n] = 'N'
		}
		n++

		// Generate address from stored mnemonic
		n += copyBytes(testResultBuf[n:], []byte{','})
		if storedBytes != nil && storedLen > 0 {
			addr := deriveAddressAtIndexFromBytes(storedBytes, storedLen, 0)
			n += copyBytes(testResultBuf[n:], []byte{'A', '='})
			showLen := 12
			if len(addr) < showLen {
				showLen = len(addr)
			}
			for i := 0; i < showLen; i++ {
				testResultBuf[n] = addr[i]
				n++
			}
		} else {
			n += copyBytes(testResultBuf[n:], []byte{'A', '=', 'N', 'O', 'N', 'E'})
		}

		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdADDRDBG) {
		// Test address encoding with different buffer sizes
		mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		addrBytes := deriveAddressAtIndexBytes(mnemonic, 0)

		n += copyBytes(testResultBuf[n:], []byte{'A', 'D', 'D', 'R', 'D', 'B', 'G', ':'})

		if len(addrBytes) == 0 {
			n += copyBytes(testResultBuf[n:], []byte{'E', 'R', 'R', ':', 'N', 'O', 'A', 'D', 'D', 'R'})
		} else {
			// Copy address bytes to a LOCAL buffer first
			var localAddr [64]byte
			addrLen := len(addrBytes)
			for i := 0; i < addrLen; i++ {
				localAddr[i] = addrBytes[i]
			}

			// Test 1: [64]byte buffer with pbEncodeBytes
			var buf64 [64]byte
			len64 := pbEncodeBytes(buf64[:], 1, localAddr[:addrLen])
			n += copyBytes(testResultBuf[n:], []byte{'6', '4', '='})
			for i := 0; i < 4; i++ {
				testResultBuf[n] = hexCharsBytes[buf64[i]>>4]
				n++
				testResultBuf[n] = hexCharsBytes[buf64[i]&0x0f]
				n++
			}
			n += copyBytes(testResultBuf[n:], []byte{','})

			// Test 2: [512]byte buffer with pbEncodeBytes (like sendAllSkycoinAddresses)
			var buf512 [512]byte
			len512 := pbEncodeBytes(buf512[:], 1, localAddr[:addrLen])
			n += copyBytes(testResultBuf[n:], []byte{'5', '1', '2', '='})
			for i := 0; i < 4; i++ {
				testResultBuf[n] = hexCharsBytes[buf512[i]>>4]
				n++
				testResultBuf[n] = hexCharsBytes[buf512[i]&0x0f]
				n++
			}
			n += copyBytes(testResultBuf[n:], []byte{','})

			// Report lengths
			n += copyBytes(testResultBuf[n:], []byte{'l', '='})
			n += copyIntBytes(testResultBuf[n:], len64)
			n += copyBytes(testResultBuf[n:], []byte{','})
			n += copyIntBytes(testResultBuf[n:], len512)
			_ = len64
			_ = len512
		}
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdPBTEST) {
		// Test just pbEncodeVarint and pbEncodeTag directly
		n += copyBytes(testResultBuf[n:], []byte{'P', 'B', 'T', 'E', 'S', 'T', ':'})

		// Test 1: Write varint 10 to a buffer
		var buf1 [16]byte
		v1Len := pbEncodeVarint(buf1[:], 10)
		n += copyBytes(testResultBuf[n:], []byte{'v', '1', '='})
		n += copyIntBytes(testResultBuf[n:], int(buf1[0]))
		n += copyBytes(testResultBuf[n:], []byte{'(', 'l'})
		n += copyIntBytes(testResultBuf[n:], v1Len)
		n += copyBytes(testResultBuf[n:], []byte{')', ','})

		// Test 2: Write tag (field 1, wire 2) to a buffer
		var buf2 [16]byte
		t1Len := pbEncodeTag(buf2[:], 1, PB_BYTES)
		n += copyBytes(testResultBuf[n:], []byte{'t', '1', '='})
		n += copyIntBytes(testResultBuf[n:], int(buf2[0]))
		n += copyBytes(testResultBuf[n:], []byte{'(', 'l'})
		n += copyIntBytes(testResultBuf[n:], t1Len)
		n += copyBytes(testResultBuf[n:], []byte{')', ','})

		// Test 3: pbEncodeBytes with simple data
		var buf3 [32]byte
		testData := []byte{'A', 'B', 'C'}
		e1Len := pbEncodeBytes(buf3[:], 1, testData)
		n += copyBytes(testResultBuf[n:], []byte{'e', '1', '='})
		for i := 0; i < 5 && i < e1Len; i++ {
			testResultBuf[n] = hexCharsBytes[buf3[i]>>4]
			n++
			testResultBuf[n] = hexCharsBytes[buf3[i]&0x0f]
			n++
		}
		n += copyBytes(testResultBuf[n:], []byte{'(', 'l'})
		n += copyIntBytes(testResultBuf[n:], e1Len)
		n += copyBytes(testResultBuf[n:], []byte{')'})

		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdSECPV) {
		// Test secp256k1Sum with "seed" - C test vector expects:
		// c79454cf362b3f55e5effce09f664311650a44b9c189b3c8eed1ae9bd696cd9e
		seed := []byte("seed")
		result := secp256k1Sum(seed)
		testResultBuf[n] = 'S'
		n++
		testResultBuf[n] = 'E'
		n++
		testResultBuf[n] = 'C'
		n++
		testResultBuf[n] = 'P'
		n++
		testResultBuf[n] = 'V'
		n++
		testResultBuf[n] = ':'
		n++
		if result == nil {
			testResultBuf[n] = 'F'
			n++
			testResultBuf[n] = 'A'
			n++
			testResultBuf[n] = 'I'
			n++
			testResultBuf[n] = 'L'
			n++
		} else {
			// Output full 32-byte hash for comparison
			for i := 0; i < 32; i++ {
				testResultBuf[n] = hexCharsBytes[result[i]>>4]
				n++
				testResultBuf[n] = hexCharsBytes[result[i]&0x0f]
				n++
			}
		}
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdPK3) {
		// Test pubkey from seckey=3
		// expect 3G.x = f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9
		var seckey [32]byte
		seckey[31] = 3
		pubkey := pubkeyFromSeckey(seckey[:])

		n += copyBytes(testResultBuf[n:], []byte{'P', 'K', '3', ':'})
		n += copyHexBytes(testResultBuf[n:], pubkey[:17])
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdPK4) {
		// Test pubkey from seckey=4 (only uses Double, no AddXY on non-infinity)
		// 4G.x = e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13
		var seckey [32]byte
		seckey[31] = 4
		pubkey := pubkeyFromSeckey(seckey[:])

		n += copyBytes(testResultBuf[n:], []byte{'P', 'K', '4', ':'})
		n += copyHexBytes(testResultBuf[n:], pubkey[:17])
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdDBL2) {
		// Debug: manually do G -> 2G -> 4G and show X coords
		initSecp256k1G()
		var p XYZ
		p.SetXY(&secp256k1G) // p = G, Z=1

		// Get G.x
		var gx [32]byte
		p.X.GetB32(gx[:])

		// Double(G) = 2G
		var p2 XYZ
		p.Double(&p2)

		// Get 2G affine
		var xy2 XY
		xy2.SetXYZ(&p2)
		var x2 [32]byte
		xy2.X.GetB32(x2[:])

		// Double(2G) = 4G
		var p4 XYZ
		p2.Double(&p4)

		// Get 4G affine
		var xy4 XY
		xy4.SetXYZ(&p4)
		var x4 [32]byte
		xy4.X.GetB32(x4[:])

		// Output: G:xxxx,2G:xxxx,4G:xxxx
		n += copyBytes(testResultBuf[n:], []byte{'G', ':'})
		n += copyHexBytes(testResultBuf[n:], gx[:4])
		n += copyBytes(testResultBuf[n:], []byte{','})
		n += copyBytes(testResultBuf[n:], []byte{'2', 'G', ':'})
		n += copyHexBytes(testResultBuf[n:], x2[:4])
		n += copyBytes(testResultBuf[n:], []byte{','})
		n += copyBytes(testResultBuf[n:], []byte{'4', 'G', ':'})
		n += copyHexBytes(testResultBuf[n:], x4[:4])

		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdPKTEST) {
		// Test pubkey from C test vector seckey
		// seckey = a7e130694166cdb95b1e1bbce3f21e4dbd63f46df42b48c5a1f8295033d57d04
		// expect pubkey = 0244350faa76799fec03de2f324acd077fd1b686c3a89babc0ef47096ccc5a13fa
		seckey := [32]byte{
			0xa7, 0xe1, 0x30, 0x69, 0x41, 0x66, 0xcd, 0xb9,
			0x5b, 0x1e, 0x1b, 0xbc, 0xe3, 0xf2, 0x1e, 0x4d,
			0xbd, 0x63, 0xf4, 0x6d, 0xf4, 0x2b, 0x48, 0xc5,
			0xa1, 0xf8, 0x29, 0x50, 0x33, 0xd5, 0x7d, 0x04,
		}
		pubkey := pubkeyFromSeckey(seckey[:])

		n += copyBytes(testResultBuf[n:], []byte{'P', 'K', 'T', ':'})
		n += copyHexBytes(testResultBuf[n:], pubkey[:17])
		sendSuccessBytes(testResultBuf[:n])
		return
	}

	if bytesEqual(cmd, cmdSECPD) {
		// Debug secp256k1Sum with "seed" - show intermediate values
		seed := []byte("seed")

		// hash = SHA256(seed)
		hash := sha256Sum(seed)

		// Step 1: deterministic_key_pair_iterator_step(hash)
		var seckey1 [32]byte
		var pubkey1 [33]byte
		deterministicKeyPairIteratorStep(hash[:], seckey1[:], pubkey1[:])

		// hash2 = SHA256(hash)
		hash2 := sha256Sum(hash[:])

		// Step 2: deterministic_key_pair_iterator_step(hash2)
		var seckey2 [32]byte
		var pubkey2 [33]byte
		deterministicKeyPairIteratorStep(hash2[:], seckey2[:], pubkey2[:])

		// ECDH(pubkey2, seckey1)
		ecdhKey := ecdh(pubkey2[:], seckey1[:])

		// Output format: H1:xxxx,S1:xxxx,P1:xxxx,H2:xxxx,P2:xxxx,EC:xxxx
		n += copyBytes(testResultBuf[n:], []byte{'H', '1', ':'})
		n += copyHexBytes(testResultBuf[n:], hash[:8])
		n += copyBytes(testResultBuf[n:], []byte{','})

		n += copyBytes(testResultBuf[n:], []byte{'S', '1', ':'})
		n += copyHexBytes(testResultBuf[n:], seckey1[:8])
		n += copyBytes(testResultBuf[n:], []byte{','})

		n += copyBytes(testResultBuf[n:], []byte{'P', '1', ':'})
		n += copyHexBytes(testResultBuf[n:], pubkey1[:5])
		n += copyBytes(testResultBuf[n:], []byte{','})

		n += copyBytes(testResultBuf[n:], []byte{'P', '2', ':'})
		n += copyHexBytes(testResultBuf[n:], pubkey2[:5])
		n += copyBytes(testResultBuf[n:], []byte{','})

		n += copyBytes(testResultBuf[n:], []byte{'E', 'C', ':'})
		if ecdhKey != nil {
			n += copyHexBytes(testResultBuf[n:], ecdhKey[:8])
		} else {
			n += copyBytes(testResultBuf[n:], []byte{'N', 'I', 'L'})
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

	// Decode positions as bytes (avoid string conversion)
	posBytes, posLen := pbDecodePinMatrixAckBytes(msgInBuffer[:msgInSize])

	// Translate positions to actual digits using the displayed permutation
	pinMatrixDoneBytes(posBytes, posLen)

	// Return to home screen after PIN entry
	layoutHome()

	switch pinState {
	case PIN_STATE_VERIFY:
		// Verifying PIN for protected operation
		if storagePINCompareBytes(pinTranslated[:], pinTranslatedLen) {
			storageResetPINFailures() // Reset on success
			sessionCachePIN()
			pinState = PIN_STATE_IDLE

			// Resume pending operation
			op := pendingOperation
			pendingOperation = PENDING_OP_NONE
			switch op {
			case PENDING_OP_SKYCOIN_ADDRESS:
				doSkycoinAddress()
			case PENDING_OP_SIGN_MESSAGE:
				doSkycoinSignMessage()
			case PENDING_OP_TRANSACTION_SIGN:
				doTransactionSign()
			default:
				sendSuccess("")
			}
		} else {
			failures := storageIncrementPINFailures()
			pinState = PIN_STATE_IDLE
			pendingOperation = PENDING_OP_NONE
			if failures >= PIN_MAX_ATTEMPTS {
				sendFailure(FailureType_PinInvalid, "Device locked. Wipe required.")
			} else {
				sendFailure(FailureType_PinInvalid, "Invalid PIN")
			}
		}

	case PIN_STATE_CHANGE_OLD:
		// Verifying old PIN for change
		if storagePINCompareBytes(pinTranslated[:], pinTranslatedLen) {
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
		// First entry of new PIN - store in pinNewFirst
		pinNewFirstLen = pinTranslatedLen
		if pinNewFirstLen > 9 {
			pinNewFirstLen = 9
		}
		for i := 0; i < pinNewFirstLen; i++ {
			pinNewFirst[i] = pinTranslated[i]
		}
		pinState = PIN_STATE_CHANGE_NEW2
		sendPinMatrixRequest(PinMatrixRequestType_NewSecond)

	case PIN_STATE_CHANGE_NEW2:
		// Second entry of new PIN - verify match
		if pinTranslatedLen == pinNewFirstLen {
			match := true
			for i := 0; i < pinNewFirstLen; i++ {
				if pinTranslated[i] != pinNewFirst[i] {
					match = false
					break
				}
			}
			if match {
				// PINs match - save new PIN
				storageSetPINBytes(pinNewFirst[:], pinNewFirstLen)
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
	// Clear the PIN matrix permutation
	for i := range pinMatrixPerm {
		pinMatrixPerm[i] = 'X'
	}
	// Return to home screen
	layoutHome()
	sendFailure(FailureType_ActionCancelled, "Cancelled")
}

// handleWipeDevice handles the WipeDevice message
func handleWipeDevice() {
	// Request button confirmation - wipe is destructive!
	oledClear()
	oledDrawString(0, 0, "Wipe device?")
	oledDrawString(0, 16, "All data will be")
	oledDrawString(0, 26, "permanently lost!")
	oledDrawString(0, 48, "Hold YES to confirm")
	oledRefresh()

	// Set state to wait for wipe confirmation
	btnState = BTN_STATE_WIPE_CONFIRM

	// Send button request to host
	sendButtonRequest(ButtonRequestType_WipeDevice)
}

// PIN matrix permutation - stores scrambled digit positions
var pinMatrixPerm [10]byte

// pinMatrixStart generates a random permutation and displays the PIN matrix
func pinMatrixStart(text string) {
	// Initialize with digits 1-9
	for i := 0; i < 9; i++ {
		pinMatrixPerm[i] = '1' + byte(i)
	}
	pinMatrixPerm[9] = 0

	// Fisher-Yates shuffle using hardware RNG
	var rngBuf [1]byte
	for i := 8; i > 0; i-- {
		getEntropy(rngBuf[:])
		j := int(rngBuf[0]) % (i + 1)
		pinMatrixPerm[i], pinMatrixPerm[j] = pinMatrixPerm[j], pinMatrixPerm[i]
	}

	// Draw the PIN matrix on OLED
	pinMatrixDraw(text)
}

// pinMatrixDraw draws the PIN matrix on the OLED
func pinMatrixDraw(text string) {
	oledClear()

	// Draw title text at top
	if text != "" {
		oledDrawString(0, 0, text)
	}

	// Draw 3x3 grid with scrambled digits
	// Layout: positions on screen map to pinMatrixPerm indices
	// Top row (y=16): positions 6,7,8 -> digits at perm[6],perm[7],perm[8]
	// Mid row (y=32): positions 3,4,5 -> digits at perm[3],perm[4],perm[5]
	// Bot row (y=48): positions 0,1,2 -> digits at perm[0],perm[1],perm[2]
	// This gives visual layout:
	//   perm[6] perm[7] perm[8]   (top)
	//   perm[3] perm[4] perm[5]   (mid)
	//   perm[0] perm[1] perm[2]   (bot)
	// Which corresponds to standard numpad positions 7,8,9 / 4,5,6 / 1,2,3

	// Cell dimensions
	cellW := 30
	cellH := 16
	startX := (128 - 3*cellW) / 2
	startY := 16

	for row := 0; row < 3; row++ {
		for col := 0; col < 3; col++ {
			// Map visual position to permutation index
			// row 0 (top of screen) = positions 6,7,8 (numpad 7,8,9)
			// row 1 (mid) = positions 3,4,5 (numpad 4,5,6)
			// row 2 (bot) = positions 0,1,2 (numpad 1,2,3)
			permIdx := (2-row)*3 + col
			digit := pinMatrixPerm[permIdx]

			// Calculate cell position
			x := startX + col*cellW
			y := startY + row*cellH

			// Draw cell border
			oledDrawRect(x, y, x+cellW-2, y+cellH-2)

			// Draw digit in center of cell
			digitX := x + (cellW-6)/2
			digitY := y + (cellH-8)/2
			oledDrawChar(digitX, digitY, digit)
		}
	}

	oledRefresh()
}

// oledDrawRect draws a rectangle outline
func oledDrawRect(x1, y1, x2, y2 int) {
	// Top and bottom lines
	for x := x1; x <= x2; x++ {
		oledSetPixel(x, y1, true)
		oledSetPixel(x, y2, true)
	}
	// Left and right lines
	for y := y1; y <= y2; y++ {
		oledSetPixel(x1, y, true)
		oledSetPixel(x2, y, true)
	}
}

// pinMatrixDone translates entered positions to actual digits using the permutation
// DEPRECATED: Use pinMatrixDoneBytes instead to avoid TinyGo string issues
func pinMatrixDone(pin string) string {
	var result [10]byte
	for i := 0; i < len(pin) && i < 9; i++ {
		k := pin[i] - '1'
		if k >= 0 && k <= 8 {
			result[i] = pinMatrixPerm[k]
		} else {
			break
		}
	}
	// Clear permutation for security
	for i := range pinMatrixPerm {
		pinMatrixPerm[i] = 'X'
	}
	return string(result[:len(pin)])
}

// pinMatrixDoneBytes translates entered positions to actual digits using the permutation
// Writes result to pinTranslated buffer and sets pinTranslatedLen
// This avoids string conversion issues in TinyGo bare-metal mode
func pinMatrixDoneBytes(positions []byte, posLen int) {
	pinTranslatedLen = 0
	for i := 0; i < posLen && i < 9; i++ {
		k := positions[i] - '1'
		if k <= 8 { // k is uint8, so k >= 0 is always true
			pinTranslated[pinTranslatedLen] = pinMatrixPerm[k]
			pinTranslatedLen++
		} else {
			break
		}
	}
	// Clear permutation for security
	for i := range pinMatrixPerm {
		pinMatrixPerm[i] = 'X'
	}
}

// sendPinMatrixRequest sends a PinMatrixRequest message and displays the matrix
func sendPinMatrixRequest(pinType uint32) {
	// Display appropriate text based on request type
	var text string
	switch pinType {
	case PinMatrixRequestType_Current:
		text = "Enter current PIN"
	case PinMatrixRequestType_NewFirst:
		text = "Enter new PIN"
	case PinMatrixRequestType_NewSecond:
		text = "Re-enter new PIN"
	default:
		text = "Enter PIN"
	}

	// Generate and display the PIN matrix (new random permutation each time)
	pinMatrixStart(text)

	// Send the request message
	var buf [8]byte
	n := pbEncodePinMatrixRequest(buf[:], pinType)
	msgWrite(MessageType_PinMatrixRequest, buf[:n])
}

// requirePIN checks if PIN is required and starts verification if needed
// Returns true if operation can proceed, false if waiting for PIN
func requirePIN() bool {
	return requirePINForOp(PENDING_OP_NONE)
}

// requirePINForOp checks if PIN is required and saves the pending operation
func requirePINForOp(op int) bool {
	storageInit()
	if !storageHasPIN() {
		return true // No PIN set
	}
	if sessionIsPINcached() {
		return true // PIN already verified this session
	}
	// Need PIN verification - save pending operation
	pendingOperation = op
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

	if DebugMode {
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
		usbDelay(3000000)
	}

	// Generate mnemonic directly into storage buffer (avoids string conversion corruption)
	storageInit()
	mnemonicDest := storageGetMnemonicDest()
	mnemonicLen := entropyToMnemonicBytes(entropy, mnemonicDest)
	storageSetMnemonicBytes(mnemonicLen)

	if DebugMode {
		// Debug screen 2: show mnemonic result
		oledClear()
		x := 0
		// Line 0: "L:" + mnemonic length
		x += oledDrawChar(x, 0, 'L')
		x += oledDrawChar(x, 0, ':')
		mlen := mnemonicLen
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
		// Line 10: first 16 chars of mnemonic (read from storage)
		x = 0
		for i := 0; i < 16 && i < mnemonicLen; i++ {
			x += oledDrawChar(x, 10, mnemonicDest[i])
		}
		// Line 20: next 16 chars of mnemonic (chars 16-31)
		x = 0
		for i := 16; i < 32 && i < mnemonicLen; i++ {
			x += oledDrawChar(x, 20, mnemonicDest[i])
		}
		oledRefresh()
		usbDelay(3000000)
	}

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

	// Generate device entropy using fixed buffer
	entropySize := 16
	if mnemonicWordCount == 24 {
		entropySize = 32
	}
	getEntropy(entropyAckDeviceBuf[:entropySize])

	// Mix entropy: XOR host entropy with device entropy (use fixed buffer)
	for i := 0; i < entropySize; i++ {
		if i < len(hostEntropy) {
			entropyAckMixedBuf[i] = entropyAckDeviceBuf[i] ^ hostEntropy[i]
		} else {
			entropyAckMixedBuf[i] = entropyAckDeviceBuf[i]
		}
	}

	// Generate mnemonic directly into storage buffer (avoids string conversion corruption)
	storageInit()
	mnemonicDest := storageGetMnemonicDest()
	mnemonicLen := entropyToMnemonicBytes(entropyAckMixedBuf[:entropySize], mnemonicDest)
	storageSetMnemonicBytes(mnemonicLen)

	mnemonicState = MNEMONIC_STATE_IDLE

	// Send success
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

	// Get mnemonic offset and length from message (avoid string allocation)
	mnemonicOffset, mnemonicLen := pbDecodeSetMnemonicBytes(msgInBuffer[:msgInSize])

	if mnemonicLen == 0 {
		sendFailure(FailureType_DataError, "No mnemonic provided")
		return
	}

	// Get the mnemonic byte slice directly from msgInBuffer
	mnemonicBytes := msgInBuffer[mnemonicOffset : mnemonicOffset+mnemonicLen]

	// Validate mnemonic using bytes-based validation (no string allocation)
	if !validateMnemonicBytes(mnemonicBytes) {
		sendFailure(FailureType_DataError, "Invalid mnemonic")
		return
	}

	// Store mnemonic - copy bytes directly to avoid string() corruption
	storageSetMnemonicFromBuffer(mnemonicBytes, mnemonicLen)
	storageSetNeedsBackup(false) // Imported = already backed up

	// Update display to show initialized state
	layoutHome()

	sendSuccess("Mnemonic set")
}

// Fixed buffer for GetEntropy response (max 1024 bytes)
var getEntropyBuf [1024]byte

// entropyResponseBuf is a global buffer for entropy response encoding
// (local [1040]byte causes stack overflow in TinyGo bare-metal mode)
var entropyResponseBuf [1040]byte

// handleGetRawEntropy handles the GetRawEntropy/GetEntropy message
// Returns raw entropy from hardware RNG
func handleGetRawEntropy() {
	// Decode size from message (default 32, max 1024)
	size := pbDecodeGetEntropy(msgInBuffer[:msgInSize])
	if size > 1024 {
		size = 1024
	}
	if size <= 0 {
		size = 32
	}

	// Get raw entropy from hardware RNG
	getEntropy(getEntropyBuf[:size])

	n := pbEncodeEntropy(entropyResponseBuf[:], getEntropyBuf[:size])
	msgWrite(MessageType_Entropy, entropyResponseBuf[:n])
}

// Mixed entropy internal state (for GetMixedEntropy)
var mixedEntropyState [32]byte
var mixedEntropyInitialized bool

// rawEntropyBuf is a global buffer for raw entropy storage
// (local [1024]byte causes stack overflow in TinyGo bare-metal mode)
var rawEntropyBuf [1024]byte

// handleGetMixedEntropy handles the GetMixedEntropy message
// Returns entropy mixed with internal state (salted random)
func handleGetMixedEntropy() {
	// Decode size from message (default 32, max 1024)
	size := pbDecodeGetEntropy(msgInBuffer[:msgInSize])
	if size > 1024 {
		size = 1024
	}
	if size <= 0 {
		size = 32
	}

	// Initialize mixed entropy state if needed
	if !mixedEntropyInitialized {
		getEntropy(mixedEntropyState[:])
		mixedEntropyInitialized = true
	}

	// Get raw entropy from hardware RNG
	getEntropy(rawEntropyBuf[:size])

	// Mix raw entropy with internal state using XOR and hash
	for i := 0; i < size; i++ {
		getEntropyBuf[i] = rawEntropyBuf[i] ^ mixedEntropyState[i%32]
	}

	// Update internal state with hash of mixed entropy
	newState := sha256Sum(getEntropyBuf[:size])
	copy(mixedEntropyState[:], newState[:])

	n := pbEncodeEntropy(entropyResponseBuf[:], getEntropyBuf[:size])
	msgWrite(MessageType_Entropy, entropyResponseBuf[:n])
}

// handleBackupDevice handles the BackupDevice message
func handleBackupDevice() {
	storageInit()

	// Check if device is initialized
	if !storageIsInitialized() {
		sendFailure(FailureType_NotInitialized, "Mnemonic required")
		return
	}

	// Check if backup is needed
	if !storageNeedsBackup() {
		sendFailure(FailureType_UnexpectedMessage, "Already backed up")
		return
	}

	// Get mnemonic bytes using helper function (avoids direct struct access issues)
	mnemonicBytes, mnemonicLen := storageGetMnemonicBytes()
	if mnemonicBytes == nil || mnemonicLen == 0 {
		sendFailure(FailureType_NotInitialized, "No mnemonic stored")
		return
	}

	// Split mnemonic into words and store in byte buffers
	pendingMnemonicWordCount = 0
	wordStart := 0
	for i := 0; i <= mnemonicLen; i++ {
		// Check for space or end of mnemonic
		if i == mnemonicLen || mnemonicBytes[i] == ' ' {
			wordLen := i - wordStart
			if wordLen > 0 && pendingMnemonicWordCount < 24 {
				// Copy word to buffer
				if wordLen > 9 {
					wordLen = 9
				}
				for j := 0; j < wordLen; j++ {
					backupWordBufs[pendingMnemonicWordCount][j] = mnemonicBytes[wordStart+j]
				}
				backupWordLens[pendingMnemonicWordCount] = wordLen
				pendingMnemonicWordCount++
			}
			wordStart = i + 1
		}
	}

	// Start backup process - two passes through all words
	mnemonicBackupIndex = 0
	mnemonicBackupPass = 0 // First pass: "Write down the seed"
	mnemonicState = MNEMONIC_STATE_BACKUP_WAIT_ACK

	// Display first word
	displayBackupWordBytes(mnemonicBackupIndex+1, backupWordBufs[mnemonicBackupIndex][:], backupWordLens[mnemonicBackupIndex], mnemonicBackupPass, pendingMnemonicWordCount)

	// Send button request
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
	// Handle wipe confirmation
	if btnState == BTN_STATE_WIPE_CONFIRM {
		// Wait for physical button press
		if !waitForButton(false) { // false = allow cancel with No button
			btnState = BTN_STATE_IDLE
			sendFailure(FailureType_ActionCancelled, "Cancelled")
			layoutHome()
			return
		}

		// User confirmed wipe
		btnState = BTN_STATE_IDLE
		storageWipe()
		layoutHome()
		sendSuccess("Device wiped")
		return
	}

	// Check address confirmation state
	if addrState == ADDR_STATE_WAIT_BUTTON {
		// User confirmed - send all pending addresses
		sendAllSkycoinAddresses()
		return
	}

	// Handle backup state - got ButtonAck, now wait for physical button
	if mnemonicState == MNEMONIC_STATE_BACKUP_WAIT_ACK {
		mnemonicState = MNEMONIC_STATE_BACKUP_WAIT_BTN

		// Wait for physical button press (blocking)
		if !waitForButton(true) {
			// Cancelled (shouldn't happen with confirmOnly=true)
			mnemonicState = MNEMONIC_STATE_IDLE
			sendFailure(FailureType_ActionCancelled, "Cancelled")
			layoutHome()
			return
		}

		// Button was pressed - advance to next word
		mnemonicBackupIndex++

		// Check if we need to move to pass 2 or finish
		if mnemonicBackupIndex >= pendingMnemonicWordCount {
			// Finished current pass
			if mnemonicBackupPass == 0 {
				// First pass done - start second pass (verify)
				mnemonicBackupPass = 1
				mnemonicBackupIndex = 0
			} else {
				// Both passes complete
				storageSetNeedsBackup(false)
				mnemonicState = MNEMONIC_STATE_IDLE
				clearBackupDisplay()
				layoutHome()
				sendSuccess("Device backed up!")
				return
			}
		}

		// Display next word
		displayBackupWordBytes(mnemonicBackupIndex+1, backupWordBufs[mnemonicBackupIndex][:], backupWordLens[mnemonicBackupIndex], mnemonicBackupPass, pendingMnemonicWordCount)

		// Request next button press
		mnemonicState = MNEMONIC_STATE_BACKUP_WAIT_ACK
		sendButtonRequest(ButtonRequestType_ConfirmWord)
		return
	}

	// Unexpected ButtonAck
	sendFailure(FailureType_UnexpectedMessage, "Unexpected button ack")
}

// displayBackupWord shows a backup word on the OLED (legacy - single pass)
func displayBackupWord(index int, word string) {
	displayBackupWordBytes(index, []byte(word), len(word), 0, 12)
}

// displayBackupWordBytes shows a backup word on the OLED with pass info
// Uses byte slice to avoid TinyGo string issues
// pass 0 = "Write down the seed", pass 1 = "Please check the seed"
func displayBackupWordBytes(index int, wordBytes []byte, wordLen int, pass int, totalWords int) {
	oledClear()

	// Show action based on pass
	if pass == 0 {
		oledDrawString(4, 0, "Write down seed")
	} else {
		oledDrawString(4, 0, "Check the seed")
	}

	// Show word position: "##th word is:"
	x := 4
	if index < 10 {
		oledDrawChar(x, 16, ' ')
		x += 6
	} else {
		x += oledDrawChar(x, 16, '0'+byte(index/10))
	}
	x += oledDrawChar(x, 16, '0'+byte(index%10))

	// Add ordinal suffix
	if index == 1 {
		oledDrawString(x, 16, "st word is:")
	} else if index == 2 {
		oledDrawString(x, 16, "nd word is:")
	} else if index == 3 {
		oledDrawString(x, 16, "rd word is:")
	} else {
		oledDrawString(x, 16, "th word is:")
	}

	// Show the word (centered on y=32) - draw byte by byte
	wordWidth := wordLen * 6
	startX := (128 - wordWidth) / 2
	if startX < 0 {
		startX = 0
	}
	for i := 0; i < wordLen; i++ {
		startX += oledDrawChar(startX, 32, wordBytes[i])
	}

	// Show button hint based on position
	isLast := index >= totalWords
	if isLast {
		if pass == 0 {
			oledDrawString(88, 56, "Again>")
		} else {
			oledDrawString(80, 56, "Finish>")
		}
	} else {
		oledDrawString(92, 56, "Next>")
	}

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

// pendingAddressesBytes stores addresses as byte arrays to avoid TinyGo string issues
var pendingAddressesBytes [10][36]byte // Max 10 addresses, 35 chars each
var pendingAddressLens [10]int
var pendingAddressCount = 0

// Compatibility wrapper - still used in some places
var pendingAddresses [10]string // Max 10 addresses - deprecated

// handleSkycoinAddress handles the SkycoinAddress message
func handleSkycoinAddress() {
	storageInit()

	// Check if device is initialized
	if !storageIsInitialized() {
		sendFailure(FailureType_NotInitialized, "Mnemonic required")
		return
	}

	// Check PIN if required
	if !requirePINForOp(PENDING_OP_SKYCOIN_ADDRESS) {
		return // Waiting for PIN - will resume after verification
	}

	// Continue with address generation
	doSkycoinAddress()
}

// doSkycoinAddress performs the actual address generation (after PIN verification)
func doSkycoinAddress() {

	// Decode message fields
	addressN, startIndex, confirmAddress := pbDecodeSkycoinAddress(msgInBuffer[:msgInSize])

	// Limit addressN to reasonable value
	if addressN <= 0 {
		addressN = 1
	}
	if addressN > 10 {
		addressN = 10
	}

	// Get mnemonic from storage as bytes (avoid string() conversion corruption)
	mnemonicBytes, mnemonicLen := storageGetMnemonicBytes()
	if mnemonicBytes == nil || mnemonicLen == 0 {
		sendFailure(FailureType_NotInitialized, "No mnemonic")
		return
	}

	if DebugMode {
		// Debug: show mnemonic info using direct char output
		oledClear()
		// Show raw MnemonicLen from storage
		x := 0
		x += oledDrawChar(x, 0, 'L')
		x += oledDrawChar(x, 0, 'e')
		x += oledDrawChar(x, 0, 'n')
		x += oledDrawChar(x, 0, ':')
		mlen := mnemonicLen
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
		for i := 0; i < 10 && i < mnemonicLen; i++ {
			x += oledDrawChar(x, 10, mnemonicBytes[i])
		}
		oledRefresh()
	}

	// Generate all requested addresses using bytes to avoid TinyGo string issues
	pendingAddressCount = 0

	for i := 0; i < addressN; i++ {
		addrBytes := deriveAddressAtIndexFromBytes(mnemonicBytes, mnemonicLen, startIndex+i)
		if len(addrBytes) == 0 {
			if DebugMode {
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
			}
			// Send failure with debug info
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
				sendFailure(FailureType_ProcessError, "Address failed")
			}
			return
		}
		// Copy to pending byte buffer
		addrLen := len(addrBytes)
		if addrLen > 35 {
			addrLen = 35
		}
		for j := 0; j < addrLen; j++ {
			pendingAddressesBytes[i][j] = addrBytes[j]
		}
		pendingAddressLens[i] = addrLen
		pendingAddressCount++
	}

	// Display first address on OLED using bytes
	if pendingAddressCount > 0 {
		displayAddressBytes(pendingAddressesBytes[0][:], pendingAddressLens[0])
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

// addressResponseBuf is a global buffer for address response encoding
// (local [512]byte causes stack overflow in TinyGo bare-metal mode)
var addressResponseBuf [512]byte

// sendAllSkycoinAddresses sends all pending addresses
func sendAllSkycoinAddresses() {
	// Encode all addresses in response using global buffer
	// Note: Using global buffer to avoid stack overflow with large local arrays
	n := 0
	for i := 0; i < pendingAddressCount; i++ {
		// Encode address bytes directly as protobuf string field
		n += pbEncodeBytesAsString(addressResponseBuf[n:], ResponseSkycoinAddress_addresses, pendingAddressesBytes[i][:pendingAddressLens[i]])
	}

	msgWrite(MessageType_ResponseSkycoinAddress, addressResponseBuf[:n])
	addrState = ADDR_STATE_IDLE
}

// intToStrBuf is a package-level buffer for intToStr
var intToStrBuf [12]byte

// intToStr converts int to string (simple implementation)
// Uses package-level buffer to avoid TinyGo string allocation issues
func intToStr(n int) string {
	if n == 0 {
		intToStrBuf[0] = '0'
		return string(intToStrBuf[:1])
	}
	i := 11
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 && i >= 0 {
		intToStrBuf[i] = '0' + byte(n%10)
		n /= 10
		i--
	}
	if neg && i >= 0 {
		intToStrBuf[i] = '-'
		i--
	}
	return string(intToStrBuf[i+1 : 12])
}

// displayAddressBytes shows an address on the OLED display using byte slice
// This avoids all TinyGo string issues
func displayAddressBytes(addr []byte, addrLen int) {
	// Clear display area
	for y := 16; y < 64; y++ {
		for x := 0; x < 128; x++ {
			oledSetPixel(x, y, false)
		}
	}

	oledDrawString(4, 24, "Address:")

	// Draw address character by character on two lines
	x := 4

	// First line: chars 0-15
	for i := 0; i < 16 && i < addrLen; i++ {
		x += oledDrawChar(x, 36, addr[i])
	}

	// Second line: chars 16-31
	if addrLen > 16 {
		x = 4
		for i := 16; i < 32 && i < addrLen; i++ {
			x += oledDrawChar(x, 48, addr[i])
		}
	}

	oledRefresh()
}

// displayAddress shows an address on the OLED display (string version, may have issues)
// Prefer displayAddressBytes for reliability
func displayAddress(address string) {
	displayAddressBytes([]byte(address), len(address))
}

// handleSkycoinSignMessage handles the SkycoinSignMessage message
func handleSkycoinSignMessage() {
	storageInit()

	// Check if device is initialized
	if !storageIsInitialized() {
		sendFailure(FailureType_NotInitialized, "Mnemonic required")
		return
	}

	// Check PIN if required
	if !requirePINForOp(PENDING_OP_SIGN_MESSAGE) {
		return // Waiting for PIN - will resume after verification
	}

	// Continue with signing
	doSkycoinSignMessage()
}

// doSkycoinSignMessage performs the actual message signing (after PIN verification)
func doSkycoinSignMessage() {
	// Decode the message
	addrIndex, message := pbDecodeSkycoinSignMessage(msgInBuffer[:msgInSize])

	// Get mnemonic from storage as bytes (avoid string() conversion corruption)
	mnemonicBytes, mnemonicLen := storageGetMnemonicBytes()
	if mnemonicBytes == nil || mnemonicLen == 0 {
		sendFailure(FailureType_NotInitialized, "No mnemonic")
		return
	}

	// Derive key at specified index using bytes
	seckey := deriveSecretKeyAtIndexFromBytes(mnemonicBytes, mnemonicLen, addrIndex)
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

	// Show first part of signature - draw character by character
	sigLen := len(sigHex)
	x := 4
	// First line: chars 0-19
	for i := 0; i < 20 && i < sigLen; i++ {
		x += oledDrawChar(x, 36, sigHex[i])
	}
	// Second line: chars 20-39
	if sigLen > 20 {
		x = 4
		for i := 20; i < 40 && i < sigLen; i++ {
			x += oledDrawChar(x, 48, sigHex[i])
		}
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

// handleLoadDevice handles the LoadDevice message
// This allows importing a mnemonic with optional settings (for testing/recovery)
func handleLoadDevice() {
	storageInit()

	// Check if device is already initialized
	if storageIsInitialized() {
		sendFailure(FailureType_UnexpectedMessage, "Already initialized")
		return
	}

	// Decode the message using bytes-based decoder to avoid string() corruption
	mnemonicOffset, mnemonicLen, pinOffset, pinLen, passphraseProtection,
		languageOffset, languageLen, labelOffset, labelLen, skipChecksum :=
		pbDecodeLoadDeviceBytes(msgInBuffer[:msgInSize])

	// Validate mnemonic unless skip_checksum is set
	if mnemonicLen == 0 {
		sendFailure(FailureType_DataError, "No mnemonic provided")
		return
	}

	// Get mnemonic bytes directly from msgInBuffer
	mnemonicBytes := msgInBuffer[mnemonicOffset : mnemonicOffset+mnemonicLen]

	if !skipChecksum {
		if !validateMnemonicBytes(mnemonicBytes) {
			sendFailure(FailureType_DataError, "Invalid mnemonic checksum")
			return
		}
	}

	// Store mnemonic - copy bytes directly to avoid string() corruption
	storageSetMnemonicFromBuffer(mnemonicBytes, mnemonicLen)
	storageSetNeedsBackup(false) // Loaded device = already backed up

	// Set PIN if provided - copy bytes directly
	if pinLen > 0 {
		storageSetPINBytes(msgInBuffer[pinOffset:pinOffset+pinLen], pinLen)
	}

	// Set passphrase protection
	storageSetPassphraseProtection(passphraseProtection)

	// Set language if provided - copy bytes directly
	if languageLen > 0 {
		storageSetLanguageFromBuffer(msgInBuffer[languageOffset:languageOffset+languageLen], languageLen)
	}

	// Set label if provided - copy bytes directly
	if labelLen > 0 {
		storageSetLabelFromBuffer(msgInBuffer[labelOffset:labelOffset+labelLen], labelLen)
		storageSave() // Save after label since it doesn't auto-save
	}

	// Update display
	layoutHome()

	sendSuccess("Device loaded")
}

// handleResetDevice handles the ResetDevice message (Trezor-compatible)
// This generates a new mnemonic with specified settings
func handleResetDevice() {
	storageInit()

	// Check if device is already initialized
	if storageIsInitialized() {
		sendFailure(FailureType_UnexpectedMessage, "Already initialized")
		return
	}

	// Decode the message
	strength, passphraseProtection, pinProtection, language, label, skipBackup := pbDecodeResetDevice(msgInBuffer[:msgInSize])

	// Determine word count from strength
	// 128 bits = 12 words, 256 bits = 24 words
	wordCount := 24
	entropySize := 32
	if strength <= 128 {
		wordCount = 12
		entropySize = 16
	}

	// Generate entropy using hardware RNG
	getEntropy(entropyBuffer[:entropySize])
	entropy := entropyBuffer[:entropySize]

	// Generate mnemonic directly into storage buffer (avoids string conversion corruption)
	mnemonicDest := storageGetMnemonicDest()
	mnemonicLen := entropyToMnemonicBytes(entropy, mnemonicDest)
	storageSetMnemonicBytes(mnemonicLen)

	// Set needs_backup based on skip_backup flag (override the default set by storageSetMnemonicBytes)
	if skipBackup {
		storageSetNeedsBackup(false)
	}

	// Set passphrase protection
	storageSetPassphraseProtection(passphraseProtection)

	// Set language if provided
	if language != "" {
		storageSetLanguage(language)
	}

	// Set label if provided
	if label != "" {
		storageSetLabel(label)
	}

	// If PIN protection requested, start PIN flow
	// For simplicity, we'll just note it - full PIN flow would need state machine
	_ = pinProtection

	// Update display
	layoutHome()

	// Display word count info
	oledClear()
	oledDrawString(4, 0, "Device Reset")
	oledDrawString(4, 16, "Words:")
	oledDrawInt(52, 16, wordCount)
	oledRefresh()
	usbDelay(2000000)

	// Show mnemonic start if not skipping backup
	if !skipBackup {
		oledClear()
		oledDrawString(4, 0, "Backup needed")
		oledDrawString(4, 16, "Use BackupDevice")
		oledRefresh()
		usbDelay(2000000)
	}

	layoutHome()

	sendSuccess("Device reset")
}
