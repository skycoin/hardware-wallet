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
	// Debug: show received message ID
	debugShowMsgID(msgInID)

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

	default:
		// Unknown message type
		sendFailure(FailureType_UnexpectedMessage, "Unknown message")
	}
}

// debugShowMsgID shows the message ID on display (disabled)
func debugShowMsgID(id uint16) {
	_ = id
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
func handlePing() {
	// Decode the ping message to get the echo string
	message := pbDecodePing(msgInBuffer[:msgInSize])

	// Send Success with the same message
	sendSuccess(message)
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
	pin := pbDecodePinMatrixAck(msgInBuffer[:msgInSize])

	switch pinState {
	case PIN_STATE_VERIFY:
		// Verifying PIN for protected operation
		if storagePINCompare(pin) {
			sessionCachePIN()
			pinState = PIN_STATE_IDLE
			sendSuccess("")
		} else {
			pinState = PIN_STATE_IDLE
			sendFailure(FailureType_PinInvalid, "Invalid PIN")
		}

	case PIN_STATE_CHANGE_OLD:
		// Verifying old PIN for change
		if storagePINCompare(pin) {
			pinState = PIN_STATE_CHANGE_NEW1
			sendPinMatrixRequest(PinMatrixRequestType_NewFirst)
		} else {
			pinState = PIN_STATE_IDLE
			sendFailure(FailureType_PinInvalid, "Invalid PIN")
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
	entropy := make([]byte, entropySize)
	getEntropy(entropy)

	// Generate mnemonic from entropy
	mnemonic := entropyToMnemonic(entropy)

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

	// Get address index from message (default 0)
	addrIndex := pbDecodeSkycoinAddress(msgInBuffer[:msgInSize])

	// Get mnemonic from storage
	mnemonic := storageGetMnemonic()
	if mnemonic == "" {
		sendFailure(FailureType_NotInitialized, "No mnemonic")
		return
	}

	// Derive address at specified index using Skycoin's deterministic derivation
	address := deriveAddressAtIndex(mnemonic, addrIndex)
	if address == "" {
		sendFailure(FailureType_ProcessError, "Key derivation failed")
		return
	}

	// Display address on OLED
	displayAddress(address)

	// Send response
	sendSkycoinAddressResponse(address)
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

// sendSkycoinAddressResponse sends a ResponseSkycoinAddress message
func sendSkycoinAddressResponse(address string) {
	var buf [64]byte
	n := pbEncodeSkycoinAddressResponse(buf[:], address)
	msgWrite(MessageType_ResponseSkycoinAddress, buf[:n])
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
