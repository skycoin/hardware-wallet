package main

// Recovery device flow implementation

// Recovery state machine
const (
	RECOVERY_IDLE = iota
	RECOVERY_WAITING_WORD
)

var recoveryState = RECOVERY_IDLE
var recoveryWordCount = 12
var recoveryWordIndex = 0
var recoveryDryRun = false

// recoveryWordBufs stores words as byte buffers to avoid TinyGo string issues
var recoveryWordBufs [24][9]byte // Max 24 words, max 8 chars each + null
var recoveryWordLens [24]int

// Legacy string array - kept for any code that needs it
var recoveryWords [24]string

// handleRecoveryDevice handles the RecoveryDevice message
func handleRecoveryDevice() {
	storageInit()

	// Check if device is already initialized (unless dry run)
	wordCount, _, _, dryRun := pbDecodeRecoveryDevice(msgInBuffer[:msgInSize])

	if !dryRun && storageIsInitialized() {
		sendFailure(FailureType_UnexpectedMessage, "Already initialized")
		return
	}

	// Set word count (default 12)
	if wordCount != 12 && wordCount != 24 {
		wordCount = 12
	}

	recoveryWordCount = wordCount
	recoveryWordIndex = 0
	recoveryDryRun = dryRun

	// Clear words
	for i := range recoveryWords {
		recoveryWords[i] = ""
	}

	// Start recovery
	recoveryState = RECOVERY_WAITING_WORD

	// Display recovery start
	layoutRecoveryStart()

	// Send first word request
	sendWordRequest(WordRequestType_Plain)
}

// handleWordAck handles the WordAck message
func handleWordAck() {
	if recoveryState != RECOVERY_WAITING_WORD {
		sendFailure(FailureType_UnexpectedMessage, "Unexpected word")
		return
	}

	// Get word offset and length from message buffer (avoid string allocation)
	wordOffset, wordLen := pbDecodeWordAckBytes(msgInBuffer[:msgInSize])
	if wordLen == 0 || wordLen > 8 {
		sendFailure(FailureType_DataError, "Invalid word length")
		recoveryState = RECOVERY_IDLE
		return
	}

	// Validate word using byte-based lookup
	wordIdx := findWordIndexInMnemonicBytes(msgInBuffer[:], wordOffset, wordLen)
	if wordIdx < 0 {
		sendFailure(FailureType_DataError, "Invalid word")
		recoveryState = RECOVERY_IDLE
		return
	}

	// Copy word to fixed buffer
	for j := 0; j < wordLen; j++ {
		recoveryWordBufs[recoveryWordIndex][j] = msgInBuffer[wordOffset+j]
	}
	recoveryWordLens[recoveryWordIndex] = wordLen
	recoveryWordIndex++

	// Display progress
	layoutRecoveryProgress(recoveryWordIndex, recoveryWordCount)

	// Check if we have all words
	if recoveryWordIndex >= recoveryWordCount {
		// Build mnemonic string
		mnemonic := buildMnemonicString()

		// Validate mnemonic
		if !validateMnemonic(mnemonic) {
			sendFailure(FailureType_DataError, "Invalid mnemonic checksum")
			recoveryState = RECOVERY_IDLE
			return
		}

		if recoveryDryRun {
			// Dry run - just validate, don't store
			recoveryState = RECOVERY_IDLE
			sendSuccess("Mnemonic is valid")
			return
		}

		// Store mnemonic
		storageSetMnemonic(mnemonic)
		storageSetNeedsBackup(false) // Recovered = already backed up

		recoveryState = RECOVERY_IDLE

		// Display success
		layoutRecoveryComplete()

		sendSuccess("Device recovered")
		return
	}

	// Request next word
	sendWordRequest(WordRequestType_Plain)
}

// isValidWord checks if word is in BIP39 wordlist
// Uses byte comparison to avoid TinyGo string issues
func isValidWord(word string) bool {
	// Use findWordIndex which has proper byte comparison
	return findWordIndex(word) >= 0
}

// recoveryMnemonicBuf is a fixed buffer for building recovery mnemonic
var recoveryMnemonicBuf [256]byte

// buildMnemonicString builds mnemonic from collected words
// Uses fixed byte buffers to avoid TinyGo string allocation issues
func buildMnemonicString() string {
	pos := 0
	for i := 0; i < recoveryWordCount; i++ {
		if i > 0 && pos < 255 {
			recoveryMnemonicBuf[pos] = ' '
			pos++
		}
		// Copy from byte buffer
		wordLen := recoveryWordLens[i]
		for j := 0; j < wordLen && pos < 255; j++ {
			recoveryMnemonicBuf[pos] = recoveryWordBufs[i][j]
			pos++
		}
	}
	return string(recoveryMnemonicBuf[:pos])
}

// sendWordRequest sends a WordRequest message
func sendWordRequest(reqType uint32) {
	var buf [8]byte
	n := pbEncodeWordRequest(buf[:], reqType)
	msgWrite(MessageType_WordRequest, buf[:n])
}

// layoutRecoveryStart shows recovery start screen
func layoutRecoveryStart() {
	oledClear()
	oledDrawString(4, 0, "Recovery Mode")
	oledDrawString(4, 16, "Enter word 1 of")
	oledDrawInt(100, 16, recoveryWordCount)
	oledDrawString(4, 32, "on computer")
	oledRefresh()
}

// layoutRecoveryProgress shows recovery progress
func layoutRecoveryProgress(current, total int) {
	oledClear()
	oledDrawString(4, 0, "Recovery Mode")
	oledDrawString(4, 16, "Enter word")
	oledDrawInt(76, 16, current+1)
	oledDrawString(92, 16, "of")
	oledDrawInt(108, 16, total)
	oledRefresh()
}

// layoutRecoveryComplete shows recovery complete, then returns to home
func layoutRecoveryComplete() {
	oledClear()
	oledDrawString(4, 0, "Recovery Complete")
	oledDrawString(4, 24, "Device is ready!")
	oledRefresh()
	usbDelay(2000000) // Show for 2 seconds
	layoutHome()      // Return to home screen
}
