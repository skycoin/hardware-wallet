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
var recoveryWords [24]string
var recoveryDryRun = false

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

	// Get word from message
	word := pbDecodeWordAck(msgInBuffer[:msgInSize])

	// Validate word is in BIP39 wordlist
	if !isValidWord(word) {
		sendFailure(FailureType_DataError, "Invalid word")
		recoveryState = RECOVERY_IDLE
		return
	}

	// Store word
	recoveryWords[recoveryWordIndex] = word
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
func isValidWord(word string) bool {
	for _, w := range bip39Words {
		if w == word {
			return true
		}
	}
	return false
}

// buildMnemonicString builds mnemonic from collected words
func buildMnemonicString() string {
	result := ""
	for i := 0; i < recoveryWordCount; i++ {
		if i > 0 {
			result += " "
		}
		result += recoveryWords[i]
	}
	return result
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

// layoutRecoveryComplete shows recovery complete
func layoutRecoveryComplete() {
	oledClear()
	oledDrawString(4, 0, "Recovery Complete")
	oledDrawString(4, 24, "Device is ready!")
	oledRefresh()
}
