package main

// Transaction signing implementation for Skycoin

// Maximum inputs/outputs per transaction
const (
	MAX_TX_INPUTS  = 8
	MAX_TX_OUTPUTS = 8
)

// Transaction represents a Skycoin transaction for signing
type Transaction struct {
	nbIn       uint8
	nbOut      uint8
	inAddress  [MAX_TX_INPUTS][32]byte  // Input hashes (SHA256)
	outAddress [MAX_TX_OUTPUTS]TxOutput // Output details
	innerHash  [32]byte                 // Computed inner hash
	hasInner   bool
}

// TxOutput represents a transaction output
type TxOutput struct {
	address [20]byte // RIPEMD160(SHA256(pubkey))
	coin    uint32   // Amount in droplets (1 SKY = 1000000)
	hour    uint32   // Coin hours
}

// TransactionInput from protobuf message
type TransactionInput struct {
	hashIn string // 64 hex chars = 32 bytes
	index  int    // Address index for signing
}

// TransactionOutput from protobuf message
type TransactionOutput struct {
	address      string // Base58 Skycoin address
	coin         uint64 // Amount in droplets
	hour         uint64 // Coin hours
	addressIndex int    // Optional address index
}

// txInit initializes a transaction
func txInit(tx *Transaction) {
	tx.nbIn = 0
	tx.nbOut = 0
	tx.hasInner = false
}

// txAddInput adds an input to the transaction
// hashIn is a 32-byte hash
func txAddInput(tx *Transaction, hashIn []byte) bool {
	if tx.nbIn >= MAX_TX_INPUTS {
		return false
	}
	if len(hashIn) != 32 {
		return false
	}
	copy(tx.inAddress[tx.nbIn][:], hashIn)
	tx.nbIn++
	tx.hasInner = false
	return true
}

// txAddOutput adds an output to the transaction
// address is 20-byte RIPEMD160 hash
func txAddOutput(tx *Transaction, address []byte, coin, hour uint32) bool {
	if tx.nbOut >= MAX_TX_OUTPUTS {
		return false
	}
	if len(address) != 20 {
		return false
	}
	copy(tx.outAddress[tx.nbOut].address[:], address)
	tx.outAddress[tx.nbOut].coin = coin
	tx.outAddress[tx.nbOut].hour = hour
	tx.nbOut++
	tx.hasInner = false
	return true
}

// txComputeInnerHash computes the transaction inner hash
func txComputeInnerHash(tx *Transaction) {
	// Serialize transaction data
	// Format:
	// - nbIn (4 bytes, little-endian)
	// - input hashes (32 bytes each)
	// - nbOut (4 bytes, little-endian)
	// - outputs (29 bytes each: 1 pad + 20 addr + 4 coin + 4 pad + 4 hour)

	// Calculate total size
	size := 4 + (int(tx.nbIn) * 32) + 4 + (int(tx.nbOut) * 33)
	data := make([]byte, size)

	pos := 0

	// nbIn as 4-byte little-endian
	data[pos] = tx.nbIn
	data[pos+1] = 0
	data[pos+2] = 0
	data[pos+3] = 0
	pos += 4

	// Input hashes
	for i := 0; i < int(tx.nbIn); i++ {
		copy(data[pos:], tx.inAddress[i][:])
		pos += 32
	}

	// nbOut as 4-byte little-endian
	data[pos] = tx.nbOut
	data[pos+1] = 0
	data[pos+2] = 0
	data[pos+3] = 0
	pos += 4

	// Outputs
	for i := 0; i < int(tx.nbOut); i++ {
		// 1 byte padding
		data[pos] = 0
		pos++
		// 20 byte address
		copy(data[pos:], tx.outAddress[i].address[:])
		pos += 20
		// 4 byte coin (little-endian)
		data[pos] = byte(tx.outAddress[i].coin)
		data[pos+1] = byte(tx.outAddress[i].coin >> 8)
		data[pos+2] = byte(tx.outAddress[i].coin >> 16)
		data[pos+3] = byte(tx.outAddress[i].coin >> 24)
		pos += 4
		// 4 byte padding
		data[pos] = 0
		data[pos+1] = 0
		data[pos+2] = 0
		data[pos+3] = 0
		pos += 4
		// 4 byte hour (little-endian)
		data[pos] = byte(tx.outAddress[i].hour)
		data[pos+1] = byte(tx.outAddress[i].hour >> 8)
		data[pos+2] = byte(tx.outAddress[i].hour >> 16)
		data[pos+3] = byte(tx.outAddress[i].hour >> 24)
		pos += 4
	}

	// SHA256 hash
	tx.innerHash = sha256Sum(data[:pos])
	tx.hasInner = true
}

// txMsgToSign computes the message to sign for a specific input
// Returns 32-byte digest
func txMsgToSign(tx *Transaction, inputIndex int) [32]byte {
	if !tx.hasInner {
		txComputeInnerHash(tx)
	}

	// Concatenate innerHash + inputHash[index]
	var toHash [64]byte
	copy(toHash[0:32], tx.innerHash[:])
	copy(toHash[32:64], tx.inAddress[inputIndex][:])

	// SHA256
	return sha256Sum(toHash[:])
}

// addressToRipemd160 extracts the 20-byte hash from a Skycoin address
func addressToRipemd160(address string) ([]byte, bool) {
	// Decode base58check
	decoded := base58CheckDecode(address)
	if len(decoded) != 21 {
		return nil, false
	}
	// First byte is version (0x00), remaining 20 bytes is the hash
	return decoded[1:21], true
}

// handleTransactionSign handles the TransactionSign message
func handleTransactionSign() {
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
	nbIn, inputs, nbOut, outputs := pbDecodeTransactionSign(msgInBuffer[:msgInSize])

	// Validate counts
	if nbIn > MAX_TX_INPUTS || nbOut > MAX_TX_OUTPUTS {
		sendFailure(FailureType_DataError, "Too many inputs/outputs")
		return
	}
	if nbIn == 0 || nbOut == 0 {
		sendFailure(FailureType_DataError, "Empty transaction")
		return
	}

	// Build transaction
	var tx Transaction
	txInit(&tx)

	// Add inputs
	for i := 0; i < nbIn; i++ {
		hashBytes := hexToBytes(inputs[i].hashIn)
		if len(hashBytes) != 32 {
			sendFailure(FailureType_DataError, "Invalid input hash")
			return
		}
		if !txAddInput(&tx, hashBytes) {
			sendFailure(FailureType_DataError, "Failed to add input")
			return
		}
	}

	// Add outputs
	for i := 0; i < nbOut; i++ {
		addrHash, ok := addressToRipemd160(outputs[i].address)
		if !ok {
			sendFailure(FailureType_DataError, "Invalid output address")
			return
		}
		// Truncate coin/hour to uint32 (Skycoin uses uint64 but inner hash uses uint32)
		coin := uint32(outputs[i].coin)
		hour := uint32(outputs[i].hour)
		if !txAddOutput(&tx, addrHash, coin, hour) {
			sendFailure(FailureType_DataError, "Failed to add output")
			return
		}
	}

	// Get mnemonic
	mnemonic := storageGetMnemonic()
	if mnemonic == "" {
		sendFailure(FailureType_NotInitialized, "No mnemonic")
		return
	}

	// Convert mnemonic to seed
	seed := mnemonicToSeed(mnemonic, "")
	masterKey := deriveKeyFromSeed(seed[:])

	// Sign each input
	var signatures [MAX_TX_INPUTS]string
	for i := 0; i < nbIn; i++ {
		// Get the digest to sign
		digest := txMsgToSign(&tx, i)

		// Derive key for this input's address index
		// TODO: Implement proper BIP32 derivation
		// For now, use same key for all (index 0)
		_ = inputs[i].index
		seckey := masterKey

		// Sign
		sig := ecdsaSignDigest(seckey, digest[:])

		// Check for valid signature
		allZero := true
		for j := 0; j < 65; j++ {
			if sig[j] != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			sendFailure(FailureType_ProcessError, "Signing failed")
			return
		}

		signatures[i] = bytesToHex(sig[:])
	}

	// Display confirmation
	displayTxSigned(nbIn, nbOut)

	// Send response
	sendTransactionSignResponse(signatures[:nbIn])
}

// displayTxSigned shows transaction signed confirmation
func displayTxSigned(nbIn, nbOut int) {
	// Clear display area
	for y := 16; y < 64; y++ {
		for x := 0; x < 128; x++ {
			oledSetPixel(x, y, false)
		}
	}

	oledDrawString(4, 24, "Transaction signed")
	oledDrawString(4, 36, "Inputs:")
	oledDrawInt(52, 36, nbIn)
	oledDrawString(4, 48, "Outputs:")
	oledDrawInt(60, 48, nbOut)

	oledRefresh()
}

// sendTransactionSignResponse sends ResponseTransactionSign message
func sendTransactionSignResponse(signatures []string) {
	// Encode response
	// Buffer needs to hold: repeated string (130 chars each) + overhead
	var buf [1200]byte // 8 * 130 + overhead
	n := pbEncodeTransactionSignResponse(buf[:], signatures)
	msgWrite(MessageType_ResponseTransactionSign, buf[:n])
}
