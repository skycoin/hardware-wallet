package main

// Minimal protobuf encoding for Skycoin wallet messages
// Field numbers and types based on messages.proto

// Protobuf wire types
const (
	PB_VARINT  = 0
	PB_FIXED64 = 1
	PB_BYTES   = 2
	PB_FIXED32 = 5
)

// pbEncodeVarint encodes a varint and returns bytes written
func pbEncodeVarint(buf []byte, val uint64) int {
	i := 0
	for val >= 0x80 {
		buf[i] = byte(val) | 0x80
		val >>= 7
		i++
	}
	buf[i] = byte(val)
	return i + 1
}

// pbEncodeTag encodes a field tag
func pbEncodeTag(buf []byte, fieldNum int, wireType int) int {
	return pbEncodeVarint(buf, uint64(fieldNum<<3|wireType))
}

// pbEncodeString encodes a string field
// Note: Manual copy is used instead of copy(buf, str) due to TinyGo bare-metal limitations
func pbEncodeString(buf []byte, fieldNum int, val string) int {
	n := 0
	n += pbEncodeTag(buf[n:], fieldNum, PB_BYTES)
	n += pbEncodeVarint(buf[n:], uint64(len(val)))
	// Manual copy - TinyGo bare-metal doesn't handle copy from string correctly
	for i := 0; i < len(val); i++ {
		buf[n+i] = val[i]
	}
	n += len(val)
	return n
}

// pbEncodeBytes encodes a bytes field
func pbEncodeBytes(buf []byte, fieldNum int, val []byte) int {
	n := 0
	n += pbEncodeTag(buf[n:], fieldNum, PB_BYTES)
	n += pbEncodeVarint(buf[n:], uint64(len(val)))
	copy(buf[n:], val)
	n += len(val)
	return n
}

// pbEncodeUint32 encodes a uint32 field
func pbEncodeUint32(buf []byte, fieldNum int, val uint32) int {
	n := 0
	n += pbEncodeTag(buf[n:], fieldNum, PB_VARINT)
	n += pbEncodeVarint(buf[n:], uint64(val))
	return n
}

// pbEncodeBool encodes a bool field
func pbEncodeBool(buf []byte, fieldNum int, val bool) int {
	v := uint32(0)
	if val {
		v = 1
	}
	return pbEncodeUint32(buf, fieldNum, v)
}

// Features message field numbers (from messages.proto)
const (
	Features_vendor                = 1
	Features_major_version         = 2
	Features_minor_version         = 3
	Features_patch_version         = 4
	Features_bootloader_mode       = 5
	Features_device_id             = 6
	Features_pin_protection        = 7
	Features_passphrase_protection = 8
	Features_language              = 9
	Features_label                 = 10
	Features_initialized           = 12
	Features_bootloader_hash       = 14
	Features_pin_cached            = 16
	Features_passphrase_cached     = 17
	Features_firmware_present      = 18
	Features_needs_backup          = 19
	Features_model                 = 21
	Features_fw_major              = 22 // Fixed: was 24
	Features_fw_minor              = 23 // Fixed: was 25
	Features_fw_patch              = 24 // Fixed: was 26
	Features_fw_vendor             = 26 // Fixed: was 27
	Features_fw_vendor_keys        = 27 // Fixed: was 28
	Features_firmware_features     = 29
)

// pbEncodeFeatures encodes a Features message
func pbEncodeFeatures(buf []byte) int {
	n := 0

	// Initialize storage to get current state
	storageInit()

	// vendor (field 1)
	n += pbEncodeString(buf[n:], Features_vendor, "SkycoinFoundation")

	// major_version (field 2)
	n += pbEncodeUint32(buf[n:], Features_major_version, 1)

	// minor_version (field 3)
	n += pbEncodeUint32(buf[n:], Features_minor_version, 0)

	// patch_version (field 4)
	n += pbEncodeUint32(buf[n:], Features_patch_version, 0)

	// bootloader_mode (field 5)
	n += pbEncodeBool(buf[n:], Features_bootloader_mode, false)

	// device_id (field 6)
	n += pbEncodeString(buf[n:], Features_device_id, storageGetDeviceID())

	// pin_protection (field 7)
	n += pbEncodeBool(buf[n:], Features_pin_protection, storageHasPIN())

	// passphrase_protection (field 8)
	n += pbEncodeBool(buf[n:], Features_passphrase_protection, storage.PassphraseProtection)

	// language (field 9) - use "en-US" as default
	n += pbEncodeString(buf[n:], Features_language, "en-US")

	// label (field 10)
	if storage.HasLabel {
		n += pbEncodeString(buf[n:], Features_label, storageGetLabel())
	}

	// initialized (field 12)
	n += pbEncodeBool(buf[n:], Features_initialized, storageIsInitialized())

	// pin_cached (field 16)
	n += pbEncodeBool(buf[n:], Features_pin_cached, sessionIsPINcached())

	// firmware_present (field 18)
	n += pbEncodeBool(buf[n:], Features_firmware_present, true)

	// needs_backup (field 19)
	n += pbEncodeBool(buf[n:], Features_needs_backup, storageNeedsBackup())

	// model (field 21)
	n += pbEncodeString(buf[n:], Features_model, "1")

	// fw_major (field 22)
	n += pbEncodeUint32(buf[n:], Features_fw_major, 1)

	// fw_minor (field 23)
	n += pbEncodeUint32(buf[n:], Features_fw_minor, 0)

	// fw_patch (field 24)
	n += pbEncodeUint32(buf[n:], Features_fw_patch, 0)

	// firmware_features (field 29) - required by CLI
	n += pbEncodeUint32(buf[n:], Features_firmware_features, 0)

	return n
}

// Success message field numbers (from messages.proto)
// msg_type = 1, message = 2
const (
	Success_msg_type = 1
	Success_message  = 2
)

// pbEncodeSuccess encodes a Success message
func pbEncodeSuccess(buf []byte, message string) int {
	if message == "" {
		return 0
	}
	return pbEncodeString(buf, Success_message, message)
}

// Failure message field numbers (from messages.proto)
// msg_type = 1, code = 2, message = 3
const (
	Failure_msg_type = 1
	Failure_code     = 2
	Failure_message  = 3
)

// FailureType codes
const (
	FailureType_UnexpectedMessage = 1
	FailureType_DataError         = 3
	FailureType_ActionCancelled   = 4
	FailureType_PinExpected       = 5
	FailureType_PinCancelled      = 6
	FailureType_PinInvalid        = 7
	FailureType_InvalidSignature  = 8
	FailureType_ProcessError      = 9
	FailureType_NotEnoughFunds    = 10
	FailureType_NotInitialized    = 11
	FailureType_PinMismatch       = 12
)

// pbEncodeFailure encodes a Failure message
func pbEncodeFailure(buf []byte, code uint32, message string) int {
	n := 0
	n += pbEncodeUint32(buf[n:], Failure_code, code)
	if message != "" {
		n += pbEncodeString(buf[n:], Failure_message, message)
	}
	return n
}

// Ping message field numbers
const (
	Ping_message               = 1
	Ping_button_protection     = 2
	Ping_pin_protection        = 3
	Ping_passphrase_protection = 4
)

// pingMsgBuf is a fixed buffer for decoded ping messages
var pingMsgBuf [256]byte

// pbDecodePing decodes a Ping message, returns the message string
func pbDecodePing(data []byte) string {
	// Simple protobuf decoding for Ping message
	// We only care about field 1 (message)
	i := 0
	for i < len(data) {
		if i >= len(data) {
			break
		}

		// Read tag
		tag := uint32(data[i])
		i++
		if tag&0x80 != 0 {
			// Multi-byte varint tag (unlikely for small field numbers)
			continue
		}

		fieldNum := tag >> 3
		wireType := tag & 0x7

		if fieldNum == 1 && wireType == PB_BYTES {
			// String field - read length
			if i >= len(data) {
				break
			}
			length := int(data[i])
			i++
			if length&0x80 != 0 {
				// Multi-byte length (unlikely for short strings)
				continue
			}
			if i+length > len(data) {
				break
			}
			// Copy to buffer and return string
			// Manual copy due to TinyGo bare-metal limitations
			if length > len(pingMsgBuf) {
				length = len(pingMsgBuf)
			}
			for j := 0; j < length; j++ {
				pingMsgBuf[j] = data[i+j]
			}
			return string(pingMsgBuf[:length])
		}

		// Skip other fields
		switch wireType {
		case PB_VARINT:
			for i < len(data) && data[i]&0x80 != 0 {
				i++
			}
			i++
		case PB_BYTES:
			if i < len(data) {
				length := int(data[i])
				i++
				i += length
			}
		case PB_FIXED32:
			i += 4
		case PB_FIXED64:
			i += 8
		}
	}
	return ""
}

// PinMatrixRequest field numbers
const (
	PinMatrixRequest_type = 1
)

// PinMatrixRequestType enum
const (
	PinMatrixRequestType_Current   = 1
	PinMatrixRequestType_NewFirst  = 2
	PinMatrixRequestType_NewSecond = 3
)

// pbEncodePinMatrixRequest encodes a PinMatrixRequest message
func pbEncodePinMatrixRequest(buf []byte, pinType uint32) int {
	return pbEncodeUint32(buf, PinMatrixRequest_type, pinType)
}

// PinMatrixAck field numbers
const (
	PinMatrixAck_pin = 1
)

// pbDecodePinMatrixAck decodes a PinMatrixAck message, returns the PIN string
func pbDecodePinMatrixAck(data []byte) string {
	// Same structure as Ping - field 1 is a string
	i := 0
	for i < len(data) {
		if i >= len(data) {
			break
		}

		tag := uint32(data[i])
		i++
		if tag&0x80 != 0 {
			continue
		}

		fieldNum := tag >> 3
		wireType := tag & 0x7

		if fieldNum == 1 && wireType == PB_BYTES {
			if i >= len(data) {
				break
			}
			length := int(data[i])
			i++
			if length&0x80 != 0 {
				continue
			}
			if i+length > len(data) {
				break
			}
			return string(data[i : i+length])
		}

		// Skip other fields
		switch wireType {
		case PB_VARINT:
			for i < len(data) && data[i]&0x80 != 0 {
				i++
			}
			i++
		case PB_BYTES:
			if i < len(data) {
				length := int(data[i])
				i++
				i += length
			}
		case PB_FIXED32:
			i += 4
		case PB_FIXED64:
			i += 8
		}
	}
	return ""
}

// ButtonRequest field numbers
const (
	ButtonRequest_code = 1
	ButtonRequest_data = 2
)

// ButtonRequestType enum
const (
	ButtonRequestType_Other             = 1
	ButtonRequestType_ConfirmWord       = 8
	ButtonRequestType_WipeDevice        = 9
	ButtonRequestType_ProtectCall       = 10
	ButtonRequestType_SignTx            = 11
	ButtonRequestType_Address           = 13
	ButtonRequestType_PublicKey         = 14
	ButtonRequestType_MnemonicWordCount = 15
	ButtonRequestType_MnemonicInput     = 16
)

// pbEncodeButtonRequest encodes a ButtonRequest message
func pbEncodeButtonRequest(buf []byte, code uint32) int {
	return pbEncodeUint32(buf, ButtonRequest_code, code)
}

// GenerateMnemonic field numbers
const (
	GenerateMnemonic_passphrase_protection = 1
	GenerateMnemonic_word_count            = 2
	GenerateMnemonic_skip_backup           = 3
)

// pbDecodeGenerateMnemonic decodes a GenerateMnemonic message
// Returns word count (12 or 24, default 12)
func pbDecodeGenerateMnemonic(data []byte) int {
	wordCount := 12 // default
	i := 0
	for i < len(data) {
		if i >= len(data) {
			break
		}

		tag := uint32(data[i])
		i++
		if tag&0x80 != 0 {
			continue
		}

		fieldNum := tag >> 3
		wireType := tag & 0x7

		if fieldNum == 2 && wireType == PB_VARINT {
			// Word count field
			if i >= len(data) {
				break
			}
			val := int(data[i])
			i++
			if val == 24 {
				wordCount = 24
			}
			continue
		}

		// Skip other fields
		switch wireType {
		case PB_VARINT:
			for i < len(data) && data[i]&0x80 != 0 {
				i++
			}
			i++
		case PB_BYTES:
			if i < len(data) {
				length := int(data[i])
				i++
				i += length
			}
		case PB_FIXED32:
			i += 4
		case PB_FIXED64:
			i += 8
		}
	}
	return wordCount
}

// SetMnemonic field numbers
const (
	SetMnemonic_mnemonic = 1
)

// pbDecodeSetMnemonic decodes a SetMnemonic message
// Returns the mnemonic string
func pbDecodeSetMnemonic(data []byte) string {
	i := 0
	for i < len(data) {
		if i >= len(data) {
			break
		}

		tag := uint32(data[i])
		i++
		if tag&0x80 != 0 {
			continue
		}

		fieldNum := tag >> 3
		wireType := tag & 0x7

		if fieldNum == 1 && wireType == PB_BYTES {
			if i >= len(data) {
				break
			}
			length := int(data[i])
			i++
			if length&0x80 != 0 {
				continue
			}
			if i+length > len(data) {
				break
			}
			return string(data[i : i+length])
		}

		// Skip other fields
		switch wireType {
		case PB_VARINT:
			for i < len(data) && data[i]&0x80 != 0 {
				i++
			}
			i++
		case PB_BYTES:
			if i < len(data) {
				length := int(data[i])
				i++
				i += length
			}
		case PB_FIXED32:
			i += 4
		case PB_FIXED64:
			i += 8
		}
	}
	return ""
}

// EntropyRequest field numbers
const (
	EntropyRequest_size = 1
)

// pbEncodeEntropyRequest encodes an EntropyRequest message
func pbEncodeEntropyRequest(buf []byte, size uint32) int {
	return pbEncodeUint32(buf, EntropyRequest_size, size)
}

// EntropyAck field numbers
const (
	EntropyAck_entropy = 1
)

// pbDecodeEntropyAck decodes an EntropyAck message
// Returns the entropy bytes
func pbDecodeEntropyAck(data []byte) []byte {
	i := 0
	for i < len(data) {
		if i >= len(data) {
			break
		}

		tag := uint32(data[i])
		i++
		if tag&0x80 != 0 {
			continue
		}

		fieldNum := tag >> 3
		wireType := tag & 0x7

		if fieldNum == 1 && wireType == PB_BYTES {
			if i >= len(data) {
				break
			}
			length := int(data[i])
			i++
			if length&0x80 != 0 {
				continue
			}
			if i+length > len(data) {
				break
			}
			return data[i : i+length]
		}

		// Skip other fields
		switch wireType {
		case PB_VARINT:
			for i < len(data) && data[i]&0x80 != 0 {
				i++
			}
			i++
		case PB_BYTES:
			if i < len(data) {
				length := int(data[i])
				i++
				i += length
			}
		case PB_FIXED32:
			i += 4
		case PB_FIXED64:
			i += 8
		}
	}
	return nil
}

// Entropy field numbers (response to GetEntropy)
const (
	Entropy_entropy = 1
)

// pbEncodeEntropy encodes an Entropy message
func pbEncodeEntropy(buf []byte, entropy []byte) int {
	return pbEncodeBytes(buf, Entropy_entropy, entropy)
}

// WordRequest field numbers
const (
	WordRequest_type = 1
)

// WordRequestType enum
const (
	WordRequestType_Plain   = 0
	WordRequestType_Matrix9 = 1
	WordRequestType_Matrix6 = 2
)

// pbEncodeWordRequest encodes a WordRequest message
func pbEncodeWordRequest(buf []byte, wordType uint32) int {
	return pbEncodeUint32(buf, WordRequest_type, wordType)
}

// WordAck field numbers
const (
	WordAck_word = 1
)

// pbDecodeWordAck decodes a WordAck message
func pbDecodeWordAck(data []byte) string {
	i := 0
	for i < len(data) {
		if i >= len(data) {
			break
		}

		tag := uint32(data[i])
		i++
		if tag&0x80 != 0 {
			continue
		}

		fieldNum := tag >> 3
		wireType := tag & 0x7

		if fieldNum == 1 && wireType == PB_BYTES {
			if i >= len(data) {
				break
			}
			length := int(data[i])
			i++
			if length&0x80 != 0 {
				continue
			}
			if i+length > len(data) {
				break
			}
			return string(data[i : i+length])
		}

		// Skip other fields
		switch wireType {
		case PB_VARINT:
			for i < len(data) && data[i]&0x80 != 0 {
				i++
			}
			i++
		case PB_BYTES:
			if i < len(data) {
				length := int(data[i])
				i++
				i += length
			}
		case PB_FIXED32:
			i += 4
		case PB_FIXED64:
			i += 8
		}
	}
	return ""
}

// SkycoinAddress field numbers
const (
	SkycoinAddress_address_n    = 1
	SkycoinAddress_start_index  = 2
	SkycoinAddress_confirm_addr = 3
)

// pbDecodeSkycoinAddress decodes a SkycoinAddress message
// Returns addressN (count), startIndex, confirmAddress
func pbDecodeSkycoinAddress(data []byte) (int, int, bool) {
	addressN := 1   // default 1
	startIndex := 0 // default 0
	confirmAddress := false
	i := 0
	for i < len(data) {
		if i >= len(data) {
			break
		}

		tag := uint32(data[i])
		i++
		if tag&0x80 != 0 {
			continue
		}

		fieldNum := tag >> 3
		wireType := tag & 0x7

		if fieldNum == 1 && wireType == PB_VARINT {
			// address_n field (count)
			if i >= len(data) {
				break
			}
			val := int(data[i])
			i++
			addressN = val
			continue
		}

		if fieldNum == 2 && wireType == PB_VARINT {
			// start_index field
			if i >= len(data) {
				break
			}
			val := int(data[i])
			i++
			startIndex = val
			continue
		}

		if fieldNum == 3 && wireType == PB_VARINT {
			// confirm_address field
			if i >= len(data) {
				break
			}
			val := data[i]
			i++
			confirmAddress = val != 0
			continue
		}

		// Skip other fields
		switch wireType {
		case PB_VARINT:
			for i < len(data) && data[i]&0x80 != 0 {
				i++
			}
			i++
		case PB_BYTES:
			if i < len(data) {
				length := int(data[i])
				i++
				i += length
			}
		case PB_FIXED32:
			i += 4
		case PB_FIXED64:
			i += 8
		}
	}
	return addressN, startIndex, confirmAddress
}

// ResponseSkycoinAddress field numbers
const (
	ResponseSkycoinAddress_addresses = 1
)

// pbEncodeSkycoinAddressResponse encodes a ResponseSkycoinAddress message
func pbEncodeSkycoinAddressResponse(buf []byte, address string) int {
	// addresses is a repeated string field, but we only send one
	return pbEncodeString(buf, ResponseSkycoinAddress_addresses, address)
}

// SkycoinSignMessage field numbers
const (
	SkycoinSignMessage_address_n = 1
	SkycoinSignMessage_message   = 2
)

// pbDecodeSkycoinSignMessage decodes a SkycoinSignMessage
// Returns address_n (index) and message string
func pbDecodeSkycoinSignMessage(data []byte) (int, string) {
	i := 0
	addressN := 0
	message := ""

	for i < len(data) {
		if i >= len(data) {
			break
		}

		tag := uint32(data[i])
		i++
		if tag&0x80 != 0 {
			continue
		}

		fieldNum := tag >> 3
		wireType := tag & 0x7

		if fieldNum == 1 && wireType == PB_VARINT {
			// address_n field
			if i >= len(data) {
				break
			}
			val := int(data[i])
			i++
			addressN = val
			continue
		}

		if fieldNum == 2 && wireType == PB_BYTES {
			// message field
			if i >= len(data) {
				break
			}
			length := int(data[i])
			i++
			if length&0x80 != 0 {
				continue
			}
			if i+length > len(data) {
				break
			}
			message = string(data[i : i+length])
			i += length
			continue
		}

		// Skip other fields
		switch wireType {
		case PB_VARINT:
			for i < len(data) && data[i]&0x80 != 0 {
				i++
			}
			i++
		case PB_BYTES:
			if i < len(data) {
				length := int(data[i])
				i++
				i += length
			}
		case PB_FIXED32:
			i += 4
		case PB_FIXED64:
			i += 8
		}
	}
	return addressN, message
}

// ResponseSkycoinSignMessage field numbers
const (
	ResponseSkycoinSignMessage_signed_message = 1
)

// pbEncodeSkycoinSignMessageResponse encodes a ResponseSkycoinSignMessage
func pbEncodeSkycoinSignMessageResponse(buf []byte, signedMessage string) int {
	return pbEncodeString(buf, ResponseSkycoinSignMessage_signed_message, signedMessage)
}

// TransactionSign field numbers
const (
	TransactionSign_nbIn           = 1
	TransactionSign_transactionIn  = 2
	TransactionSign_nbOut          = 3
	TransactionSign_transactionOut = 4
)

// SkycoinTransactionInput field numbers
const (
	SkycoinTransactionInput_hashIn = 1
	SkycoinTransactionInput_index  = 2
)

// SkycoinTransactionOutput field numbers
const (
	SkycoinTransactionOutput_address       = 1
	SkycoinTransactionOutput_coin          = 2
	SkycoinTransactionOutput_hour          = 3
	SkycoinTransactionOutput_address_index = 4
)

// pbDecodeTransactionSign decodes a TransactionSign message
// Returns nbIn, inputs, nbOut, outputs
func pbDecodeTransactionSign(data []byte) (int, []TransactionInput, int, []TransactionOutput) {
	var nbIn, nbOut int
	inputs := make([]TransactionInput, 0, MAX_TX_INPUTS)
	outputs := make([]TransactionOutput, 0, MAX_TX_OUTPUTS)

	i := 0
	for i < len(data) {
		if i >= len(data) {
			break
		}

		// Read tag
		tag := uint32(data[i])
		i++
		if tag&0x80 != 0 {
			// Multi-byte tag - read rest
			tag &= 0x7F
			for i < len(data) && data[i-1]&0x80 != 0 {
				i++
			}
		}

		fieldNum := tag >> 3
		wireType := tag & 0x7

		switch fieldNum {
		case TransactionSign_nbIn:
			if wireType == PB_VARINT && i < len(data) {
				nbIn = int(data[i])
				i++
			}

		case TransactionSign_nbOut:
			if wireType == PB_VARINT && i < len(data) {
				nbOut = int(data[i])
				i++
			}

		case TransactionSign_transactionIn:
			if wireType == PB_BYTES && i < len(data) {
				length := int(data[i])
				i++
				if i+length <= len(data) {
					input := decodeTransactionInput(data[i : i+length])
					inputs = append(inputs, input)
					i += length
				}
			}

		case TransactionSign_transactionOut:
			if wireType == PB_BYTES && i < len(data) {
				length := int(data[i])
				i++
				if i+length <= len(data) {
					output := decodeTransactionOutput(data[i : i+length])
					outputs = append(outputs, output)
					i += length
				}
			}

		default:
			// Skip unknown field
			switch wireType {
			case PB_VARINT:
				for i < len(data) && data[i]&0x80 != 0 {
					i++
				}
				i++
			case PB_BYTES:
				if i < len(data) {
					length := int(data[i])
					i++
					i += length
				}
			case PB_FIXED32:
				i += 4
			case PB_FIXED64:
				i += 8
			}
		}
	}

	return nbIn, inputs, nbOut, outputs
}

// decodeTransactionInput decodes a SkycoinTransactionInput
func decodeTransactionInput(data []byte) TransactionInput {
	var input TransactionInput
	i := 0

	for i < len(data) {
		tag := uint32(data[i])
		i++
		fieldNum := tag >> 3
		wireType := tag & 0x7

		switch fieldNum {
		case SkycoinTransactionInput_hashIn:
			if wireType == PB_BYTES && i < len(data) {
				length := int(data[i])
				i++
				if i+length <= len(data) {
					input.hashIn = string(data[i : i+length])
					i += length
				}
			}

		case SkycoinTransactionInput_index:
			if wireType == PB_VARINT && i < len(data) {
				input.index = int(data[i])
				i++
			}

		default:
			// Skip
			switch wireType {
			case PB_VARINT:
				for i < len(data) && data[i]&0x80 != 0 {
					i++
				}
				i++
			case PB_BYTES:
				if i < len(data) {
					length := int(data[i])
					i++
					i += length
				}
			}
		}
	}

	return input
}

// decodeTransactionOutput decodes a SkycoinTransactionOutput
func decodeTransactionOutput(data []byte) TransactionOutput {
	var output TransactionOutput
	i := 0

	for i < len(data) {
		tag := uint32(data[i])
		i++
		fieldNum := tag >> 3
		wireType := tag & 0x7

		switch fieldNum {
		case SkycoinTransactionOutput_address:
			if wireType == PB_BYTES && i < len(data) {
				length := int(data[i])
				i++
				if i+length <= len(data) {
					output.address = string(data[i : i+length])
					i += length
				}
			}

		case SkycoinTransactionOutput_coin:
			if wireType == PB_VARINT && i < len(data) {
				output.coin = pbDecodeUint64(data[i:])
				// Skip varint bytes
				for i < len(data) && data[i]&0x80 != 0 {
					i++
				}
				i++
			}

		case SkycoinTransactionOutput_hour:
			if wireType == PB_VARINT && i < len(data) {
				output.hour = pbDecodeUint64(data[i:])
				// Skip varint bytes
				for i < len(data) && data[i]&0x80 != 0 {
					i++
				}
				i++
			}

		case SkycoinTransactionOutput_address_index:
			if wireType == PB_VARINT && i < len(data) {
				output.addressIndex = int(data[i])
				i++
			}

		default:
			// Skip
			switch wireType {
			case PB_VARINT:
				for i < len(data) && data[i]&0x80 != 0 {
					i++
				}
				i++
			case PB_BYTES:
				if i < len(data) {
					length := int(data[i])
					i++
					i += length
				}
			}
		}
	}

	return output
}

// pbDecodeUint64 decodes a varint as uint64
func pbDecodeUint64(data []byte) uint64 {
	var val uint64
	var shift uint
	for i := 0; i < len(data) && i < 10; i++ {
		b := data[i]
		val |= uint64(b&0x7F) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}
	return val
}

// ResponseTransactionSign field numbers
const (
	ResponseTransactionSign_signatures = 1
	ResponseTransactionSign_padding    = 2
)

// pbEncodeTransactionSignResponse encodes a ResponseTransactionSign message
func pbEncodeTransactionSignResponse(buf []byte, signatures []string) int {
	n := 0

	// Encode each signature as repeated string field
	for _, sig := range signatures {
		n += pbEncodeString(buf[n:], ResponseTransactionSign_signatures, sig)
	}

	// Encode padding field (required bool)
	n += pbEncodeBool(buf[n:], ResponseTransactionSign_padding, false)

	return n
}

// RecoveryDevice field numbers
const (
	RecoveryDevice_word_count            = 1
	RecoveryDevice_passphrase_protection = 2
	RecoveryDevice_pin_protection        = 3
	RecoveryDevice_language              = 4
	RecoveryDevice_label                 = 5
	RecoveryDevice_dry_run               = 6
)

// pbDecodeRecoveryDevice decodes a RecoveryDevice message
// Returns word_count, passphrase_protection, pin_protection, dry_run
func pbDecodeRecoveryDevice(data []byte) (int, bool, bool, bool) {
	wordCount := 12 // default
	passphraseProtection := false
	pinProtection := false
	dryRun := false

	i := 0
	for i < len(data) {
		if i >= len(data) {
			break
		}

		tag := uint32(data[i])
		i++
		fieldNum := tag >> 3
		wireType := tag & 0x7

		switch fieldNum {
		case RecoveryDevice_word_count:
			if wireType == PB_VARINT && i < len(data) {
				wordCount = int(data[i])
				i++
			}

		case RecoveryDevice_passphrase_protection:
			if wireType == PB_VARINT && i < len(data) {
				passphraseProtection = data[i] != 0
				i++
			}

		case RecoveryDevice_pin_protection:
			if wireType == PB_VARINT && i < len(data) {
				pinProtection = data[i] != 0
				i++
			}

		case RecoveryDevice_dry_run:
			if wireType == PB_VARINT && i < len(data) {
				dryRun = data[i] != 0
				i++
			}

		default:
			// Skip
			switch wireType {
			case PB_VARINT:
				for i < len(data) && data[i]&0x80 != 0 {
					i++
				}
				i++
			case PB_BYTES:
				if i < len(data) {
					length := int(data[i])
					i++
					i += length
				}
			case PB_FIXED32:
				i += 4
			case PB_FIXED64:
				i += 8
			}
		}
	}

	return wordCount, passphraseProtection, pinProtection, dryRun
}
