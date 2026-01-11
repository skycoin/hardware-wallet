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
func pbEncodeString(buf []byte, fieldNum int, val string) int {
	n := 0
	n += pbEncodeTag(buf[n:], fieldNum, PB_BYTES)
	n += pbEncodeVarint(buf[n:], uint64(len(val)))
	copy(buf[n:], val)
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
	Features_vendor              = 1
	Features_major_version       = 2
	Features_minor_version       = 3
	Features_patch_version       = 4
	Features_bootloader_mode     = 5
	Features_device_id           = 6
	Features_pin_protection      = 7
	Features_passphrase_protection = 8
	Features_language            = 9
	Features_label               = 10
	Features_initialized         = 12
	Features_bootloader_hash     = 14
	Features_pin_cached          = 16
	Features_passphrase_cached   = 17
	Features_firmware_present    = 18
	Features_needs_backup        = 19
	Features_model               = 21
	Features_fw_major            = 22  // Fixed: was 24
	Features_fw_minor            = 23  // Fixed: was 25
	Features_fw_patch            = 24  // Fixed: was 26
	Features_fw_vendor           = 26  // Fixed: was 27
	Features_fw_vendor_keys      = 27  // Fixed: was 28
	Features_firmware_features   = 29
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

	// language (field 9)
	n += pbEncodeString(buf[n:], Features_language, string(storage.Language[:]))

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

// Success message field numbers
const (
	Success_message = 1
)

// pbEncodeSuccess encodes a Success message
func pbEncodeSuccess(buf []byte, message string) int {
	if message == "" {
		return 0
	}
	return pbEncodeString(buf, Success_message, message)
}

// Failure message field numbers
const (
	Failure_code    = 1
	Failure_message = 2
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
	Ping_message           = 1
	Ping_button_protection = 2
	Ping_pin_protection    = 3
	Ping_passphrase_protection = 4
)

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
			// Return the message string
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
	ButtonRequestType_Other            = 1
	ButtonRequestType_ConfirmWord      = 8
	ButtonRequestType_WipeDevice       = 9
	ButtonRequestType_ProtectCall      = 10
	ButtonRequestType_SignTx           = 11
	ButtonRequestType_Address          = 13
	ButtonRequestType_PublicKey        = 14
	ButtonRequestType_MnemonicWordCount = 15
	ButtonRequestType_MnemonicInput    = 16
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
// Returns the address index (default 0)
func pbDecodeSkycoinAddress(data []byte) int {
	startIndex := 0
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
			// start_index field
			if i >= len(data) {
				break
			}
			val := int(data[i])
			i++
			startIndex = val
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
	return startIndex
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
