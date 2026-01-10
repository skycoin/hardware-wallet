package main

// MessageHandler is a function that handles a specific message type
type MessageHandler func(data []byte)

// MessageEntry maps a message ID to its handler
type MessageEntry struct {
	MsgID   uint16
	Handler MessageHandler
}

// Message dispatch table
// Only include handlers for messages we support
var messagesMap = []MessageEntry{
	{MessageType_Initialize, handleInitialize},
	{MessageType_GetFeatures, handleGetFeatures},
	{MessageType_Ping, handlePing},
	// Add more handlers as implemented:
	// {MessageType_ChangePin, handleChangePin},
	// {MessageType_WipeDevice, handleWipeDevice},
	// etc.
}

// dispatchMessage routes a message to its handler
func dispatchMessage(msgID uint16, data []byte) {
	// Look up handler in dispatch table
	for _, entry := range messagesMap {
		if entry.MsgID == msgID {
			println("Dispatching message:", msgID)
			entry.Handler(data)
			return
		}
	}

	// Unknown message
	println("Unknown message type:", msgID)
	sendFailure(Failure_UnexpectedMessage, "Unknown message")
}

// sendSuccess sends a Success response
func sendSuccess(message string) {
	success := &Success{
		Message: message,
	}
	payload := encodeSuccess(success)
	msgWrite(MessageType_Success, payload)
	println("Sent Success:", message)
}

// sendFailure sends a Failure response
func sendFailure(code FailureType, message string) {
	failure := &Failure{
		Code:    code,
		Message: message,
	}
	payload := encodeFailure(failure)
	msgWrite(MessageType_Failure, payload)
	println("Sent Failure:", message)
}

// sendFeatures sends a Features response
func sendFeatures() {
	features := &Features{
		Vendor:          VENDOR_NAME,
		MajorVersion:    FW_VERSION_MAJOR,
		MinorVersion:    FW_VERSION_MINOR,
		PatchVersion:    FW_VERSION_PATCH,
		BootloaderMode:  false,
		DeviceID:        DEVICE_ID,
		PinProtection:   false, // TODO: Check storage
		Initialized:     false, // TODO: Check storage for mnemonic
		FirmwarePresent: true,
		NeedsBackup:     false,
		Model:           MODEL_NAME,
		FwMajor:         FW_VERSION_MAJOR,
		FwMinor:         FW_VERSION_MINOR,
		FwPatch:         FW_VERSION_PATCH,
		FwVendor:        "TinyGo",
	}

	payload := encodeFeatures(features)
	msgWrite(MessageType_Features, payload)
	println("Sent Features")
}
