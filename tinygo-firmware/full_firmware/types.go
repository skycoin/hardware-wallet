package main

// Message Type IDs from messages.proto
const (
	MessageType_Initialize                    = 0
	MessageType_Ping                          = 1
	MessageType_Success                       = 2
	MessageType_Failure                       = 3
	MessageType_ChangePin                     = 4
	MessageType_WipeDevice                    = 5
	MessageType_FirmwareErase                 = 6
	MessageType_FirmwareUpload                = 7
	MessageType_GetRawEntropy                 = 9
	MessageType_Entropy                       = 10
	MessageType_LoadDevice                    = 13
	MessageType_ResetDevice                   = 14
	MessageType_Features                      = 17
	MessageType_PinMatrixRequest              = 18
	MessageType_PinMatrixAck                  = 19
	MessageType_Cancel                        = 20
	MessageType_ApplySettings                 = 25
	MessageType_ButtonRequest                 = 26
	MessageType_ButtonAck                     = 27
	MessageType_BackupDevice                  = 34
	MessageType_EntropyRequest                = 35
	MessageType_EntropyAck                    = 36
	MessageType_PassphraseRequest             = 41
	MessageType_PassphraseAck                 = 42
	MessageType_RecoveryDevice                = 45
	MessageType_WordRequest                   = 46
	MessageType_WordAck                       = 47
	MessageType_GetFeatures                   = 55
	MessageType_PassphraseStateRequest        = 77
	MessageType_PassphraseStateAck            = 78
	MessageType_SetMnemonic                   = 113
	MessageType_SkycoinAddress                = 114
	MessageType_SkycoinCheckMessageSignature  = 115
	MessageType_SkycoinSignMessage            = 116
	MessageType_ResponseSkycoinAddress        = 117
	MessageType_ResponseSkycoinSignMessage    = 118
	MessageType_GenerateMnemonic              = 119
	MessageType_TransactionSign               = 122
	MessageType_ResponseTransactionSign       = 123
	MessageType_GetMixedEntropy               = 124
	MessageType_SignTx                        = 125
	MessageType_TxRequest                     = 126
	MessageType_TxAck                         = 127
	MessageType_BitcoinTxAck                  = 128
	MessageType_BitcoinAddress                = 129
)

// Failure Type codes from types.proto
type FailureType uint32

const (
	Failure_UnexpectedMessage FailureType = 1
	Failure_ButtonExpected    FailureType = 2
	Failure_DataError         FailureType = 3
	Failure_ActionCancelled   FailureType = 4
	Failure_PinExpected       FailureType = 5
	Failure_PinCancelled      FailureType = 6
	Failure_PinInvalid        FailureType = 7
	Failure_InvalidSignature  FailureType = 8
	Failure_ProcessError      FailureType = 9
	Failure_NotEnoughFunds    FailureType = 10
	Failure_NotInitialized    FailureType = 11
	Failure_PinMismatch       FailureType = 12
	Failure_AddressGeneration FailureType = 13
	Failure_FirmwarePanic     FailureType = 14
	Failure_FirmwareError     FailureType = 99
)

// Message structures

// Initialize message (request)
type Initialize struct {
	State []byte // Optional state for session management
}

// GetFeatures message (request)
type GetFeatures struct {
	// Empty message
}

// Ping message (request)
type Ping struct {
	Message              string
	ButtonProtection     bool
	PinProtection        bool
	PassphraseProtection bool
}

// Success message (response)
type Success struct {
	MsgType uint16 // Optional: message type of successful operation
	Message string // Human readable description
}

// Failure message (response)
type Failure struct {
	MsgType uint16      // Optional: message type of failed operation
	Code    FailureType // Error code
	Message string      // Human readable error message
}

// Features message (response)
type Features struct {
	Vendor               string
	MajorVersion         uint32
	MinorVersion         uint32
	PatchVersion         uint32
	BootloaderMode       bool
	DeviceID             string
	PinProtection        bool
	PassphraseProtection bool
	Language             string
	Label                string
	Initialized          bool
	BootloaderHash       []byte
	PinCached            bool
	PassphraseCached     bool
	FirmwarePresent      bool
	NeedsBackup          bool
	Model                string
	FwMajor              uint32
	FwMinor              uint32
	FwPatch              uint32
	FwVersionHead        string
	FwVendor             string
	FwVendorKeys         []byte
	UnfinishedBackup     bool
	FirmwareFeatures     uint32
}

// Firmware version constants
const (
	FW_VERSION_MAJOR = 0
	FW_VERSION_MINOR = 1
	FW_VERSION_PATCH = 0
)

// Device constants
const (
	VENDOR_NAME = "Skycoin Foundation"
	MODEL_NAME  = "1"
	DEVICE_ID   = "TINYGO-00001" // TODO: Generate unique ID
)
