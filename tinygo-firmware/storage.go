package main

import (
	"runtime/volatile"
	"unsafe"
)

// Flash memory layout for STM32F205RG
const (
	FLASH_ORIGIN        = 0x08000000
	FLASH_META_START    = 0x08008000 // Metadata area (sector 2-3)
	FLASH_STORAGE_START = 0x08008100 // Storage starts after 256-byte header
	FLASH_STORAGE_LEN   = 0x7F00     // ~32KB - 256 bytes
	FLASH_APP_START     = 0x08010000 // Application code (sector 4+)

	// Flash control registers
	FLASH_KEYR    = 0x40023C04
	FLASH_SR      = 0x40023C0C
	FLASH_CR      = 0x40023C10
	FLASH_OPTKEYR = 0x40023C08

	// Flash keys for unlocking
	FLASH_KEY1 = 0x45670123
	FLASH_KEY2 = 0xCDEF89AB

	// Flash CR bits
	FLASH_CR_PG     = 1 << 0  // Programming
	FLASH_CR_SER    = 1 << 1  // Sector erase
	FLASH_CR_MER    = 1 << 2  // Mass erase
	FLASH_CR_SNB    = 3       // Sector number shift
	FLASH_CR_PSIZE  = 8       // Program size shift
	FLASH_CR_STRT   = 1 << 16 // Start
	FLASH_CR_LOCK   = 1 << 31 // Lock

	// Flash SR bits
	FLASH_SR_BSY = 1 << 16 // Busy
	FLASH_SR_EOP = 1 << 0  // End of operation
)

// Storage magic value
const STORAGE_MAGIC = 0x726F7473 // "stor" in little-endian

// Storage version
const STORAGE_VERSION = 1

// StorageHDNode holds BIP32 HD node data
type StorageHDNode struct {
	Depth       uint32
	Fingerprint uint32
	ChildNum    uint32
	ChainCode   [32]byte
	PrivateKey  [32]byte
	PublicKey   [33]byte
	HasPrivate  bool
	HasPublic   bool
}

// Storage holds all persistent wallet data
type Storage struct {
	Magic   uint32 // Must be STORAGE_MAGIC
	Version uint32

	// HD Node for BIP32
	Node    StorageHDNode
	HasNode bool

	// Mnemonic seed phrase
	Mnemonic    [241]byte
	MnemonicLen uint8
	HasMnemonic bool

	// Security settings
	PassphraseProtection bool
	PinFailedAttempts    uint32
	PIN                  [10]byte
	PINLen               uint8
	HasPIN               bool

	// Device settings
	Language  [17]byte
	HasLabel  bool
	Label     [33]byte
	LabelLen  uint8

	// Flags
	Imported         bool
	NeedsBackup      bool
	UnfinishedBackup bool
	Initialized      bool

	// U2F (if needed later)
	U2FCounter uint32

	// Auto-lock delay in milliseconds
	AutoLockDelayMs uint32
}

// In-memory storage cache
var storage Storage
var storageLoaded bool

// Session state
var sessionPINcached bool
var sessionPIN [10]byte

// flashReg returns a volatile register at the given address
func flashReg(addr uintptr) *volatile.Register32 {
	return (*volatile.Register32)(unsafe.Pointer(addr))
}

// flashUnlock unlocks flash for writing
func flashUnlock() {
	// Check if already unlocked
	if flashReg(FLASH_CR).Get()&FLASH_CR_LOCK == 0 {
		return
	}
	// Write unlock sequence
	flashReg(FLASH_KEYR).Set(FLASH_KEY1)
	flashReg(FLASH_KEYR).Set(FLASH_KEY2)
}

// flashLock locks flash after writing
func flashLock() {
	flashReg(FLASH_CR).SetBits(FLASH_CR_LOCK)
}

// flashWaitBusy waits for flash operation to complete
func flashWaitBusy() {
	for flashReg(FLASH_SR).Get()&FLASH_SR_BSY != 0 {
	}
}

// flashEraseSector erases a flash sector (2 or 3 for metadata)
func flashEraseSector(sector uint8) {
	flashUnlock()
	flashWaitBusy()

	// Set sector number and erase bit
	cr := flashReg(FLASH_CR).Get()
	cr &^= 0x78       // Clear sector bits
	cr |= FLASH_CR_SER // Sector erase
	cr |= uint32(sector) << FLASH_CR_SNB
	cr |= 2 << FLASH_CR_PSIZE // 32-bit parallelism
	flashReg(FLASH_CR).Set(cr)

	// Start erase
	flashReg(FLASH_CR).SetBits(FLASH_CR_STRT)
	flashWaitBusy()

	// Clear sector erase bit
	flashReg(FLASH_CR).ClearBits(FLASH_CR_SER)
	flashLock()
}

// flashWrite32 writes a 32-bit word to flash
func flashWrite32(addr uintptr, val uint32) {
	flashUnlock()
	flashWaitBusy()

	// Set programming mode
	cr := flashReg(FLASH_CR).Get()
	cr |= FLASH_CR_PG
	cr |= 2 << FLASH_CR_PSIZE // 32-bit
	flashReg(FLASH_CR).Set(cr)

	// Write the data
	*(*uint32)(unsafe.Pointer(addr)) = val
	flashWaitBusy()

	// Clear programming bit
	flashReg(FLASH_CR).ClearBits(FLASH_CR_PG)
	flashLock()
}

// flashRead32 reads a 32-bit word from flash
func flashRead32(addr uintptr) uint32 {
	return *(*uint32)(unsafe.Pointer(addr))
}

// storageInit initializes storage from flash
func storageInit() {
	if storageLoaded {
		return
	}

	// Read magic to check if storage is valid
	magic := flashRead32(FLASH_STORAGE_START)
	if magic != STORAGE_MAGIC {
		// Storage not initialized - use defaults
		storage = Storage{
			Magic:   STORAGE_MAGIC,
			Version: STORAGE_VERSION,
		}
		copy(storage.Language[:], "en")
		storageLoaded = true
		return
	}

	// Read storage from flash
	src := (*[unsafe.Sizeof(Storage{})]byte)(unsafe.Pointer(uintptr(FLASH_STORAGE_START)))
	dst := (*[unsafe.Sizeof(Storage{})]byte)(unsafe.Pointer(&storage))
	*dst = *src
	storageLoaded = true
}

// storageSave saves storage to flash
func storageSave() {
	storage.Magic = STORAGE_MAGIC
	storage.Version = STORAGE_VERSION

	// Erase sector 2 (metadata area where storage lives)
	flashEraseSector(2)

	// Write storage structure to flash
	src := (*[unsafe.Sizeof(Storage{})]byte)(unsafe.Pointer(&storage))
	size := int(unsafe.Sizeof(Storage{}))

	for i := 0; i < size; i += 4 {
		var val uint32
		if i+3 < size {
			val = uint32(src[i]) | uint32(src[i+1])<<8 | uint32(src[i+2])<<16 | uint32(src[i+3])<<24
		} else {
			// Handle remaining bytes
			val = 0
			for j := 0; j+i < size; j++ {
				val |= uint32(src[i+j]) << (j * 8)
			}
		}
		flashWrite32(uintptr(FLASH_STORAGE_START+i), val)
	}
}

// storageWipe clears all storage data
func storageWipe() {
	storage = Storage{
		Magic:   STORAGE_MAGIC,
		Version: STORAGE_VERSION,
	}
	copy(storage.Language[:], "en")
	sessionClear(true)
	storageSave()
}

// sessionClear clears session data
func sessionClear(clearPIN bool) {
	if clearPIN {
		sessionPINcached = false
		for i := range sessionPIN {
			sessionPIN[i] = 0
		}
	}
}

// storageIsInitialized returns true if wallet has been set up
func storageIsInitialized() bool {
	storageInit()
	return storage.Initialized
}

// storageHasPIN returns true if PIN is set
func storageHasPIN() bool {
	storageInit()
	return storage.HasPIN
}

// storageGetLabel returns the device label
func storageGetLabel() string {
	storageInit()
	if !storage.HasLabel {
		return ""
	}
	return string(storage.Label[:storage.LabelLen])
}

// storageSetLabel sets the device label
func storageSetLabel(label string) {
	storage.HasLabel = len(label) > 0
	storage.LabelLen = uint8(len(label))
	if storage.LabelLen > 32 {
		storage.LabelLen = 32
	}
	copy(storage.Label[:], label)
}

// storageNeedsBackup returns true if mnemonic needs backup
func storageNeedsBackup() bool {
	storageInit()
	return storage.NeedsBackup
}

// storageSetNeedsBackup sets the needs backup flag
func storageSetNeedsBackup(needsBackup bool) {
	storage.NeedsBackup = needsBackup
	storageSave()
}

// storagePINCompare compares a PIN with the stored PIN
func storagePINCompare(pin string) bool {
	storageInit()
	if !storage.HasPIN {
		return true // No PIN set means any PIN is valid
	}
	if len(pin) != int(storage.PINLen) {
		return false
	}
	for i := 0; i < int(storage.PINLen); i++ {
		if pin[i] != storage.PIN[i] {
			return false
		}
	}
	return true
}

// storageSetPIN sets a new PIN
func storageSetPIN(pin string) {
	storage.HasPIN = len(pin) > 0
	storage.PINLen = uint8(len(pin))
	if storage.PINLen > 9 {
		storage.PINLen = 9
	}
	copy(storage.PIN[:], pin)
	storageSave()
}

// sessionIsPINcached returns true if PIN is cached for this session
func sessionIsPINcached() bool {
	return sessionPINcached
}

// sessionCachePIN caches the PIN for this session
func sessionCachePIN() {
	sessionPINcached = true
}

// storageGetMnemonic returns the stored mnemonic
func storageGetMnemonic() string {
	storageInit()
	if !storage.HasMnemonic {
		return ""
	}
	return string(storage.Mnemonic[:storage.MnemonicLen])
}

// storageSetMnemonic stores a mnemonic
func storageSetMnemonic(mnemonic string) {
	storage.HasMnemonic = len(mnemonic) > 0
	storage.MnemonicLen = uint8(len(mnemonic))
	if storage.MnemonicLen > 240 {
		storage.MnemonicLen = 240
	}
	copy(storage.Mnemonic[:], mnemonic)
	storage.Initialized = true
	storage.NeedsBackup = true
	storageSave()
}

// storageGetDeviceID returns a unique device ID
func storageGetDeviceID() string {
	// Read STM32 unique ID from ROM
	// Located at 0x1FFF7A10 (96 bits = 12 bytes)
	uid0 := flashRead32(0x1FFF7A10)
	uid1 := flashRead32(0x1FFF7A14)
	_ = flashRead32(0x1FFF7A18) // uid2 - available if needed

	// Convert to hex string (simplified - first 11 chars)
	var id [11]byte
	hexChars := "0123456789ABCDEF"
	id[0] = hexChars[(uid0>>28)&0xF]
	id[1] = hexChars[(uid0>>24)&0xF]
	id[2] = hexChars[(uid0>>20)&0xF]
	id[3] = hexChars[(uid0>>16)&0xF]
	id[4] = hexChars[(uid0>>12)&0xF]
	id[5] = hexChars[(uid0>>8)&0xF]
	id[6] = hexChars[(uid0>>4)&0xF]
	id[7] = hexChars[uid0&0xF]
	id[8] = hexChars[(uid1>>28)&0xF]
	id[9] = hexChars[(uid1>>24)&0xF]
	id[10] = hexChars[(uid1>>20)&0xF]

	return string(id[:])
}
