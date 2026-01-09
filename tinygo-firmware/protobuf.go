package main

// Minimal protobuf encoding/decoding for Skywallet messages
// This is hand-coded for the specific message types we need,
// avoiding reflection and the full protobuf library.

// Protobuf wire types
const (
	WireVarint  = 0
	WireFixed64 = 1
	WireBytes   = 2 // Also used for strings
	WireFixed32 = 5
)

// Encoding buffer helper
type PbEncoder struct {
	buf []byte
	pos int
}

// Create encoder with pre-allocated buffer
func newEncoder(buf []byte) *PbEncoder {
	return &PbEncoder{buf: buf, pos: 0}
}

// Get encoded bytes
func (e *PbEncoder) Bytes() []byte {
	return e.buf[:e.pos]
}

// Encode varint
func (e *PbEncoder) putVarint(v uint64) {
	for v >= 0x80 {
		e.buf[e.pos] = byte(v) | 0x80
		e.pos++
		v >>= 7
	}
	e.buf[e.pos] = byte(v)
	e.pos++
}

// Encode field tag
func (e *PbEncoder) putTag(fieldNum int, wireType int) {
	e.putVarint(uint64(fieldNum<<3 | wireType))
}

// Encode string field
func (e *PbEncoder) putString(fieldNum int, s string) {
	if len(s) == 0 {
		return
	}
	e.putTag(fieldNum, WireBytes)
	e.putVarint(uint64(len(s)))
	for i := 0; i < len(s); i++ {
		e.buf[e.pos] = s[i]
		e.pos++
	}
}

// Encode bytes field
func (e *PbEncoder) putBytes(fieldNum int, b []byte) {
	if len(b) == 0 {
		return
	}
	e.putTag(fieldNum, WireBytes)
	e.putVarint(uint64(len(b)))
	copy(e.buf[e.pos:], b)
	e.pos += len(b)
}

// Encode uint32 field
func (e *PbEncoder) putUint32(fieldNum int, v uint32) {
	e.putTag(fieldNum, WireVarint)
	e.putVarint(uint64(v))
}

// Encode bool field
func (e *PbEncoder) putBool(fieldNum int, v bool) {
	e.putTag(fieldNum, WireVarint)
	if v {
		e.putVarint(1)
	} else {
		e.putVarint(0)
	}
}

// Decoding buffer helper
type PbDecoder struct {
	buf []byte
	pos int
}

// Create decoder
func newDecoder(buf []byte) *PbDecoder {
	return &PbDecoder{buf: buf, pos: 0}
}

// Check if more data available
func (d *PbDecoder) hasMore() bool {
	return d.pos < len(d.buf)
}

// Decode varint
func (d *PbDecoder) getVarint() uint64 {
	var v uint64
	var shift uint
	for {
		if d.pos >= len(d.buf) {
			return 0
		}
		b := d.buf[d.pos]
		d.pos++
		v |= uint64(b&0x7F) << shift
		if b < 0x80 {
			break
		}
		shift += 7
	}
	return v
}

// Decode field tag
func (d *PbDecoder) getTag() (fieldNum int, wireType int) {
	v := d.getVarint()
	return int(v >> 3), int(v & 0x7)
}

// Skip field based on wire type
func (d *PbDecoder) skipField(wireType int) {
	switch wireType {
	case WireVarint:
		d.getVarint()
	case WireFixed64:
		d.pos += 8
	case WireBytes:
		length := int(d.getVarint())
		d.pos += length
	case WireFixed32:
		d.pos += 4
	}
}

// Decode string field (after tag is read)
func (d *PbDecoder) getString() string {
	length := int(d.getVarint())
	if d.pos+length > len(d.buf) {
		return ""
	}
	s := string(d.buf[d.pos : d.pos+length])
	d.pos += length
	return s
}

// Decode bytes field (after tag is read)
func (d *PbDecoder) getBytes() []byte {
	length := int(d.getVarint())
	if d.pos+length > len(d.buf) {
		return nil
	}
	b := d.buf[d.pos : d.pos+length]
	d.pos += length
	return b
}

// Decode uint32 field (after tag is read)
func (d *PbDecoder) getUint32() uint32 {
	return uint32(d.getVarint())
}

// Decode bool field (after tag is read)
func (d *PbDecoder) getBool() bool {
	return d.getVarint() != 0
}

// Message-specific encoding functions

// Encode Features message
func encodeFeatures(f *Features) []byte {
	var buf [512]byte
	e := newEncoder(buf[:])

	if f.Vendor != "" {
		e.putString(1, f.Vendor)
	}
	if f.MajorVersion != 0 {
		e.putUint32(2, f.MajorVersion)
	}
	if f.MinorVersion != 0 {
		e.putUint32(3, f.MinorVersion)
	}
	if f.PatchVersion != 0 {
		e.putUint32(4, f.PatchVersion)
	}
	if f.BootloaderMode {
		e.putBool(5, f.BootloaderMode)
	}
	if f.DeviceID != "" {
		e.putString(6, f.DeviceID)
	}
	if f.PinProtection {
		e.putBool(7, f.PinProtection)
	}
	if f.PassphraseProtection {
		e.putBool(8, f.PassphraseProtection)
	}
	if f.Language != "" {
		e.putString(9, f.Language)
	}
	if f.Label != "" {
		e.putString(10, f.Label)
	}
	if f.Initialized {
		e.putBool(12, f.Initialized)
	}
	if f.PinCached {
		e.putBool(16, f.PinCached)
	}
	if f.PassphraseCached {
		e.putBool(17, f.PassphraseCached)
	}
	if f.FirmwarePresent {
		e.putBool(18, f.FirmwarePresent)
	}
	if f.NeedsBackup {
		e.putBool(19, f.NeedsBackup)
	}
	if f.Model != "" {
		e.putString(21, f.Model)
	}
	if f.FwMajor != 0 {
		e.putUint32(22, f.FwMajor)
	}
	if f.FwMinor != 0 {
		e.putUint32(23, f.FwMinor)
	}
	if f.FwPatch != 0 {
		e.putUint32(24, f.FwPatch)
	}
	if f.FwVersionHead != "" {
		e.putString(25, f.FwVersionHead)
	}
	if f.FwVendor != "" {
		e.putString(26, f.FwVendor)
	}
	if f.UnfinishedBackup {
		e.putBool(28, f.UnfinishedBackup)
	}
	if f.FirmwareFeatures != 0 {
		e.putUint32(29, f.FirmwareFeatures)
	}

	return e.Bytes()
}

// Encode Success message
func encodeSuccess(s *Success) []byte {
	var buf [256]byte
	e := newEncoder(buf[:])

	if s.MsgType != 0 {
		e.putUint32(1, uint32(s.MsgType))
	}
	if s.Message != "" {
		e.putString(2, s.Message)
	}

	return e.Bytes()
}

// Encode Failure message
func encodeFailure(f *Failure) []byte {
	var buf [256]byte
	e := newEncoder(buf[:])

	if f.MsgType != 0 {
		e.putUint32(1, uint32(f.MsgType))
	}
	if f.Code != 0 {
		e.putUint32(2, uint32(f.Code))
	}
	if f.Message != "" {
		e.putString(3, f.Message)
	}

	return e.Bytes()
}

// Decode Initialize message
func decodeInitialize(data []byte) *Initialize {
	init := &Initialize{}
	d := newDecoder(data)

	for d.hasMore() {
		fieldNum, wireType := d.getTag()
		switch fieldNum {
		case 1: // state (bytes)
			if wireType == WireBytes {
				init.State = d.getBytes()
			} else {
				d.skipField(wireType)
			}
		default:
			d.skipField(wireType)
		}
	}

	return init
}

// Decode Ping message
func decodePing(data []byte) *Ping {
	ping := &Ping{}
	d := newDecoder(data)

	for d.hasMore() {
		fieldNum, wireType := d.getTag()
		switch fieldNum {
		case 1: // message (string)
			if wireType == WireBytes {
				ping.Message = d.getString()
			} else {
				d.skipField(wireType)
			}
		case 2: // button_protection (bool)
			if wireType == WireVarint {
				ping.ButtonProtection = d.getBool()
			} else {
				d.skipField(wireType)
			}
		case 3: // pin_protection (bool)
			if wireType == WireVarint {
				ping.PinProtection = d.getBool()
			} else {
				d.skipField(wireType)
			}
		case 4: // passphrase_protection (bool)
			if wireType == WireVarint {
				ping.PassphraseProtection = d.getBool()
			} else {
				d.skipField(wireType)
			}
		default:
			d.skipField(wireType)
		}
	}

	return ping
}

// Decode GetFeatures (empty message)
func decodeGetFeatures(data []byte) *GetFeatures {
	// GetFeatures has no fields
	return &GetFeatures{}
}
