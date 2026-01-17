package main

// USB Descriptor Types
const (
	USB_DT_DEVICE        = 0x01
	USB_DT_CONFIGURATION = 0x02
	USB_DT_STRING        = 0x03
	USB_DT_INTERFACE     = 0x04
	USB_DT_ENDPOINT      = 0x05
	USB_DT_HID           = 0x21
	USB_DT_REPORT        = 0x22
)

// USB Class Codes
const (
	USB_CLASS_HID = 0x03
)

// USB Endpoint Attributes
const (
	USB_ENDPOINT_ATTR_INTERRUPT = 0x03
)

// USB Request Types
const (
	USB_REQ_GET_STATUS        = 0x00
	USB_REQ_CLEAR_FEATURE     = 0x01
	USB_REQ_SET_FEATURE       = 0x03
	USB_REQ_SET_ADDRESS       = 0x05
	USB_REQ_GET_DESCRIPTOR    = 0x06
	USB_REQ_SET_DESCRIPTOR    = 0x07
	USB_REQ_GET_CONFIGURATION = 0x08
	USB_REQ_SET_CONFIGURATION = 0x09
	USB_REQ_GET_INTERFACE     = 0x0A
	USB_REQ_SET_INTERFACE     = 0x0B
)

// USB HID Request Types
const (
	USB_HID_REQ_GET_REPORT   = 0x01
	USB_HID_REQ_GET_IDLE     = 0x02
	USB_HID_REQ_GET_PROTOCOL = 0x03
	USB_HID_REQ_SET_REPORT   = 0x09
	USB_HID_REQ_SET_IDLE     = 0x0A
	USB_HID_REQ_SET_PROTOCOL = 0x0B
)

// Skywallet USB IDs
const (
	USB_VID = 0x313A
	USB_PID = 0x0001
)

// Endpoint Addresses
const (
	ENDPOINT_ADDRESS_IN  = 0x81
	ENDPOINT_ADDRESS_OUT = 0x01
)

// String Descriptor Indices
const (
	USB_STRING_LANGID       = 0
	USB_STRING_MANUFACTURER = 1
	USB_STRING_PRODUCT      = 2
	USB_STRING_SERIAL       = 3
	USB_STRING_INTERFACE    = 4
)

// Device Descriptor (18 bytes)
var deviceDescriptor = [18]byte{
	18,            // bLength
	USB_DT_DEVICE, // bDescriptorType
	0x00, 0x02,    // bcdUSB = 2.00
	0x00,           // bDeviceClass (defined at interface level)
	0x00,           // bDeviceSubClass
	0x00,           // bDeviceProtocol
	64,             // bMaxPacketSize0
	USB_VID & 0xFF, // idVendor low
	USB_VID >> 8,   // idVendor high
	USB_PID & 0xFF, // idProduct low
	USB_PID >> 8,   // idProduct high
	0x00, 0x01,     // bcdDevice = 1.00
	USB_STRING_MANUFACTURER, // iManufacturer
	USB_STRING_PRODUCT,      // iProduct
	USB_STRING_SERIAL,       // iSerialNumber
	1,                       // bNumConfigurations
}

// HID Report Descriptor (34 bytes)
// Vendor-defined 64-byte input/output reports
var hidReportDescriptor = [34]byte{
	0x06, 0x00, 0xFF, // USAGE_PAGE (Vendor Defined)
	0x09, 0x01, // USAGE (1)
	0xA1, 0x01, // COLLECTION (Application)
	0x09, 0x20, // USAGE (Input Report Data)
	0x15, 0x00, // LOGICAL_MINIMUM (0)
	0x26, 0xFF, 0x00, // LOGICAL_MAXIMUM (255)
	0x75, 0x08, // REPORT_SIZE (8)
	0x95, 0x40, // REPORT_COUNT (64)
	0x81, 0x02, // INPUT (Data,Var,Abs)
	0x09, 0x21, // USAGE (Output Report Data)
	0x15, 0x00, // LOGICAL_MINIMUM (0)
	0x26, 0xFF, 0x00, // LOGICAL_MAXIMUM (255)
	0x75, 0x08, // REPORT_SIZE (8)
	0x95, 0x40, // REPORT_COUNT (64)
	0x91, 0x02, // OUTPUT (Data,Var,Abs)
	0xC0, // END_COLLECTION
}

// Configuration Descriptor with Interface, HID, and Endpoints
// Total length: 9 (config) + 9 (interface) + 9 (HID) + 7 (EP IN) + 7 (EP OUT) = 41 bytes
var configDescriptor = [41]byte{
	// Configuration Descriptor (9 bytes)
	9,                    // bLength
	USB_DT_CONFIGURATION, // bDescriptorType
	41, 0,                // wTotalLength (41 bytes)
	1,    // bNumInterfaces
	1,    // bConfigurationValue
	0,    // iConfiguration
	0x80, // bmAttributes (bus powered)
	50,   // bMaxPower (100mA)

	// Interface Descriptor (9 bytes)
	9,                    // bLength
	USB_DT_INTERFACE,     // bDescriptorType
	0,                    // bInterfaceNumber
	0,                    // bAlternateSetting
	2,                    // bNumEndpoints
	USB_CLASS_HID,        // bInterfaceClass
	0,                    // bInterfaceSubClass
	0,                    // bInterfaceProtocol
	USB_STRING_INTERFACE, // iInterface

	// HID Descriptor (9 bytes)
	9,          // bLength
	USB_DT_HID, // bDescriptorType
	0x11, 0x01, // bcdHID = 1.11
	0,                                   // bCountryCode
	1,                                   // bNumDescriptors
	USB_DT_REPORT,                       // bDescriptorType (Report)
	byte(len(hidReportDescriptor)),      // wDescriptorLength low
	byte(len(hidReportDescriptor) >> 8), // wDescriptorLength high

	// Endpoint IN Descriptor (7 bytes)
	7,                           // bLength
	USB_DT_ENDPOINT,             // bDescriptorType
	ENDPOINT_ADDRESS_IN,         // bEndpointAddress
	USB_ENDPOINT_ATTR_INTERRUPT, // bmAttributes
	64, 0,                       // wMaxPacketSize
	1, // bInterval (1ms)

	// Endpoint OUT Descriptor (7 bytes)
	7,                           // bLength
	USB_DT_ENDPOINT,             // bDescriptorType
	ENDPOINT_ADDRESS_OUT,        // bEndpointAddress
	USB_ENDPOINT_ATTR_INTERRUPT, // bmAttributes
	64, 0,                       // wMaxPacketSize
	1, // bInterval (1ms)
}

// Language ID String Descriptor
var stringLangID = [4]byte{
	4,             // bLength
	USB_DT_STRING, // bDescriptorType
	0x09, 0x04,    // English (US)
}

// String descriptors (UTF-16LE encoded)
// Helper to create string descriptors
func makeStringDescriptor(s string) []byte {
	// String descriptor format: length, type, UTF-16LE characters
	desc := make([]byte, 2+len(s)*2)
	desc[0] = byte(len(desc))
	desc[1] = USB_DT_STRING
	for i, c := range s {
		desc[2+i*2] = byte(c)
		desc[2+i*2+1] = 0
	}
	return desc
}

// Pre-computed string descriptors (to avoid runtime allocation)
var stringManufacturer = [36]byte{
	36, USB_DT_STRING,
	'S', 0, 'k', 0, 'y', 0, 'c', 0, 'o', 0, 'i', 0, 'n', 0,
	'F', 0, 'o', 0, 'u', 0, 'n', 0, 'd', 0, 'a', 0, 't', 0, 'i', 0, 'o', 0, 'n', 0,
}

var stringProduct = [20]byte{
	20, USB_DT_STRING,
	'S', 0, 'K', 0, 'Y', 0, 'W', 0, 'A', 0, 'L', 0, 'L', 0, 'E', 0, 'T', 0,
}

var stringSerial = [26]byte{
	26, USB_DT_STRING,
	'0', 0, '0', 0, '0', 0, '0', 0, '0', 0, '0', 0, '0', 0, '0', 0, '0', 0, '0', 0, '0', 0, '1', 0,
}

var stringInterface = [32]byte{
	32, USB_DT_STRING,
	'S', 0, 'K', 0, 'Y', 0, 'C', 0, 'O', 0, 'I', 0, 'N', 0, ' ', 0,
	'I', 0, 'n', 0, 't', 0, 'e', 0, 'r', 0, 'f', 0, 'a', 0,
}

// GetStringDescriptor returns the string descriptor for the given index
func getStringDescriptor(index uint8) []byte {
	switch index {
	case USB_STRING_LANGID:
		return stringLangID[:]
	case USB_STRING_MANUFACTURER:
		return stringManufacturer[:]
	case USB_STRING_PRODUCT:
		return stringProduct[:]
	case USB_STRING_SERIAL:
		return stringSerial[:]
	case USB_STRING_INTERFACE:
		return stringInterface[:]
	default:
		return nil
	}
}
