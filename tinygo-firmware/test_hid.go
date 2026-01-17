//go:build ignore
// +build ignore

package main

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/karalabe/hid"
)

const (
	VID uint16 = 0x313a
	PID uint16 = 0x0001
)

func main() {
	// Find devices
	devices := hid.Enumerate(VID, PID)
	if len(devices) == 0 {
		fmt.Println("No device found")
		return
	}

	fmt.Printf("Found %d device(s)\n", len(devices))
	for i, d := range devices {
		fmt.Printf("[%d] Path: %s, Interface: %d\n", i, d.Path, d.Interface)
	}

	// Open first device
	device, err := devices[0].Open()
	if err != nil {
		fmt.Printf("Failed to open device: %v\n", err)
		return
	}
	defer device.Close()

	// Send SkycoinAddress message (MessageType 114)
	// Format: ?## + msgID (2 bytes BE) + length (4 bytes BE) + payload
	// Payload: protobuf encoded SkycoinAddress (empty = address_n=0, count=1)
	// Empty message means: generate 1 address starting from index 0

	// For SkycoinAddress: address_n=1 (default), start_index=0 (default)
	// We send empty payload to use defaults

	msgID := uint16(114) // SkycoinAddress
	payload := []byte{}  // Empty payload = use defaults

	packet := make([]byte, 64)
	packet[0] = '?'
	packet[1] = '#'
	packet[2] = '#'
	packet[3] = byte(msgID >> 8)
	packet[4] = byte(msgID)
	packet[5] = byte(len(payload) >> 24)
	packet[6] = byte(len(payload) >> 16)
	packet[7] = byte(len(payload) >> 8)
	packet[8] = byte(len(payload))
	copy(packet[9:], payload)

	fmt.Printf("Sending: %s\n", hex.EncodeToString(packet))

	n, err := device.Write(packet)
	if err != nil {
		fmt.Printf("Write error: %v\n", err)
		return
	}
	fmt.Printf("Wrote %d bytes\n", n)

	// Wait for response
	time.Sleep(100 * time.Millisecond)

	// Read response
	response := make([]byte, 64)
	n, err = device.Read(response)
	if err != nil {
		fmt.Printf("Read error: %v\n", err)
		return
	}

	fmt.Printf("Read %d bytes: %s\n", n, hex.EncodeToString(response[:n]))

	// Parse response
	if n > 9 && response[0] == '?' && response[1] == '#' && response[2] == '#' {
		respID := uint16(response[3])<<8 | uint16(response[4])
		respLen := uint32(response[5])<<24 | uint32(response[6])<<16 | uint32(response[7])<<8 | uint32(response[8])
		fmt.Printf("Response: MessageType=%d, Length=%d\n", respID, respLen)
		if respLen > 0 && respLen < 55 {
			fmt.Printf("Payload: %s\n", hex.EncodeToString(response[9:9+respLen]))
			// Try to decode as string if it looks like ResponseSkycoinAddress
			if respID == 117 && respLen > 2 {
				// Field 1, wire type 2 (string)
				if response[9] == 0x0a {
					strLen := int(response[10])
					if strLen < int(respLen)-2 {
						addr := string(response[11 : 11+strLen])
						fmt.Printf("Address: %s\n", addr)
					}
				}
			}
		}
	} else {
		fmt.Printf("Invalid response format\n")
	}
}
