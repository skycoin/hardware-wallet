//go:build ignore
// +build ignore

package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/karalabe/hid"
)

const (
	VID uint16 = 0x313a
	PID uint16 = 0x0001
)

func main() {
	testCmd := "SHA256"
	if len(os.Args) > 1 {
		testCmd = os.Args[1]
	}

	// Find devices
	devices := hid.Enumerate(VID, PID)
	if len(devices) == 0 {
		fmt.Println("No device found")
		return
	}

	// Open first device
	device, err := devices[0].Open()
	if err != nil {
		fmt.Printf("Failed to open device: %v\n", err)
		return
	}
	defer device.Close()

	// Build ping message with test command
	pingMsg := "TEST:" + testCmd

	// Encode as protobuf Ping message
	// Field 1 (message) = wire type 2 (string)
	// 0x0a = field 1, wire type 2
	payload := make([]byte, 2+len(pingMsg))
	payload[0] = 0x0a // field 1, wire type 2
	payload[1] = byte(len(pingMsg))
	copy(payload[2:], pingMsg)

	// Send Ping message (MessageType 1)
	msgID := uint16(1) // Ping

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

	fmt.Printf("Sending TEST:%s\n", testCmd)
	fmt.Printf("Packet: %s\n", hex.EncodeToString(packet[:20]))

	n, err := device.Write(packet)
	if err != nil {
		fmt.Printf("Write error: %v\n", err)
		return
	}
	fmt.Printf("Wrote %d bytes\n", n)

	// Wait for response
	time.Sleep(500 * time.Millisecond)

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

		// Decode Success message (field 1 is string)
		if respID == 2 && respLen > 0 {
			// Parse string field
			if response[9] == 0x0a && respLen > 2 {
				strLen := int(response[10])
				if strLen <= int(respLen)-2 {
					msg := string(response[11 : 11+strLen])
					fmt.Printf("Result: %s\n", msg)
				}
			} else {
				fmt.Printf("Payload: %s\n", hex.EncodeToString(response[9:9+respLen]))
			}
		} else if respID == 3 {
			// Failure message
			fmt.Printf("FAILURE - Payload: %s\n", hex.EncodeToString(response[9:9+respLen]))
		}
	} else {
		fmt.Printf("Invalid response format\n")
	}
}
