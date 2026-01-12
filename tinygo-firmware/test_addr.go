//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"os"

	"github.com/skycoin/hardware-wallet-go/src/skywallet"
	messages "github.com/skycoin/hardware-wallet-protob/go"
)

func main() {
	device := skywallet.NewDevice(skywallet.DeviceTypeUSB)
	if device == nil {
		fmt.Println("No device found")
		os.Exit(1)
	}
	defer device.Close()

	// Get 1 address starting from index 0
	msg, err := device.AddressGen(1, 0, false)
	if err != nil {
		fmt.Printf("AddressGen error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Response kind: %d\n", msg.Kind)
	fmt.Printf("Response data hex: %x\n", msg.Data)

	if msg.Kind == uint16(messages.MessageType_MessageType_ResponseSkycoinAddress) {
		addresses, err := skywallet.DecodeResponseSkycoinAddress(msg)
		if err != nil {
			fmt.Printf("Decode error: %v\n", err)
		} else {
			fmt.Printf("Addresses: %v\n", addresses)
		}
	} else if msg.Kind == uint16(messages.MessageType_MessageType_Failure) {
		failMsg, _ := skywallet.DecodeFailMsg(msg)
		fmt.Printf("Failure: %s\n", failMsg)
	} else if msg.Kind == uint16(messages.MessageType_MessageType_Success) {
		fmt.Printf("Success: %s\n", string(msg.Data))
	} else {
		fmt.Printf("Unexpected message type: %d\n", msg.Kind)
	}
}
