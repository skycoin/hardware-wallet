package main

// handleInitialize handles the Initialize message
// This resets the device session and responds with Features
func handleInitialize(data []byte) {
	println("handleInitialize")

	// Parse Initialize message
	init := decodeInitialize(data)

	// TODO: Check state and clear session if different
	_ = init.State

	// Clear any cached session data
	sessionClear()

	// Update home screen display
	layoutHome()

	// Respond with Features
	sendFeatures()
}

// handleGetFeatures handles the GetFeatures message
// This responds with device capabilities without resetting session
func handleGetFeatures(data []byte) {
	println("handleGetFeatures")

	// No need to decode - GetFeatures has no fields
	_ = decodeGetFeatures(data)

	// Respond with Features
	sendFeatures()
}

// handlePing handles the Ping message
// This echoes the message back in a Success response
func handlePing(data []byte) {
	println("handlePing")

	// Parse Ping message
	ping := decodePing(data)

	// Check for button protection
	if ping.ButtonProtection {
		// TODO: Show confirmation dialog and wait for button
		// For now, just proceed
		println("Button protection requested (not implemented)")
	}

	// Check for PIN protection
	if ping.PinProtection {
		// TODO: Request and verify PIN
		println("PIN protection requested (not implemented)")
	}

	// Check for passphrase protection
	if ping.PassphraseProtection {
		// TODO: Request and cache passphrase
		println("Passphrase protection requested (not implemented)")
	}

	// Echo message back in Success
	sendSuccess(ping.Message)
}

// Session management (placeholder)
func sessionClear() {
	// TODO: Clear cached PIN, passphrase, etc.
	println("Session cleared")
}

// Layout management
func layoutHome() {
	// Update OLED to show home screen
	oledClear()
	oledDrawStringCenter(0, "SKYWALLET")
	oledDrawStringCenter(16, "TINYGO")
	oledDrawStringCenter(32, "v0.1.0")

	if isConfigured() {
		oledDrawStringCenter(48, "READY")
	} else {
		oledDrawStringCenter(48, "NO USB")
	}

	oledRefresh()
}
