/*
 * This file is part of the Skycoin project, https://skycoin.net/
 *
 * Copyright (C) 2018-2019 Skycoin Project
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef __TINYFIRMWARE_FIRMWARE_ERRORCODES__
#define __TINYFIRMWARE_FIRMWARE_ERRORCODES__

#include <stdint.h>

/**
 * @brief The ErrCode_t enum represents the status of an operation with different error modes.
 */
enum ErrCode_t {
	// Success
	ReasonSuccess = 0,
	// Reason unknown
	ReasonUnknown = 0xFFF,
	// Unexpected or invalid value
	ReasonValueError = 1,
	// Value out of bounds
	ReasonOutOfBounds = 2,
};
typedef enum ErrCode_t ErrCode_t;

// 32-bits error constants are structured as folows:
//
// - First byte represents a package (i.e. logical part of the source code)
//   being the origin of the error condition
// - Remaining 24-LSB represent an specific error mode or condition
#define ERROR_CODE(PKG, INDEX) ((PKG) << 24 | (INDEX))

/**
 * Generic error definitions
 */

// Byte prefix for generic error codes
#define PkgGeneric 0

// Operation completed successfully
#define ErrOk           ERROR_CODE(PkgGeneric, ReasonSuccess)
// Generic failure
#define ErrFailed       ERROR_CODE(PkgGeneric, ReasonUnknown)
// Invalid argument
# define ErrInvalidArg  ERROR_CODE(PkgGeneric, ReasonValueError)
// Index out of bounds
# define ErrIndexValue  ERROR_CODE(PkgGeneric, ReasonOutOfBounds)


/**
 * Entropy error codes
 */

// Byte prefix for entropy error codes
#define PkgEntropy 1

// Buffer entropy under 4.0 bits/symbol
# define ErrLowEntropy  ERROR_CODE(PkgEntropy, ReasonOutOfBounds)

#endif  // __TINYFIRMWARE_FIRMWARE_ERRORCODES__
