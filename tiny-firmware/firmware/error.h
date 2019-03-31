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
 * @brief The ErrMode enum represents the error modes.
 */
enum ErrMode
{
	ReasonSuccess = 0,		/*!< Success */
	ReasonUnknown = 0xFFF,		/*!< Reason unknown */
	ReasonArgumentError = 1,	/*!< Unexpected or invalid argument */
	ReasonOutOfBounds = 2,		/*!< Value out of bounds */
	ReasonInvalidState = 3,		/*!< The system get in an invalid state, for example a syc problem in server implementation */
	ReasonValueError = 5,		/*!< Unexpected or invalid value */
	ReasonNotImplemented = 6,	/*!< Not implemented code */
	ReasonPinRequired = 7,          /*!< Action requires PIN and it did not match or is not configured */
};

// 32-bits error constants are structured as folows:
//
// - First byte represents a package (i.e. logical part of the source code)
//   being the origin of the error condition
// - Remaining 24-LSB represent an specific error mode or condition
#define ERROR_CODE(PKG, INDEX) ((int32_t)((PKG) << 24) | (INDEX))

/**
 * @brief The ErrCategory enum
 */
enum ErrCategory {
	PkgGeneric = 1, /*!< Generic error codes */
	PkgEntropy = 2, /*!< Entropy error codes */
	PkgServer = 3, /*! < Server schema related errors */
	PkgSign = 4, /*!   < Signing errors */
} __attribute__ ((__packed__));
_Static_assert(sizeof (enum ErrCategory) == 1, "One byte as max for package");

/**
 * @brief The ErrCode enum
 */
enum ErrCode
{
	ErrOk = ERROR_CODE(PkgGeneric, ReasonSuccess),			     /*!< Operation completed successfully */
	ErrFailed = ERROR_CODE(PkgGeneric, ReasonUnknown),		     /*!< Generic failure */
	ErrInvalidArg = ERROR_CODE(PkgGeneric, ReasonArgumentError),	     /*!< Invalid argument */
	ErrIndexValue = ERROR_CODE(PkgGeneric, ReasonOutOfBounds),	     /*!< Index out of bounds */
	ErrInvalidValue = ERROR_CODE(PkgGeneric, ReasonValueError),	     /*!< Invalid value */
	ErrNotImplemented = ERROR_CODE(PkgGeneric, ReasonNotImplemented),    /*!< Feature not implemented */
	ErrPinRequired = ERROR_CODE(PkgGeneric, ReasonPinRequired),          /*!< Action requires PIN and it did not match or is not configured */
	ErrLowEntropy = ERROR_CODE(PkgEntropy, ReasonArgumentError),	     /*!< Buffer entropy under 4.0 bits/symbol */
	ErrUnexpectedMessage = ERROR_CODE(PkgServer, ReasonInvalidState),    /*!< Server state loses path */
	ErrSignPreconditionFailed = ERROR_CODE(PkgSign, ReasonInvalidState), /*!< Signing precondition failed */
};
typedef enum ErrCode ErrCode_t;
_Static_assert(sizeof (ErrCode_t) == 4, "One byte as max for package");

#endif  // __TINYFIRMWARE_FIRMWARE_ERRORCODES__
