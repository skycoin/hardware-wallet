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
	ReasonSuccess = 0, /*!         < Success */
	ReasonUnknown = 0xFFF, /*!     < Reason unknown */
	ReasonArgumentError = 1, /*!   < Unexpected or invalid argument */
	ReasonOutOfBounds = 2, /*!     < Value out of bounds */
	ReasonInvalidState = 3,	/*!    < The system get in an invalid state, for example a syc problem in server implementation */
	ReasonValueError = 4, /*!      < Unexpected or invalid value */
	ReasonNotImplemented = 5, /*!  < Not implemented code */
	ReasonActionCancelled = 6, /*! < Action cancelled by user */
	ReasonUserConfirmation = 7, /*!< User confirmation needed to complete action */
	ReasonExpired = 8, /*!         < User confirmation needed to complete action */
	ReasonSkip = 9, /*!            < User confirmation needed to complete action */
	ReasonInvalidChecksum = 9, /*! < User confirmation needed to complete action */
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
	PkgGeneric = 1, /*! < Generic error codes */
	PkgEntropy = 2, /*! < Entropy error codes */
	PkgServer = 3, /*!  < Server schema related errors */
	PkgSign = 4, /*!    < Signing errors */
	PkgPinChk = 5, /*!  < Pin errors */
	PkgStorage = 6, /*! < Storage errors */
	PkgMnemonic = 7, /*!< Mnemonic errors */
	PkgAddress = 8, /*! < Address errors */
	PkgBackup = 9, /*!  < Backup errors */
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
	ErrUserConfirmation = ERROR_CODE(PkgGeneric, ReasonUserConfirmation), /*!< User confirmation required to complete action */
	ErrInvalidChecksum = ERROR_CODE(PkgGeneric, ReasonInvalidChecksum), /*!< Checksum verification failed */
	ErrPinRequired = ERROR_CODE(PkgPinChk, ReasonInvalidState),          /*!< Action requires PIN and is not configured */
	ErrPinMismatch = ERROR_CODE(PkgPinChk, ReasonValueError),          /*!< Action requires PIN and it didn't match */
	ErrPinCancelled = ERROR_CODE(PkgPinChk, ReasonActionCancelled), /*!< Action requires PIN and was cancelled by user */
	ErrActionCancelled = ERROR_CODE(PkgGeneric, ReasonActionCancelled), /*!< Action cancelled by user */
	ErrNotInitialized = ERROR_CODE(PkgStorage, ReasonInvalidState), /*!< Storage not initialized */
	ErrMnemonicRequired = ERROR_CODE(PkgMnemonic, ReasonInvalidState), /*!< Mnemonic required */
	ErrAddressGeneration = ERROR_CODE(PkgAddress, ErrInvalidValue), /*!< Failed address generation */
	ErrTooManyAddresses = ERROR_CODE(PkgAddress, ReasonOutOfBounds), /*!< Too many addresses to generate */
	ErrUnfinishedBackup = ERROR_CODE(PkgBackup, ReasonInvalidState), /*!< Backup operation did not finish properly */
	ErrEntropyRequired = ERROR_CODE(PkgEntropy, ReasonExpired),	/*!< External entropy required */
	ErrEntropyAvailable = ERROR_CODE(PkgEntropy, ReasonSuccess),	/*!< External entropy available */
	ErrEntropyNotNeeded = ERROR_CODE(PkgEntropy, ReasonSkip),	/*!< External entropy not needed */
	ErrLowEntropy = ERROR_CODE(PkgEntropy, ReasonOutOfBounds),	     /*!< Buffer entropy under 4.0 bits/symbol */
	ErrUnexpectedMessage = ERROR_CODE(PkgServer, ReasonInvalidState),    /*!< Server state loses path */
	ErrSignPreconditionFailed = ERROR_CODE(PkgSign, ReasonInvalidState), /*!< Signing precondition failed */
	ErrInvalidSignature = ERROR_CODE(PkgSign, ReasonValueError), /*!< Invalid Message Signature */
};
typedef enum ErrCode ErrCode_t;
_Static_assert(sizeof (ErrCode_t) == 4, "One byte as max for package");

#endif  // __TINYFIRMWARE_FIRMWARE_ERRORCODES__
