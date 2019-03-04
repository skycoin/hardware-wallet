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

#include "entropy.h"

/**
 * @brief make_histogram create a histogram in plce from bytes
 * @param bytes source to build the histogram
 * @param bytes_size size of source bites
 * @param hist output variable to fill with histogram values
 * @return the histogram length
 */
static uint8_t make_histogram(
	const uint8_t* const bytes, uint16_t bytes_size, uint8_t *hist) {
	// NOTE(denisacostaq@gmail.com): byte_posibilities = 2^sizeof(S[0])
	const uint16_t byte_posibilities = 256;
	int wherechar[byte_posibilities];
	for (uint16_t i = 0; i < byte_posibilities; ++i) {
		wherechar[i] = -1;
	}
	{GenerateMnemonic gmMsg;
		_Static_assert(
			sizeof(gmMsg.entropy.bytes) < 256, // 2^(size of uint8_t )
			"entropy.bytes can acumulate more than len, histlen and/or hist[i]");}
	uint8_t histlen = 0;
	for (uint8_t i = 0; i < bytes_size; ++i) {
		if (wherechar[bytes[i]] == -1) {
			wherechar[bytes[i]] = histlen++;
		}
		++hist[wherechar[bytes[i]]];
	}
	return histlen;
}

/**
 * @brief entropy return the entropy in a giving histogram
 * @param hist histogram to mesure the entropy from
 * @param histlen histogram length
 * @param len amount of symbols
 * @return the Shannon entropy (bits/symbol)
 * @sa https://rosettacode.org/wiki/Entropy
 */
static float entropy(
	const uint8_t *const hist, uint8_t histlen, uint16_t len) {
	float entr = .0f;
	for (uint8_t i = 0; i < histlen; ++i) {
		entr -= (float)hist[i]/len * (float)log2((double)hist[i]/len);
	}
	return entr;
}

/**
 * @brief verify_entropy says if a bytes distribution have enough entropy
 * @param bytes the bytes to mesur the entropy
 * @param size the size of bytes
 * @return an error if not fit minimal entropy required
 * @sa entropy, make_histogram
 */
ErrCode_t verify_entropy(const uint8_t* const bytes, uint16_t size) {
	uint8_t hist[size];
	memset(hist, 0, size);
	uint8_t histlen = make_histogram(bytes, size, hist);
	float entr = entropy(hist, histlen, size);
	return entr < 4.f ? ErrFailed : ErrOk;
}

