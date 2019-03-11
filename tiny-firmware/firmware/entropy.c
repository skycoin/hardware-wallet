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

#include <string.h>

#include "messages.pb.h"

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
 * @brief compute an integer entropy factor in a giving histogram
 * @param hist histogram to mesure the entropy from
 * @param histlen histogram length
 * @param len amount of symbols
 * @return the Shannon entropy (bits/symbol)
 * @sa https://rosettacode.org/wiki/Entropy
 */
static uint64_t entropy_factor(
	const uint8_t *const hist, uint8_t histlen, uint16_t len) {
	// Python : nlogn = [x * math.log2(x) * 100 for x in range(256) ]
	static uint32_t nlog[256] = {
		0, 0, 200, 475, 800, 1160, 1550, 1965, 2400, 2852, 3321,
		3805, 4301, 4810, 5330, 5860, 6400, 6948, 7505, 8071, 8643,
		9223, 9810, 10404, 11003, 11609, 12221, 12838, 13460, 14088, 14720,
		15358, 16000, 16646, 17297, 17952, 18611, 19274, 19942, 20613, 21287,
		21965, 22647, 23332, 24021, 24713, 25408, 26106, 26807, 27512, 28219,
		28929, 29642, 30357, 31076, 31797, 32521, 33247, 33976, 34707, 35441,
		36177, 36916, 37656, 38400, 39145, 39893, 40642, 41394, 42148, 42904,
		43663, 44423, 45185, 45949, 46716, 47484, 48254, 49026, 49799, 50575,
		51352, 52131, 52912, 53695, 54479, 55265, 56053, 56842, 57634, 58426,
		59220, 60016, 60814, 61613, 62413, 63215, 64019, 64824, 65630, 66438,
		67247, 68058, 68870, 69684, 70499, 71315, 72133, 72952, 73773, 74594,
		75418, 76242, 77068, 77894, 78723, 79552, 80383, 81215, 82048, 82882,
		83718, 84554, 85392, 86232, 87072, 87913, 88756, 89600, 90444, 91290,
		92137, 92986, 93835, 94685, 95537, 96389, 97243, 98097, 98953, 99809,
		100667, 101526, 102386, 103246, 104108, 104971, 105835, 106699, 107565, 108432,
		109299, 110168, 111038, 111908, 112779, 113652, 114525, 115399, 116274, 117150,
		118027, 118905, 119784, 120663, 121544, 122425, 123307, 124190, 125074, 125959,
		126845, 127731, 128619, 129507, 130396, 131285, 132176, 133068, 133960, 134853,
		135747, 136641, 137537, 138433, 139330, 140228, 141126, 142026, 142926, 143827,
		144728, 145631, 146534, 147438, 148342, 149248, 150154, 151061, 151968, 152877,
		153786, 154695, 155606, 156517, 157429, 158341, 159255, 160169, 161083, 161999,
		162915, 163831, 164749, 165667, 166586, 167505, 168425, 169346, 170267, 171189,
		172112, 173036, 173960, 174884, 175810, 176736, 177662, 178589, 179517, 180446,
		181375, 182305, 183235, 184166, 185098, 186030, 186963, 187896, 188830, 189765,
		190700, 191636, 192572, 193509, 194447, 195385, 196324, 197264, 198204, 199144,
		200085, 201027, 201969, 202912, 203856
	};
	uint64_t sum = 0;
	uint64_t log_len = nlog[len] /	(100 * (uint64_t) len);
	for (uint8_t i = 0; i < histlen; ++i) {
		uint64_t hval = hist[i];
		sum += hval * log_len - nlog[hval];
	}
	return sum;
}

/**
 * @brief verify_entropy says if a bytes distribution have enough entropy
 * @param bytes the bytes to mesur the entropy
 * @param size the size of bytes
 * @return an error if not fit minimal entropy required
 * @sa entropy, make_histogram
 */
ErrCode_t verify_entropy(const uint8_t* const bytes, uint64_t size) {
	uint8_t hist[size];
	memset(hist, 0, size);
	uint8_t histlen = make_histogram(bytes, size, hist);
	uint64_t entr = entropy_factor(hist, histlen, size);
	return (entr < size << 2) ? ErrLowEntropy : ErrOk;
}
