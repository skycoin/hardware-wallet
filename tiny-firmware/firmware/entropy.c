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

#include "protob/c/messages.pb.h"

/**
 * @brief make_histogram create a histogram in place from bytes
 * @param bytes source to build the histogram from
 * @param bytes_size size of source bytes
 * @param hist output variable to fill with histogram values
 * @return the histogram length
 */
uint8_t make_histogram(
	const uint8_t* const bytes, uint16_t bytes_size, uint8_t *hist) {
	// NOTE(denisacostaq@gmail.com): byte_posibilities = 2^sizeof(bytes[0])
	const uint8_t byte_posibilities = 255; // +1, 0-255
	int32_t wherechar[byte_posibilities];
	for (uint16_t i = 0; i <= byte_posibilities; ++i) {
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
 * @brief entropy return the entropy from a given histogram
 * @param hist histogram to measure the entropy from (count values in formula)
 * @param histlen histogram length (<strong>n</strong> in formula)
 * @param len amount of symbols (<strong>N</strong> in formula)
 * @details Given the discrete random variable <strong>X</strong> that is an 
 * @details array of <strong>N</strong> "symbols" (total characters) consisting 
 * @details of <strong>n</strong> different characters (n=2 for binary), 
 * @details the Shannon entropy of X in bits/symbol is:
 * @details \f{eqnarray*}{
	H(x)=-\sum_i^n\frac{count_{i}}{N}\log_{2}{\frac{count_{i}}{N}}
\f}
 * @details where <strong>count_{i}</strong> is the count of character 
 * @details <strong>n_{i}</strong>.
 * @details In this implementation, the shanon entropy equation is modified as 
 * @details follow (to avoid floating point aritmetics in a microcontroller 
 * @details without FPU):
 * @details \f{eqnarray*}{
	H(x)=-\sum_i^n\frac{count_{i}}{N}\log_{2}{\frac{count_{i}}{N}} \\
	100H(x)=-100\sum_i^n\frac{count_{i}}{N}\log_{2}{\frac{count_{i}}{N}} \\
	100H(x)=-\sum_i^n\frac{count_{i}}{N}100\log_{2}{\frac{count_{i}}{N}} \\
	100H(x)=-\sum_i^n\frac{count_{i}}{N}100(\log_{2}count_{i} - \log_{2}{N}) \\
	100H(x)=-\sum_i^n\frac{count_{i}}{N}(100\log_{2}count_{i} - 100\log_{2}{N}) \\
	100H(x)=-\frac{1}{N}\sum_i^ncount_{i}(100\log_{2}count_{i} - 100\log_{2}{N}) \\
	100H(x)N=-\sum_i^ncount_{i}(100\log_{2}count_{i} - 100\log_{2}{N})
\f}
 * @return the Shannon entropy (bits/symbol) multiplied by 100 and by len
 * @sa https://rosettacode.org/wiki/Entropy
 */
int32_t entropy_factor(
	const uint8_t *const hist, uint8_t histlen, uint16_t len) {
	// Python : log2_100 = [math.round(math.log2(x) * 100) for x in range(256)]
	static const uint16_t log2_100[] = {
		0,   0,   100, 158, 200, 232, 258, 281, 300, 317, 332, 346, 358, 370, 
		381, 391, 400, 409, 417, 425, 432, 439, 446, 452, 458, 464, 470, 475, 
		481, 486, 491, 495, 500, 504, 509, 513, 517, 521, 525, 529, 532, 536, 
		539, 543, 546, 549, 552, 555, 558, 561, 564, 567, 570, 573, 575, 578, 
		581, 583, 586, 588, 591, 593, 595, 598, 600, 602, 604, 607, 609, 611, 
		613, 615, 617, 619, 621, 623, 625, 627, 629, 630, 632, 634, 636, 638, 
		639, 641, 643, 644, 646, 648, 649, 651, 652, 654, 655, 657, 658, 660, 
		661, 663, 664, 666, 667, 669, 670, 671, 673, 674, 675, 677, 678, 679, 
		681, 682, 683, 685, 686, 687, 688, 689, 691, 692, 693, 694, 695, 697, 
		698, 699, 700, 701, 702, 703, 704, 706, 707, 708, 709, 710, 711, 712, 
		713, 714, 715, 716, 717, 718, 719, 720, 721, 722, 723, 724, 725, 726, 
		727, 728, 729, 729, 730, 731, 732, 733, 734, 735, 736, 737, 738, 738, 
		739, 740, 741, 742, 743, 743, 744, 745, 746, 747, 748, 748, 749, 750, 
		751, 752, 752, 753, 754, 755, 755, 756, 757, 758, 758, 759, 760, 761, 
		761, 762, 763, 764, 764, 765, 766, 767, 767, 768, 769, 769, 770, 771,
		771, 772, 773, 773, 774, 775, 775, 776, 777, 777, 778, 779, 779, 780, 
		781, 781, 782, 783, 783, 784, 785, 785, 786, 786, 787, 788, 788, 789, 
		789, 790, 791, 791, 792, 792, 793, 794, 794, 795, 795, 796, 797, 797, 
		798, 798, 799, 799
	};
	_Static_assert(
		sizeof (log2_100)/sizeof (log2_100[0]) == 256, 
		"Should have defined log2 in 0:255 range");
	int32_t sum = 0; // max asigned value could be 52363264
	uint16_t log2_len = log2_100[len];
	for (uint8_t i = 0; i < histlen; ++i) {
		sum -= hist[i] * (log2_100[hist[i]] - log2_len);
	}
	return sum;
}

/**
 * @brief verify_entropy says if a bytes distribution have enough entropy
 * @param bytes the bytes to measure the entropy
 * @param size the size of bytes
 * @return an error if not fit minimal entropy required
 * @sa entropy_factor, make_histogram
 */
ErrCode_t verify_entropy(const uint8_t* const bytes, uint16_t size) {
	uint8_t hist[size];
	memset(hist, 0, size);
	uint8_t histlen = make_histogram(bytes, size, hist);
	int32_t entr = entropy_factor(hist, histlen, size);
	// NOTE(denisacostaq@gmail.com): multiplied by 100 and by size as specified 
	// in entropy factor
	return entr < 400 * size ? ErrFailed : ErrOk;
}
