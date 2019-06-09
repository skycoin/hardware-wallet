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

#ifndef SKYCOIN_CHECK_SIGNATURE_TOOLS_H
#define SKYCOIN_CHECK_SIGNATURE_TOOLS_H

#include "bignum.h"
#include "ecdsa.h"
#include <stdint.h>


typedef struct jacobian_curve_point {
    bignum256 x, y, z;
} jacobian_curve_point;


void uncompress_mcoords(const ecdsa_curve* curve, uint8_t odd, const bignum256* x, bignum256* y);
int mecdsa_validate_pubkey(const ecdsa_curve* curve, const curve_point* pub);
void mpoint_multiply(const ecdsa_curve* curve, const bignum256* k, const curve_point* p, curve_point* res);
void mscalar_multiply(const ecdsa_curve* curve, const bignum256* k, curve_point* res);
void mpoint_set_infinity(curve_point* p);
int mpoint_is_infinity(const curve_point* p);
void mpoint_add(const ecdsa_curve* curve, const curve_point* cp1, curve_point* cp2);
void mpoint_copy(const curve_point* cp1, curve_point* cp2);
int mpoint_is_equal(const curve_point* p, const curve_point* q);
int mpoint_is_negative_of(const curve_point* p, const curve_point* q);
void mpoint_double(const ecdsa_curve* curve, curve_point* cp);
void mcurve_to_jacobian(const curve_point* p, jacobian_curve_point* jp, const bignum256* prime);
void mjacobian_to_curve(const jacobian_curve_point* jp, curve_point* p, const bignum256* prime);
void mpoint_jacobian_add(const curve_point* p1, jacobian_curve_point* p2, const ecdsa_curve* curve);
void mconditional_negate(uint32_t cond, bignum256* a, const bignum256* prime);
void mpoint_jacobian_double(jacobian_curve_point* p, const ecdsa_curve* curve);

#endif
