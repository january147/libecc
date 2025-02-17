/*
 *  Copyright (C) 2021 - This file is part of libecc project
 *
 *  Authors:
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *      Ryad BENADJILA <ryadbenadjila@gmail.com>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */
#include <libecc/lib_ecc_config.h>
#ifdef WITH_CURVE_WEI448

#ifndef __EC_PARAMS_WEI448_H__
#define __EC_PARAMS_WEI448_H__
#include "../known/ec_params_external.h"
static const u8 wei448_p[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
};

TO_EC_STR_PARAM(wei448_p);

#define CURVE_WEI448_P_BITLEN 448
static const u8 wei448_p_bitlen[] = {
	0x01, 0xc0, 
};

TO_EC_STR_PARAM(wei448_p_bitlen);

#if (WORD_BYTES == 8)     /* 64-bit words */
static const u8 wei448_r[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x01, 
};

TO_EC_STR_PARAM(wei448_r);

static const u8 wei448_r_square[] = {
	0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x02, 
};

TO_EC_STR_PARAM(wei448_r_square);

static const u8 wei448_mpinv[] = {
	0x01, 
};

TO_EC_STR_PARAM(wei448_mpinv);

static const u8 wei448_p_shift[] = {
	0x00, 
};

TO_EC_STR_PARAM(wei448_p_shift);

static const u8 wei448_p_normalized[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
};

TO_EC_STR_PARAM(wei448_p_normalized);

static const u8 wei448_p_reciprocal[] = {
	0x00, 
};

TO_EC_STR_PARAM(wei448_p_reciprocal);

#elif (WORD_BYTES == 4)   /* 32-bit words */
static const u8 wei448_r[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x01, 
};

TO_EC_STR_PARAM(wei448_r);

static const u8 wei448_r_square[] = {
	0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x02, 
};

TO_EC_STR_PARAM(wei448_r_square);

static const u8 wei448_mpinv[] = {
	0x01, 
};

TO_EC_STR_PARAM(wei448_mpinv);

static const u8 wei448_p_shift[] = {
	0x00, 
};

TO_EC_STR_PARAM(wei448_p_shift);

static const u8 wei448_p_normalized[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
};

TO_EC_STR_PARAM(wei448_p_normalized);

static const u8 wei448_p_reciprocal[] = {
	0x00, 
};

TO_EC_STR_PARAM(wei448_p_reciprocal);

#elif (WORD_BYTES == 2)   /* 16-bit words */
static const u8 wei448_r[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x01, 
};

TO_EC_STR_PARAM(wei448_r);

static const u8 wei448_r_square[] = {
	0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x02, 
};

TO_EC_STR_PARAM(wei448_r_square);

static const u8 wei448_mpinv[] = {
	0x01, 
};

TO_EC_STR_PARAM(wei448_mpinv);

static const u8 wei448_p_shift[] = {
	0x00, 
};

TO_EC_STR_PARAM(wei448_p_shift);

static const u8 wei448_p_normalized[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
};

TO_EC_STR_PARAM(wei448_p_normalized);

static const u8 wei448_p_reciprocal[] = {
	0x00, 
};

TO_EC_STR_PARAM(wei448_p_reciprocal);

#else                     /* unknown word size */
#error "Unsupported word size"
#endif

static const u8 wei448_a[] = {
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 
	0xaa, 0xaa, 0xaa, 0xa9, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xfe, 0x1a, 0x76, 0xd4, 0x1f, 
};

TO_EC_STR_PARAM(wei448_a);

static const u8 wei448_b[] = {
	0x5e, 0xd0, 0x97, 0xb4, 0x25, 0xed, 0x09, 0x7b, 
	0x42, 0x5e, 0xd0, 0x97, 0xb4, 0x25, 0xed, 0x09, 
	0x7b, 0x42, 0x5e, 0xd0, 0x97, 0xb4, 0x25, 0xed, 
	0x09, 0x7b, 0x42, 0x5e, 0x71, 0xc7, 0x1c, 0x71, 
	0xc7, 0x1c, 0x71, 0xc7, 0x1c, 0x71, 0xc7, 0x1c, 
	0x71, 0xc7, 0x1c, 0x71, 0xc7, 0x1c, 0x71, 0xc7, 
	0x1c, 0x72, 0xc8, 0x7b, 0x7c, 0xc6, 0x9f, 0x70, 
};

TO_EC_STR_PARAM(wei448_b);

#define CURVE_WEI448_CURVE_ORDER_BITLEN 448
static const u8 wei448_curve_order[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xfd, 0xf3, 0x28, 0x8f, 0xa7, 
	0x11, 0x3b, 0x6d, 0x26, 0xbb, 0x58, 0xda, 0x40, 
	0x85, 0xb3, 0x09, 0xca, 0x37, 0x16, 0x3d, 0x54, 
	0x8d, 0xe3, 0x0a, 0x4a, 0xad, 0x61, 0x13, 0xcc, 
};

TO_EC_STR_PARAM(wei448_curve_order);

static const u8 wei448_gx[] = {
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 
	0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcb, 0x91, 
};

TO_EC_STR_PARAM(wei448_gx);

static const u8 wei448_gy[] = {
	0x7d, 0x23, 0x5d, 0x12, 0x95, 0xf5, 0xb1, 0xf6, 
	0x6c, 0x98, 0xab, 0x6e, 0x58, 0x32, 0x6f, 0xce, 
	0xcb, 0xae, 0x5d, 0x34, 0xf5, 0x55, 0x45, 0xd0, 
	0x60, 0xf7, 0x5d, 0xc2, 0x8d, 0xf3, 0xf6, 0xed, 
	0xb8, 0x02, 0x7e, 0x23, 0x46, 0x43, 0x0d, 0x21, 
	0x13, 0x12, 0xc4, 0xb1, 0x50, 0x67, 0x7a, 0xf7, 
	0x6f, 0xd7, 0x22, 0x3d, 0x45, 0x7b, 0x5b, 0x1a, 
};

TO_EC_STR_PARAM(wei448_gy);

static const u8 wei448_gz[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
};

TO_EC_STR_PARAM(wei448_gz);

static const u8 wei448_gen_order[] = {
	0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0x7c, 0xca, 0x23, 0xe9, 
	0xc4, 0x4e, 0xdb, 0x49, 0xae, 0xd6, 0x36, 0x90, 
	0x21, 0x6c, 0xc2, 0x72, 0x8d, 0xc5, 0x8f, 0x55, 
	0x23, 0x78, 0xc2, 0x92, 0xab, 0x58, 0x44, 0xf3, 
};

TO_EC_STR_PARAM(wei448_gen_order);

#define CURVE_WEI448_Q_BITLEN 446
static const u8 wei448_gen_order_bitlen[] = {
	0x01, 0xbe, 
};

TO_EC_STR_PARAM(wei448_gen_order_bitlen);

static const u8 wei448_cofactor[] = {
	0x04, 
};

TO_EC_STR_PARAM(wei448_cofactor);

static const u8 wei448_alpha_montgomery[] = {
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcb, 0x8c, 
};

TO_EC_STR_PARAM(wei448_alpha_montgomery);

static const u8 wei448_gamma_montgomery[] = {
	0x01, 
};

TO_EC_STR_PARAM(wei448_gamma_montgomery);

static const u8 wei448_alpha_edwards[] = {
	0x45, 0xb2, 0xc5, 0xf7, 0xd6, 0x49, 0xee, 0xd0,
	0x77, 0xed, 0x1a, 0xe4, 0x5f, 0x44, 0xd5, 0x41,
	0x43, 0xe3, 0x4f, 0x71, 0x4b, 0x71, 0xaa, 0x96,
	0xc9, 0x45, 0xaf, 0x01, 0x2d, 0x18, 0x29, 0x75,
	0x07, 0x34, 0xcd, 0xe9, 0xfa, 0xdd, 0xbd, 0xa4,
	0xc0, 0x66, 0xf7, 0xed, 0x54, 0x41, 0x9c, 0xa5,
	0x2c, 0x85, 0xde, 0x1e, 0x8a, 0xae, 0x4e, 0x6c, 
};

TO_EC_STR_PARAM(wei448_alpha_edwards);

static const u8 wei448_name[] = "WEI448";
TO_EC_STR_PARAM(wei448_name);

static const u8 wei448_oid[] = "";
TO_EC_STR_PARAM(wei448_oid);

static const ec_str_params wei448_str_params = {
	.p = &wei448_p_str_param, 
	.p_bitlen = &wei448_p_bitlen_str_param, 
	.r = &wei448_r_str_param, 
	.r_square = &wei448_r_square_str_param, 
	.mpinv = &wei448_mpinv_str_param, 
	.p_shift = &wei448_p_shift_str_param, 
	.p_normalized = &wei448_p_normalized_str_param, 
	.p_reciprocal = &wei448_p_reciprocal_str_param, 
	.a = &wei448_a_str_param, 
	.b = &wei448_b_str_param, 
	.curve_order = &wei448_curve_order_str_param, 
	.gx = &wei448_gx_str_param, 
	.gy = &wei448_gy_str_param, 
	.gz = &wei448_gz_str_param, 
	.gen_order = &wei448_gen_order_str_param, 
	.gen_order_bitlen = &wei448_gen_order_bitlen_str_param, 
	.cofactor = &wei448_cofactor_str_param, 
	.alpha_montgomery = &wei448_alpha_montgomery_str_param, 
	.gamma_montgomery = &wei448_gamma_montgomery_str_param, 
	.alpha_edwards = &wei448_alpha_edwards_str_param, 
	.oid = &wei448_oid_str_param, 
	.name = &wei448_name_str_param, 
};

/*
 * Compute max bit length of all curves for p and q
 */
#ifndef CURVES_MAX_P_BIT_LEN
#define CURVES_MAX_P_BIT_LEN    0
#endif
#if (CURVES_MAX_P_BIT_LEN < CURVE_WEI448_P_BITLEN)
#undef CURVES_MAX_P_BIT_LEN
#define CURVES_MAX_P_BIT_LEN CURVE_WEI448_P_BITLEN
#endif
#ifndef CURVES_MAX_Q_BIT_LEN
#define CURVES_MAX_Q_BIT_LEN    0
#endif
#if (CURVES_MAX_Q_BIT_LEN < CURVE_WEI448_Q_BITLEN)
#undef CURVES_MAX_Q_BIT_LEN
#define CURVES_MAX_Q_BIT_LEN CURVE_WEI448_Q_BITLEN
#endif
#ifndef CURVES_MAX_CURVE_ORDER_BIT_LEN
#define CURVES_MAX_CURVE_ORDER_BIT_LEN    0
#endif
#if (CURVES_MAX_CURVE_ORDER_BIT_LEN < CURVE_WEI448_CURVE_ORDER_BITLEN)
#undef CURVES_MAX_CURVE_ORDER_BIT_LEN
#define CURVES_MAX_CURVE_ORDER_BIT_LEN CURVE_WEI448_CURVE_ORDER_BITLEN
#endif

/*
 * Compute and adapt max name and oid length
 */
#ifndef MAX_CURVE_OID_LEN
#define MAX_CURVE_OID_LEN 0
#endif
#ifndef MAX_CURVE_NAME_LEN
#define MAX_CURVE_NAME_LEN 0
#endif
#if (MAX_CURVE_OID_LEN < 1)
#undef MAX_CURVE_OID_LEN
#define MAX_CURVE_OID_LEN 1
#endif
#if (MAX_CURVE_NAME_LEN < 20)
#undef MAX_CURVE_NAME_LEN
#define MAX_CURVE_NAME_LEN 20
#endif

#endif /* __EC_PARAMS_WEI448_H__ */

#endif /* WITH_CURVE_WEI448 */
