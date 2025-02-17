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
#ifdef WITH_CURVE_SM2P256TEST

#ifndef __EC_PARAMS_SM2P256TEST_H__
#define __EC_PARAMS_SM2P256TEST_H__
#include "../known/ec_params_external.h"

static const u8 sm2p256test_p[] = {
	0x85, 0x42, 0xd6, 0x9e, 0x4c, 0x04, 0x4f, 0x18,
	0xe8, 0xb9, 0x24, 0x35, 0xbf, 0x6f, 0xf7, 0xde,
	0x45, 0x72, 0x83, 0x91, 0x5c, 0x45, 0x51, 0x7d,
	0x72, 0x2e, 0xdb, 0x8b, 0x08, 0xf1, 0xdf, 0xc3,
};

TO_EC_STR_PARAM(sm2p256test_p);

#define CURVE_SM2P256TEST_P_BITLEN 256
static const u8 sm2p256test_p_bitlen[] = {
	0x01, 0x00,
};

TO_EC_STR_PARAM(sm2p256test_p_bitlen);

#if (WORD_BYTES == 8)     /* 64-bit words */
static const u8 sm2p256test_r[] = {
	0x7a, 0xbd, 0x29, 0x61, 0xb3, 0xfb, 0xb0, 0xe7,
	0x17, 0x46, 0xdb, 0xca, 0x40, 0x90, 0x08, 0x21,
	0xba, 0x8d, 0x7c, 0x6e, 0xa3, 0xba, 0xae, 0x82,
	0x8d, 0xd1, 0x24, 0x74, 0xf7, 0x0e, 0x20, 0x3d,
};

TO_EC_STR_PARAM(sm2p256test_r);

static const u8 sm2p256test_r_square[] = {
	0x0a, 0xe5, 0x52, 0x29, 0x28, 0x3c, 0xd9, 0x6a,
	0xee, 0x4d, 0x87, 0xda, 0x90, 0xd8, 0xc6, 0x6c,
	0xeb, 0x37, 0x2d, 0xa8, 0x3f, 0xc9, 0xc6, 0x36,
	0x3d, 0x57, 0x9c, 0x46, 0xf6, 0xde, 0x18, 0xf2,
};

TO_EC_STR_PARAM(sm2p256test_r_square);

static const u8 sm2p256test_mpinv[] = {
	0xa2, 0xa0, 0x38, 0x0c, 0x50, 0xf7, 0x77, 0x15,
};

TO_EC_STR_PARAM(sm2p256test_mpinv);

static const u8 sm2p256test_p_shift[] = {
	0x00,
};

TO_EC_STR_PARAM(sm2p256test_p_shift);

static const u8 sm2p256test_p_normalized[] = {
	0x85, 0x42, 0xd6, 0x9e, 0x4c, 0x04, 0x4f, 0x18,
	0xe8, 0xb9, 0x24, 0x35, 0xbf, 0x6f, 0xf7, 0xde,
	0x45, 0x72, 0x83, 0x91, 0x5c, 0x45, 0x51, 0x7d,
	0x72, 0x2e, 0xdb, 0x8b, 0x08, 0xf1, 0xdf, 0xc3,
};

TO_EC_STR_PARAM(sm2p256test_p_normalized);

static const u8 sm2p256test_p_reciprocal[] = {
	0xeb, 0xc9, 0x56, 0x3c, 0x60, 0x57, 0x6b, 0xb9,
};

TO_EC_STR_PARAM(sm2p256test_p_reciprocal);

#elif (WORD_BYTES == 4)   /* 32-bit words */
static const u8 sm2p256test_r[] = {
	0x7a, 0xbd, 0x29, 0x61, 0xb3, 0xfb, 0xb0, 0xe7,
	0x17, 0x46, 0xdb, 0xca, 0x40, 0x90, 0x08, 0x21,
	0xba, 0x8d, 0x7c, 0x6e, 0xa3, 0xba, 0xae, 0x82,
	0x8d, 0xd1, 0x24, 0x74, 0xf7, 0x0e, 0x20, 0x3d,
};

TO_EC_STR_PARAM(sm2p256test_r);

static const u8 sm2p256test_r_square[] = {
	0x0a, 0xe5, 0x52, 0x29, 0x28, 0x3c, 0xd9, 0x6a,
	0xee, 0x4d, 0x87, 0xda, 0x90, 0xd8, 0xc6, 0x6c,
	0xeb, 0x37, 0x2d, 0xa8, 0x3f, 0xc9, 0xc6, 0x36,
	0x3d, 0x57, 0x9c, 0x46, 0xf6, 0xde, 0x18, 0xf2,
};

TO_EC_STR_PARAM(sm2p256test_r_square);

static const u8 sm2p256test_mpinv[] = {
	0x50, 0xf7, 0x77, 0x15,
};

TO_EC_STR_PARAM(sm2p256test_mpinv);

static const u8 sm2p256test_p_shift[] = {
	0x00,
};

TO_EC_STR_PARAM(sm2p256test_p_shift);

static const u8 sm2p256test_p_normalized[] = {
	0x85, 0x42, 0xd6, 0x9e, 0x4c, 0x04, 0x4f, 0x18,
	0xe8, 0xb9, 0x24, 0x35, 0xbf, 0x6f, 0xf7, 0xde,
	0x45, 0x72, 0x83, 0x91, 0x5c, 0x45, 0x51, 0x7d,
	0x72, 0x2e, 0xdb, 0x8b, 0x08, 0xf1, 0xdf, 0xc3,
};

TO_EC_STR_PARAM(sm2p256test_p_normalized);

static const u8 sm2p256test_p_reciprocal[] = {
	0xeb, 0xc9, 0x56, 0x3c,
};

TO_EC_STR_PARAM(sm2p256test_p_reciprocal);

#elif (WORD_BYTES == 2)   /* 16-bit words */
static const u8 sm2p256test_r[] = {
	0x7a, 0xbd, 0x29, 0x61, 0xb3, 0xfb, 0xb0, 0xe7,
	0x17, 0x46, 0xdb, 0xca, 0x40, 0x90, 0x08, 0x21,
	0xba, 0x8d, 0x7c, 0x6e, 0xa3, 0xba, 0xae, 0x82,
	0x8d, 0xd1, 0x24, 0x74, 0xf7, 0x0e, 0x20, 0x3d,
};

TO_EC_STR_PARAM(sm2p256test_r);

static const u8 sm2p256test_r_square[] = {
	0x0a, 0xe5, 0x52, 0x29, 0x28, 0x3c, 0xd9, 0x6a,
	0xee, 0x4d, 0x87, 0xda, 0x90, 0xd8, 0xc6, 0x6c,
	0xeb, 0x37, 0x2d, 0xa8, 0x3f, 0xc9, 0xc6, 0x36,
	0x3d, 0x57, 0x9c, 0x46, 0xf6, 0xde, 0x18, 0xf2,
};

TO_EC_STR_PARAM(sm2p256test_r_square);

static const u8 sm2p256test_mpinv[] = {
	0x77, 0x15,
};

TO_EC_STR_PARAM(sm2p256test_mpinv);

static const u8 sm2p256test_p_shift[] = {
	0x00,
};

TO_EC_STR_PARAM(sm2p256test_p_shift);

static const u8 sm2p256test_p_normalized[] = {
	0x85, 0x42, 0xd6, 0x9e, 0x4c, 0x04, 0x4f, 0x18,
	0xe8, 0xb9, 0x24, 0x35, 0xbf, 0x6f, 0xf7, 0xde,
	0x45, 0x72, 0x83, 0x91, 0x5c, 0x45, 0x51, 0x7d,
	0x72, 0x2e, 0xdb, 0x8b, 0x08, 0xf1, 0xdf, 0xc3,
};

TO_EC_STR_PARAM(sm2p256test_p_normalized);

static const u8 sm2p256test_p_reciprocal[] = {
	0xeb, 0xc9,
};

TO_EC_STR_PARAM(sm2p256test_p_reciprocal);

#else                     /* unknown word size */
#error "Unsupported word size"
#endif

static const u8 sm2p256test_a[] = {
	0x78, 0x79, 0x68, 0xb4, 0xfa, 0x32, 0xc3, 0xfd,
	0x24, 0x17, 0x84, 0x2e, 0x73, 0xbb, 0xfe, 0xff,
	0x2f, 0x3c, 0x84, 0x8b, 0x68, 0x31, 0xd7, 0xe0,
	0xec, 0x65, 0x22, 0x8b, 0x39, 0x37, 0xe4, 0x98,
};

TO_EC_STR_PARAM(sm2p256test_a);

static const u8 sm2p256test_b[] = {
	0x63, 0xe4, 0xc6, 0xd3, 0xb2, 0x3b, 0x0c, 0x84,
	0x9c, 0xf8, 0x42, 0x41, 0x48, 0x4b, 0xfe, 0x48,
	0xf6, 0x1d, 0x59, 0xa5, 0xb1, 0x6b, 0xa0, 0x6e,
	0x6e, 0x12, 0xd1, 0xda, 0x27, 0xc5, 0x24, 0x9a,
};

TO_EC_STR_PARAM(sm2p256test_b);

#define CURVE_SM2P256TEST_CURVE_ORDER_BITLEN 256
static const u8 sm2p256test_order[] = {
	0x85, 0x42, 0xd6, 0x9e, 0x4c, 0x04, 0x4f, 0x18,
	0xe8, 0xb9, 0x24, 0x35, 0xbf, 0x6f, 0xf7, 0xdd,
	0x29, 0x77, 0x20, 0x63, 0x04, 0x85, 0x62, 0x8d,
	0x5a, 0xe7, 0x4e, 0xe7, 0xc3, 0x2e, 0x79, 0xb7,
};

TO_EC_STR_PARAM(sm2p256test_order);

static const u8 sm2p256test_gx[] = {
	0x42, 0x1d, 0xeb, 0xd6, 0x1b, 0x62, 0xea, 0xb6,
	0x74, 0x64, 0x34, 0xeb, 0xc3, 0xcc, 0x31, 0x5e,
	0x32, 0x22, 0x0b, 0x3b, 0xad, 0xd5, 0x0b, 0xdc,
	0x4c, 0x4e, 0x6c, 0x14, 0x7f, 0xed, 0xd4, 0x3d,
};

TO_EC_STR_PARAM(sm2p256test_gx);

static const u8 sm2p256test_gy[] = {
	0x06, 0x80, 0x51, 0x2b, 0xcb, 0xb4, 0x2c, 0x07,
	0xd4, 0x73, 0x49, 0xd2, 0x15, 0x3b, 0x70, 0xc4,
	0xe5, 0xd7, 0xfd, 0xfc, 0xbf, 0xa3, 0x6e, 0xa1,
	0xa8, 0x58, 0x41, 0xb9, 0xe4, 0x6e, 0x09, 0xa2,
};

TO_EC_STR_PARAM(sm2p256test_gy);

static const u8 sm2p256test_gz[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};

TO_EC_STR_PARAM(sm2p256test_gz);

static const u8 sm2p256test_gen_order[] = {
	0x85, 0x42, 0xd6, 0x9e, 0x4c, 0x04, 0x4f, 0x18,
	0xe8, 0xb9, 0x24, 0x35, 0xbf, 0x6f, 0xf7, 0xdd,
	0x29, 0x77, 0x20, 0x63, 0x04, 0x85, 0x62, 0x8d,
	0x5a, 0xe7, 0x4e, 0xe7, 0xc3, 0x2e, 0x79, 0xb7,
};

TO_EC_STR_PARAM(sm2p256test_gen_order);

#define CURVE_SM2P256TEST_Q_BITLEN 256
static const u8 sm2p256test_gen_order_bitlen[] = {
	0x01, 0x00,
};

TO_EC_STR_PARAM(sm2p256test_gen_order_bitlen);

static const u8 sm2p256test_cofactor[] = {
	0x01,
};

TO_EC_STR_PARAM(sm2p256test_cofactor);


static const u8 sm2p256test_alpha_montgomery[] = {
        0x00,
};

TO_EC_STR_PARAM_FIXED_SIZE(sm2p256test_alpha_montgomery, 0);

static const u8 sm2p256test_gamma_montgomery[] = {
        0x00,
};

TO_EC_STR_PARAM_FIXED_SIZE(sm2p256test_gamma_montgomery, 0);

static const u8 sm2p256test_alpha_edwards[] = {
        0x00,
};

TO_EC_STR_PARAM_FIXED_SIZE(sm2p256test_alpha_edwards, 0);


static const u8 sm2p256test_name[] = "SM2P256TEST";
TO_EC_STR_PARAM(sm2p256test_name);

static const u8 sm2p256test_oid[] = "sm2-iso14888-test-curve";
TO_EC_STR_PARAM(sm2p256test_oid);

static const ec_str_params sm2p256test_str_params = {
	.p = &sm2p256test_p_str_param,
	.p_bitlen = &sm2p256test_p_bitlen_str_param,
	.r = &sm2p256test_r_str_param,
	.r_square = &sm2p256test_r_square_str_param,
	.mpinv = &sm2p256test_mpinv_str_param,
	.p_shift = &sm2p256test_p_shift_str_param,
	.p_normalized = &sm2p256test_p_normalized_str_param,
	.p_reciprocal = &sm2p256test_p_reciprocal_str_param,
	.a = &sm2p256test_a_str_param,
	.b = &sm2p256test_b_str_param,
	.curve_order = &sm2p256test_order_str_param,
	.gx = &sm2p256test_gx_str_param,
	.gy = &sm2p256test_gy_str_param,
	.gz = &sm2p256test_gz_str_param,
	.gen_order = &sm2p256test_gen_order_str_param,
	.gen_order_bitlen = &sm2p256test_gen_order_bitlen_str_param,
	.cofactor = &sm2p256test_cofactor_str_param,
        .alpha_montgomery = &sm2p256test_alpha_montgomery_str_param,
        .gamma_montgomery = &sm2p256test_gamma_montgomery_str_param,
        .alpha_edwards = &sm2p256test_alpha_edwards_str_param,
	.oid = &sm2p256test_oid_str_param,
	.name = &sm2p256test_name_str_param,
};

/*
 * Compute max bit length of all curves for p and q
 */
#ifndef CURVES_MAX_P_BIT_LEN
#define CURVES_MAX_P_BIT_LEN    0
#endif
#if (CURVES_MAX_P_BIT_LEN < CURVE_SM2P256TEST_P_BITLEN)
#undef CURVES_MAX_P_BIT_LEN
#define CURVES_MAX_P_BIT_LEN CURVE_SM2P256TEST_P_BITLEN
#endif
#ifndef CURVES_MAX_Q_BIT_LEN
#define CURVES_MAX_Q_BIT_LEN    0
#endif
#if (CURVES_MAX_Q_BIT_LEN < CURVE_SM2P256TEST_Q_BITLEN)
#undef CURVES_MAX_Q_BIT_LEN
#define CURVES_MAX_Q_BIT_LEN CURVE_SM2P256TEST_Q_BITLEN
#endif
#ifndef CURVES_MAX_CURVE_ORDER_BIT_LEN
#define CURVES_MAX_CURVE_ORDER_BIT_LEN  0
#endif
#if (CURVES_MAX_CURVE_ORDER_BIT_LEN < CURVE_SM2P256TEST_CURVE_ORDER_BITLEN)
#undef CURVES_MAX_CURVE_ORDER_BIT_LEN
#define CURVES_MAX_CURVE_ORDER_BIT_LEN CURVE_SM2P256TEST_CURVE_ORDER_BITLEN
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
#if (MAX_CURVE_OID_LEN < 24)
#undef MAX_CURVE_OID_LEN
#define MAX_CURVE_OID_LEN 24
#endif
#if (MAX_CURVE_NAME_LEN < 24)
#undef MAX_CURVE_NAME_LEN
#define MAX_CURVE_NAME_LEN 24
#endif

#endif /* __EC_PARAMS_SM2P256TEST_H__ */

#endif /* WITH_CURVE_SM2P256TEST */
