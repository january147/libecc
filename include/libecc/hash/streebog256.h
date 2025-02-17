/*
 *  Copyright (C) 2021 - This file is part of libecc project
 *
 *  Authors:
 *      Ryad BENADJILA <ryadbenadjila@gmail.com>
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */
#include <libecc/lib_ecc_config.h>
#ifdef WITH_HASH_STREEBOG256

#ifndef __STREEBOG256_H__
#define __STREEBOG256_H__

#include "../words/words.h"
#include "../utils/utils.h"
#include "streebog.h"

#define STREEBOG256_BLOCK_SIZE   STREEBOG_BLOCK_SIZE
#define STREEBOG256_DIGEST_SIZE  32

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE	0
#endif
#if (MAX_DIGEST_SIZE < STREEBOG256_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE STREEBOG256_DIGEST_SIZE
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE  0
#endif
#if (MAX_BLOCK_SIZE < STREEBOG256_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE STREEBOG256_BLOCK_SIZE
#endif

#define STREEBOG256_HASH_MAGIC ((word_t)(0x11221a2122328332ULL))
#define STREEBOG256_HASH_CHECK_INITIALIZED(A) \
	MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == STREEBOG256_HASH_MAGIC))

typedef streebog_context streebog256_context;

void streebog256_init(streebog256_context *ctx);
void streebog256_update(streebog256_context *ctx, const u8 *input, u32 ilen);
void streebog256_final(streebog256_context *ctx, u8 output[STREEBOG256_DIGEST_SIZE]);
void streebog256_scattered(const u8 **inputs, const u32 *ilens,
			   u8 output[STREEBOG256_DIGEST_SIZE]);
void streebog256(const u8 *input, u32 ilen, u8 output[STREEBOG256_DIGEST_SIZE]);

#endif /* __STREEBOG256_H__ */
#endif /* WITH_HASH_STREEBOG256 */
