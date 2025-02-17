/*
 *  Copyright (C) 2017 - This file is part of libecc project
 *
 *  Authors:
 *      Ryad BENADJILA <ryadbenadjila@gmail.com>
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *      Jean-Pierre FLORI <jean-pierre.flori@ssi.gouv.fr>
 *
 *  Contributors:
 *      Nicolas VIVET <nicolas.vivet@ssi.gouv.fr>
 *      Karim KHALFALLAH <karim.khalfallah@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */
#include <libecc/lib_ecc_config.h>
#ifdef WITH_HASH_SHA512_224

#ifndef __SHA512_224_H__
#define __SHA512_224_H__

#include "../words/words.h"
#include "../utils/utils.h"
#include "sha2.h"
#include "sha512_core.h"

#define SHA512_224_STATE_SIZE   SHA512_CORE_STATE_SIZE
#define SHA512_224_BLOCK_SIZE   SHA512_CORE_BLOCK_SIZE
#define SHA512_224_DIGEST_SIZE  28

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE 0
#endif
#if (MAX_DIGEST_SIZE < SHA512_224_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE SHA512_224_DIGEST_SIZE
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE	0
#endif
#if (MAX_BLOCK_SIZE < SHA512_224_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE SHA512_224_BLOCK_SIZE
#endif

#define SHA512_224_HASH_MAGIC ((word_t)(0x12345a2b73932916ULL))
#define SHA512_224_HASH_CHECK_INITIALIZED(A) \
        MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == SHA512_224_HASH_MAGIC))

typedef sha512_core_context sha512_224_context;

void sha512_224_init(sha512_224_context *ctx);
void sha512_224_update(sha512_224_context *ctx, const u8 *input, u32 ilen);
void sha512_224_final(sha512_224_context *ctx, u8 output[SHA512_224_DIGEST_SIZE]);
void sha512_224_scattered(const u8 **inputs, const u32 *ilens,
		      u8 output[SHA512_224_DIGEST_SIZE]);
void sha512_224(const u8 *input, u32 ilen, u8 output[SHA512_224_DIGEST_SIZE]);

#endif /* __SHA512_224_H__ */
#endif /* WITH_HASH_SHA512_224 */
