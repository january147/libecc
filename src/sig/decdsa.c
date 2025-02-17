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
#ifdef WITH_SIG_DECDSA

#if !defined(WITH_HMAC)
#error "DECDSA signature needs HMAC, please activate it!"
#endif
#include <libecc/hash/hmac.h>

#include <libecc/nn/nn_rand.h>
#include <libecc/nn/nn_mul.h>
#include <libecc/nn/nn_logical.h>

#include <libecc/sig/sig_algs_internal.h>
#include <libecc/sig/ec_key.h>
#include <libecc/utils/utils.h>
#ifdef VERBOSE_INNER_VALUES
#define EC_SIG_ALG "DECDSA"
#endif
#include <libecc/utils/dbg_sig.h>

int decdsa_init_pub_key(ec_pub_key *out_pub, const ec_priv_key *in_priv)
{
	return __ecdsa_init_pub_key(out_pub, in_priv, DECDSA);
}

u8 decdsa_siglen(u16 p_bit_len, u16 q_bit_len, u8 hsize, u8 blocksize)
{
	return __ecdsa_siglen(p_bit_len, q_bit_len, hsize, blocksize);
}

int _decdsa_sign_init(struct ec_sign_context *ctx)
{
	/* Override our random source with NULL since we want a deterministic
	 * generation.
	 */
	MUST_HAVE(ctx != NULL);
	ctx->rand = NULL;
	return __ecdsa_sign_init(ctx, DECDSA);
}

int _decdsa_sign_update(struct ec_sign_context *ctx,
		       const u8 *chunk, u32 chunklen)
{
	MUST_HAVE((ctx != NULL) && (ctx->rand == NULL));

	return __ecdsa_sign_update(ctx, chunk, chunklen, DECDSA);
}

int _decdsa_sign_finalize(struct ec_sign_context *ctx, u8 *sig, u8 siglen)
{
	MUST_HAVE((ctx != NULL) && (ctx->rand == NULL));

	return __ecdsa_sign_finalize(ctx, sig, siglen, DECDSA);
}

int _decdsa_verify_init(struct ec_verify_context *ctx, const u8 *sig, u8 siglen)
{
	return __ecdsa_verify_init(ctx, sig, siglen, DECDSA);
}

int _decdsa_verify_update(struct ec_verify_context *ctx,
			 const u8 *chunk, u32 chunklen)
{
	return __ecdsa_verify_update(ctx, chunk, chunklen, DECDSA);
}

int _decdsa_verify_finalize(struct ec_verify_context *ctx)
{
	return __ecdsa_verify_finalize(ctx, DECDSA);
}

#else /* WITH_SIG_DECDSA */

/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif /* WITH_SIG_DECDSA */
