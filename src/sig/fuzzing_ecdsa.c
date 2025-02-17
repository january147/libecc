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
#if defined(WITH_SIG_ECDSA) && defined(USE_CRYPTOFUZZ)

#include <libecc/nn/nn_rand.h>
#include <libecc/nn/nn_mul.h>
#include <libecc/nn/nn_logical.h>

#include <libecc/sig/sig_algs_internal.h>
#include <libecc/sig/ec_key.h>
#include <libecc/utils/utils.h>
#ifdef VERBOSE_INNER_VALUES
#define EC_SIG_ALG "ECDSA"
#endif
#include <libecc/utils/dbg_sig.h>

/* NOTE: the following versions of ECDSA are "raw" with
 * no hash functions and nonce override. They are DANGEROUS and
 * should NOT be used in production mode! They are however useful
 * for corner cases tests and fuzzing.
 */

#define ECDSA_SIGN_MAGIC ((word_t)(0x80299a2bf630945bULL))
#define ECDSA_SIGN_CHECK_INITIALIZED(A) \
        MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == ECDSA_SIGN_MAGIC))

int ecdsa_sign_raw(struct ec_sign_context *ctx, const u8 *input, u8 inputlen, u8 *sig, u8 siglen, const u8 *nonce, u8 noncelen)
{
	nn k, r, e, tmp, tmp2, s, kinv;
#ifdef USE_SIG_BLINDING
        /* b is the blinding mask */
        nn b;
#endif
	const ec_priv_key *priv_key;
	prj_pt_src_t G;
	/* NOTE: hash here is not really a hash ... */
	u8 hash[BIT_LEN_WORDS(NN_MAX_BIT_LEN) * (WORDSIZE / 8)];
	bitcnt_t rshift, q_bit_len;
	prj_pt kG;
	aff_pt W;
	nn_src_t q, x;
	u8 hsize, q_len;
	int ret;

	/*
	 * First, verify context has been initialized and private
	 * part too. This guarantees the context is an ECDSA
	 * signature one and we do not finalize() before init().
	 */
	SIG_SIGN_CHECK_INITIALIZED(ctx);
	ECDSA_SIGN_CHECK_INITIALIZED(&(ctx->sign_data.ecdsa));

	/* Zero init out poiny */
	local_memset(&kG, 0, sizeof(prj_pt));

	/* Make things more readable */
	priv_key = &(ctx->key_pair->priv_key);
	q = &(priv_key->params->ec_gen_order);
	q_bit_len = priv_key->params->ec_gen_order_bitlen;
	G = &(priv_key->params->ec_gen);
	q_len = (u8)BYTECEIL(q_bit_len);
	x = &(priv_key->x);
	hsize = inputlen;

	dbg_nn_print("p", &(priv_key->params->ec_fp.p));
	dbg_nn_print("q", &(priv_key->params->ec_gen_order));
	dbg_priv_key_print("x", priv_key);
	dbg_ec_point_print("G", &(priv_key->params->ec_gen));
	dbg_pub_key_print("Y", &(ctx->key_pair->pub_key));

	/* Check given signature buffer length has the expected size */
	if (siglen != ECDSA_SIGLEN(q_bit_len)) {
		ret = -1;
		goto err;
	}

	/* 1. Compute h = H(m) */
	/* NOTE: here we have raw ECDSA, this is the raw input */
	if((input == NULL) || (inputlen > sizeof(hash))){
		ret = -1;
		goto err;
	}
	local_memset(hash, 0, sizeof(hash));
	local_memcpy(hash, input, hsize);
	
	dbg_buf_print("h", hash, hsize);

	/*
	 * 2. If |h| > bitlen(q), set h to bitlen(q)
	 *    leftmost bits of h.
	 *
	 * Note that it's easier to check if the truncation has
	 * to be done here but only implement it using a logical
	 * shift at the beginning of step 3. below once the hash
	 * has been converted to an integer.
	 */
	rshift = 0;
	if ((hsize * 8) > q_bit_len) {
		rshift = (hsize * 8) - q_bit_len;
	}

	/*
	 * 3. Compute e = OS2I(h) mod q, i.e. by converting h to an
	 *    integer and reducing it mod q
	 */
	nn_init_from_buf(&tmp2, hash, hsize);
	local_memset(hash, 0, hsize);
	dbg_nn_print("h initial import as nn", &tmp2);
	if (rshift) {
		nn_rshift_fixedlen(&tmp2, &tmp2, rshift);
	}
	dbg_nn_print("h   final import as nn", &tmp2);
	nn_mod(&e, &tmp2, q);
	dbg_nn_print("e", &e);

/*
     NOTE: the restart label is removed in CRYPTOFUZZ mode as
     we trigger MUST_HAVE instead of restarting in this mode.
 restart:
*/
	/* 4. get a random value k in ]0,q[ */
	/* NOTE: copy our input nonce if not NULL */
	if(nonce != NULL){
                if(noncelen > (u8)(BYTECEIL(q_bit_len))){
			ret = -1;
		}
		else{
			nn_init_from_buf(&k, nonce, noncelen);
			ret = 0;
		}
	}
	else{
		ret = ctx->rand(&k, q);
	}
	if (ret) {
		nn_uninit(&tmp2);
		nn_uninit(&e);
		ret = -1;
		goto err;
	}
	dbg_nn_print("k", &k);

#ifdef USE_SIG_BLINDING
	/* Note: if we use blinding, r and e are multiplied by
	 * a random value b in ]0,q[ */
        ret = nn_get_random_mod(&b, q);
        if (ret) {
		nn_uninit(&tmp2);
		nn_uninit(&e);
		ret = -1;
                goto err;
        }
        dbg_nn_print("b", &b);
#endif /* USE_SIG_BLINDING */


	/* 5. Compute W = (W_x,W_y) = kG */
#ifdef USE_SIG_BLINDING
	if(prj_pt_mul_monty_blind(&kG, &k, G)){
		ret = -1;
		goto err;
	}
#else
        prj_pt_mul_monty(&kG, &k, G);
#endif /* USE_SIG_BLINDING */
	prj_pt_to_aff(&W, &kG);
	prj_pt_uninit(&kG);

	dbg_nn_print("W_x", &(W.x.fp_val));
	dbg_nn_print("W_y", &(W.y.fp_val));

	/* 6. Compute r = W_x mod q */
	nn_mod(&r, &(W.x.fp_val), q);
	aff_pt_uninit(&W);
	dbg_nn_print("r", &r);

	/* 7. If r is 0, restart the process at step 4. */
	/* NOTE: for the CRYPTOFUZZ mode, we do not restart
	 * the procedure but throw an assert exception instead.
	 */
	MUST_HAVE(!nn_iszero(&r));

	/* Export r */
	nn_export_to_buf(sig, q_len, &r);

#ifdef USE_SIG_BLINDING
	/* Blind r with b */
	nn_mul_mod(&r, &r, &b, q);

	/* Blind the message e */
	nn_mul_mod(&e, &e, &b, q);
#endif /* USE_SIG_BLINDING */

	/* tmp = xr mod q */
	nn_mul_mod(&tmp, x, &r, q);
	dbg_nn_print("x*r mod q", &tmp);

	/* 8. If e == rx, restart the process at step 4. */
	/* NOTE: for the CRYPTOFUZZ mode, we do not restart
	 * the procedure but throw an assert exception instead.
	 */
	MUST_HAVE(nn_cmp(&e, &tmp));

	/* 9. Compute s = k^-1 * (xr + e) mod q */

	/* tmp2 = (e + xr) mod q */
	nn_mod_add(&tmp2, &tmp, &e, q);
	nn_uninit(&e);
	nn_uninit(&tmp);
	dbg_nn_print("(xr + e) mod q", &tmp2);

#ifdef USE_SIG_BLINDING
	/* In case of blinding, we compute (b*k)^-1, and 
	 * b^-1 will automatically unblind (r*x) in the following
	 */
	nn_mul_mod(&k, &k, &b, q);
#endif
	/* Compute k^-1 mod q */
	nn_modinv(&kinv, &k, q);
	nn_uninit(&k);

	dbg_nn_print("k^-1 mod q", &kinv);

	/* s = k^-1 * tmp2 mod q */
	nn_mul_mod(&s, &tmp2, &kinv, q);
	nn_uninit(&kinv);
	nn_uninit(&tmp2);

	dbg_nn_print("s", &s);

	/* 10. If s is 0, restart the process at step 4. */
	/* NOTE: for the CRYPTOFUZZ mode, we do not restart
	 * the procedure but throw an assert exception instead.
	 */
	MUST_HAVE(!nn_iszero(&s));

	/* 11. return (r,s) */
	nn_export_to_buf(sig + q_len, q_len, &s);

	nn_uninit(&r);
	nn_uninit(&s);

 err:

	/*
	 * We can now clear data part of the context. This will clear
	 * magic and avoid further reuse of the whole context.
	 */
	local_memset(&(ctx->sign_data.ecdsa), 0, sizeof(ecdsa_sign_data));

	/* Clean what remains on the stack */
	PTR_NULLIFY(priv_key);
	PTR_NULLIFY(G);
	PTR_NULLIFY(q);
	PTR_NULLIFY(x);
	VAR_ZEROIFY(q_len);
	VAR_ZEROIFY(q_bit_len);
	VAR_ZEROIFY(rshift);
	VAR_ZEROIFY(hsize);

#ifdef USE_SIG_BLINDING
        if(nn_is_initialized(&b)){
                nn_uninit(&b);
        }
#endif /* USE_SIG_BLINDING */

	return ret;
}

/******************************/
#define ECDSA_VERIFY_MAGIC ((word_t)(0x5155fe73e7fd51beULL))
#define ECDSA_VERIFY_CHECK_INITIALIZED(A) \
        MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == ECDSA_VERIFY_MAGIC))

int ecdsa_verify_raw(struct ec_verify_context *ctx, const u8 *input, u8 inputlen)
{
	prj_pt uG, vY, W_prime;
	nn e, tmp, sinv, u, v, r_prime;
	aff_pt W_prime_aff;
	prj_pt_src_t G, Y;
	/* NOTE: hash here is not really a hash ... */
	u8 hash[BIT_LEN_WORDS(NN_MAX_BIT_LEN) * (WORDSIZE / 8)];
	bitcnt_t rshift, q_bit_len;
	nn_src_t q;
	nn *s, *r;
	u8 hsize;
	int ret;

	/*
	 * First, verify context has been initialized and public
	 * part too. This guarantees the context is an ECDSA
	 * verification one and we do not finalize() before init().
	 */
	SIG_VERIFY_CHECK_INITIALIZED(ctx);
	ECDSA_VERIFY_CHECK_INITIALIZED(&(ctx->verify_data.ecdsa));

	/* Zero init points */
	local_memset(&uG, 0, sizeof(prj_pt));
	local_memset(&vY, 0, sizeof(prj_pt));

	/* Make things more readable */
	G = &(ctx->pub_key->params->ec_gen);
	Y = &(ctx->pub_key->y);
	q = &(ctx->pub_key->params->ec_gen_order);
	q_bit_len = ctx->pub_key->params->ec_gen_order_bitlen;
	hsize = inputlen;
	r = &(ctx->verify_data.ecdsa.r);
	s = &(ctx->verify_data.ecdsa.s);

	/* 2. Compute h = H(m) */
	/* NOTE: here we have raw ECDSA, this is the raw input */
	if((input == NULL) || (inputlen > sizeof(hash))){
		ret = -1;
		goto err;
	}
	local_memset(hash, 0, sizeof(hash));
	local_memcpy(hash, input, hsize);
	
	dbg_buf_print("h = H(m)", hash, hsize);

	/*
	 * 3. If |h| > bitlen(q), set h to bitlen(q)
	 *    leftmost bits of h.
	 *
	 * Note that it's easier to check here if the truncation
	 * needs to be done but implement it using a logical
	 * shift at the beginning of step 3. below once the hash
	 * has been converted to an integer.
	 */
	rshift = 0;
	if ((hsize * 8) > q_bit_len) {
		rshift = (hsize * 8) - q_bit_len;
	}

	/*
	 * 4. Compute e = OS2I(h) mod q, by converting h to an integer
	 * and reducing it mod q
	 */
	nn_init_from_buf(&tmp, hash, hsize);
	local_memset(hash, 0, hsize);
	dbg_nn_print("h initial import as nn", &tmp);
	if (rshift) {
		nn_rshift_fixedlen(&tmp, &tmp, rshift);
	}
	dbg_nn_print("h   final import as nn", &tmp);

	nn_mod(&e, &tmp, q);
	nn_uninit(&tmp);
	dbg_nn_print("e", &e);

	/* Compute s^-1 mod q */
	nn_modinv(&sinv, s, q);
	dbg_nn_print("s", s);
	dbg_nn_print("sinv", &sinv);
	nn_uninit(s);

	/* 5. Compute u = (s^-1)e mod q */
	nn_mul(&tmp, &e, &sinv);
	nn_uninit(&e);
	nn_mod(&u, &tmp, q);
	dbg_nn_print("u = (s^-1)e mod q", &u);

	/* 6. Compute v = (s^-1)r mod q */
	nn_mul_mod(&v, r, &sinv, q);
	dbg_nn_print("v = (s^-1)r mod q", &v);
	nn_uninit(&sinv);
	nn_uninit(&tmp);

	/* 7. Compute W' = uG + vY */
	prj_pt_mul_monty(&uG, &u, G);
	prj_pt_mul_monty(&vY, &v, Y);
	prj_pt_add_monty(&W_prime, &uG, &vY);
	prj_pt_uninit(&uG);
	prj_pt_uninit(&vY);
	nn_uninit(&u);
	nn_uninit(&v);

	/* 8. If W' is the point at infinity, reject the signature. */
	if (prj_pt_iszero(&W_prime)) {
		ret = -1;
		goto err;
	}

	/* 9. Compute r' = W'_x mod q */
	prj_pt_to_aff(&W_prime_aff, &W_prime);
	dbg_nn_print("W'_x", &(W_prime_aff.x.fp_val));
	dbg_nn_print("W'_y", &(W_prime_aff.y.fp_val));
	nn_mod(&r_prime, &(W_prime_aff.x.fp_val), q);
	prj_pt_uninit(&W_prime);
	aff_pt_uninit(&W_prime_aff);

	/* 10. Accept the signature if and only if r equals r' */
	ret = (nn_cmp(&r_prime, r) != 0) ? -1 : 0;
	nn_uninit(&r_prime);

 err:
	/*
	 * We can now clear data part of the context. This will clear
	 * magic and avoid further reuse of the whole context.
	 */
	local_memset(&(ctx->verify_data.ecdsa), 0, sizeof(ecdsa_verify_data));

	/* Clean what remains on the stack */
	PTR_NULLIFY(G);
	PTR_NULLIFY(Y);
	VAR_ZEROIFY(rshift);
	VAR_ZEROIFY(q_bit_len);
	PTR_NULLIFY(q);
	PTR_NULLIFY(s);
	PTR_NULLIFY(r);
	VAR_ZEROIFY(hsize);

	return ret;
}


#else /* WITH_SIG_ECDSA && USE_CRYPTOFUZZ */

/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif /* WITH_SIG_ECDSA */
