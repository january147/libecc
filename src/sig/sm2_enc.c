/*
 * @Author: January
 * @Date: 2021-12-22 21:16:47
 */

#include <libecc/hash/hash_algs.h>
#include <libecc/sig/sig_algs.h>

typedef struct {
    aff_pt pt;
    uint8_t* data;
    uint8_t* hash;

} sm2_ciphertext_t;

/**
 * sm2_ciphertext ::= 
 *      x       INTEGER
 *      y       INTEGER
 *      data    OCTSTRING
 *      hash    OCTSTRING
 */

#ifdef WITH_SM2_ENC
static int sm2_do_encrypt(hash_alg_type hash_alg, const unsigned char *in,
                          int inlen,  ec_pub_key* pubkey, sm2_ciphertext_t *ciphertext) {
    int ret = SECRYPTO_ERR_INVALID_PARAM;
    mbedtls_ecp_group *ec;

    mbedtls_ecp_point share_point;

    mbedtls_ecp_point *ephem_point;


    mbedtls_mpi k;
    mbedtls_mpi h;
    mbedtls_md_context_t md_ctx;

    mbedtls_mpi *n;

    unsigned char buf[SM2_SIZE * 2 + 1];
    size_t point_buf_len;
    int nbytes;
    size_t i;

    mbedtls_mpi_init(&k);
    mbedtls_mpi_init(&h);
    mbedtls_ecp_point_init(&share_point);
    ec = &(ec_key->grp);
    point_buf_len = sizeof(buf);
    nbytes = ec->nbits / 8;
    ephem_point = &(ciphertext->c1);

    /* check arguments */
    if (!md || !in || !ec_key) {
        LOG_DEBUG_VERBOSE("invalid input argument ");
        goto out;
    }

    if (inlen <= 0 || inlen > SM2_MAX_PLAINTEXT_LENGTH) {
        LOG_DEBUG_VERBOSE("invalid plain text length");
        goto out;
    }

    n = &(ec->N);
    CHECK_RETURN(mbedtls_mpi_lset(&h, ec->h));

    CHECK_RETURN(mbedtls_ecp_mul(ec, &share_point, &h, &(ec_key->Q), NULL, NULL));

    if (mbedtls_ecp_is_zero(&share_point)) {
        ret = SECRYPTO_ERR_INVALID_PARAM;
        LOG_DEBUG_VERBOSE("invalid public key");
        goto out;
    }

    /* rand k in [1, n-1] */
    mbedtls_mpi_init(&k);
    CHECK_RETURN(rng_mpi(&k, n));
    /* compute ephem_point [k]G = (x1, y1) */
    CHECK_RETURN(mbedtls_ecp_mul(ec, ephem_point, &k, &(ec->G), NULL, NULL));
    // ephem_point is the pointer to ciphertext->c1 and since
    // c1 in the ciphertext has been generated, do not modify it any longer.
    ephem_point = NULL;

    /* compute ECDH share_point [k]P_B = (x2, y2) */
    CHECK_RETURN(mbedtls_ecp_mul(ec, &share_point, &k, &(ec_key->Q), NULL, NULL));

    /* compute t = KDF(x2 || y2, klen) */

    CHECK_RETURN(gfp_ec_point_encode(ec, &share_point, POINT_CONVERSION_UNCOMPRESSED, buf, &point_buf_len));


    CHECK_RETURN(x963_kdf(md, buf + 1, point_buf_len - 1, ciphertext->data, inlen));

    /* ciphertext = t xor in */
    for (i = 0; i < inlen; i++) {
        ciphertext->data[i] ^= in[i];
    }
    ciphertext->data_len = inlen;

    /* generate hash = Hash(x2 || M || y2) */

    mbedtls_md_init(&md_ctx);
    CHECK_RETURN(mbedtls_md_setup(&md_ctx, md, 0));
    CHECK_RETURN(mbedtls_md_starts(&md_ctx));

    CHECK_RETURN(mbedtls_md_update(&md_ctx, buf + 1, nbytes));
    CHECK_RETURN(mbedtls_md_update(&md_ctx, in, inlen));
    CHECK_RETURN(mbedtls_md_update(&md_ctx, buf + 1 + nbytes, nbytes));
    CHECK_RETURN(mbedtls_md_finish(&md_ctx, ciphertext->hash));
    mbedtls_md_free(&md_ctx);
    ciphertext->hash_len = mbedtls_md_get_size(md);
    ret = SECRYPTO_OK;
    out:
    mbedtls_mpi_free(&k);
    mbedtls_mpi_free(&h);
    mbedtls_ecp_point_free(&share_point);
    return ret;
}

static int sm2_do_decrypt(const mbedtls_md_info_t *md, sm2_ciphertext_t *ciphertext,
                          unsigned char *out, size_t *outlen, mbedtls_ecp_keypair *ec_key) {
    int ret = SECRYPTO_ERR_INVALID_PARAM;

    int nbytes, i;

    mbedtls_ecp_group *group;
    mbedtls_mpi h;
    mbedtls_md_context_t md_ctx;

    mbedtls_ecp_point point;
    mbedtls_ecp_point tmp_point;
    uint8_t buf[SM2_SIZE * 2 + 1];
    size_t buf_len;
    uint8_t hash[SM2_DIGEST_SIZE];
    size_t hash_len;


    mbedtls_mpi_init(&h);
    mbedtls_ecp_point_init(&tmp_point);
    mbedtls_ecp_point_init(&point);
    buf_len = sizeof(buf);

    /* check arguments */
    if (!md || !ciphertext || !outlen || !ec_key) {
        LOG_DEBUG_VERBOSE("invalid input parameter for sm2 decryption");
        goto out;
    }

    if (*outlen < ciphertext->data_len) {
        LOG_DEBUG_VERBOSE("out buffer too small");
        goto out;
    }

    hash_len = mbedtls_md_get_size(md);
    if (ciphertext->hash_len != hash_len) {
        LOG_DEBUG_VERBOSE("invalid hash size in ciphertext");
        goto out;
    }

    if (ciphertext->data_len > SM2_MAX_PLAINTEXT_LENGTH) {
        LOG_DEBUG_VERBOSE("invalid ciphertext length");
        goto out;
    }

    group = &(ec_key->grp);
    nbytes = group->nbits / 8;

    CHECK_RETURN(mbedtls_mpi_lset(&h, group->h));

    CHECK_RETURN(mbedtls_ecp_check_pubkey(group, &(ciphertext->c1)));

    // check [h]C1 != O
    CHECK_RETURN(mbedtls_ecp_mul(group, &tmp_point, &h, &(ciphertext->c1), NULL, NULL));

    if (mbedtls_ecp_is_zero(&tmp_point)) {
        ret = SECRYPTO_ERR_INVALID_PARAM;
        LOG_DEBUG_VERBOSE("invalid ciphertext, C1 invalid");
        goto out;
    }

    // compute ECDH [d]C1 = (x2, y2)
    CHECK_RETURN(mbedtls_ecp_mul(group, &point, &(ec_key->d), &(ciphertext->c1), NULL, NULL));

    buf_len = sizeof(buf);
    CHECK_RETURN(gfp_ec_point_encode(group, &point, POINT_CONVERSION_UNCOMPRESSED, buf, &buf_len));

    // compute t = KDF(x2 || y2, clen)
    *outlen = ciphertext->data_len;
    CHECK_RETURN(x963_kdf(md, buf + 1, buf_len - 1, out, *outlen));

    /* compute M = C2 xor t */
    for (i = 0; i < ciphertext->data_len; i++) {
        out[i] ^= ciphertext->data[i];
    }

    /* check hash == Hash(x2 || M || y2) */
    /* generate hash = Hash(x2 || M || y2) */

    mbedtls_md_init(&md_ctx);
    CHECK_RETURN(mbedtls_md_setup(&md_ctx, md, 0));
    CHECK_RETURN(mbedtls_md_starts(&md_ctx));

    CHECK_RETURN(mbedtls_md_update(&md_ctx, buf + 1, nbytes));
    CHECK_RETURN(mbedtls_md_update(&md_ctx, out, *outlen));
    CHECK_RETURN(mbedtls_md_update(&md_ctx, buf + 1 + nbytes, nbytes));
    CHECK_RETURN(mbedtls_md_finish(&md_ctx, hash));
    mbedtls_md_free(&md_ctx);

    if (memcmp(hash, ciphertext->hash, hash_len) != 0) {
        LOG_DEBUG_VERBOSE("invalid hash in ciphertext");
        memset(out, 0, *outlen);
        goto out;
    }

    ret = SECRYPTO_OK;
    out:
    mbedtls_ecp_point_free(&point);
    mbedtls_ecp_point_free(&tmp_point);
    mbedtls_mpi_free(&h);
    return ret;
}
#endif