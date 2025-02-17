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
#include <libecc/curves/ec_edwards.h>

#define EC_EDWARDS_CRV_MAGIC ((word_t)(0x9c7349a1837c6794ULL))

/*
 * Check pointed Edwards curve structure has already been
 * initialized.
 */
int ec_edwards_crv_is_initialized(ec_edwards_crv_src_t crv)
{
	return !!((crv != NULL) && (crv->magic == EC_EDWARDS_CRV_MAGIC));
}

void ec_edwards_crv_check_initialized(ec_edwards_crv_src_t crv)
{
	MUST_HAVE((crv != NULL) && (crv->magic == EC_EDWARDS_CRV_MAGIC));
}

/*
 * Initialize pointed Edwards curve structure using given a and d
 * Fp elements representing curve equation (a x^2 + y^2 = 1 + d x^2 y^2) parameters.
 */
void ec_edwards_crv_init(ec_edwards_crv_t crv, fp_src_t a, fp_src_t d, nn_src_t order)
{
	MUST_HAVE(crv != NULL);

	fp_check_initialized(a);
	fp_check_initialized(d);
	MUST_HAVE(a->ctx == d->ctx);

	/* a and d in Fp, must be distinct and non zero */
	MUST_HAVE(!fp_iszero(a));
	MUST_HAVE(!fp_iszero(d));
	MUST_HAVE(fp_cmp(a, d) != 0);

	nn_check_initialized(order);

	fp_init(&(crv->a), a->ctx);
	fp_init(&(crv->d), d->ctx);

	fp_copy(&(crv->a), a);
	fp_copy(&(crv->d), d);

	nn_copy(&(crv->order), order);

	crv->magic = EC_EDWARDS_CRV_MAGIC;
}


/* Uninitialize curve */
void ec_edwards_crv_uninit(ec_edwards_crv_t crv)
{
        ec_edwards_crv_check_initialized(crv);

	crv->magic = WORD(0);
}
