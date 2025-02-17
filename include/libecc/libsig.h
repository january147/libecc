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
#ifndef __LIBSIG_H__
#define __LIBSIG_H__

/* Include the Elliptic Curves layer */
#include "libec.h"
/* Include configuration as well as types */
#include <libecc/lib_ecc_config.h>
#include <libecc/lib_ecc_types.h>
/* Include the signature algorithms and their
 * keys primitives
 */
#include "sig/sig_algs.h"
#include "sig/ec_key.h"
#include "utils/dbg_sig.h"	/* debug */
/* Include the hash functions */
#include "hash/hash_algs.h"

#endif /* __LIBSIG_H__ */
