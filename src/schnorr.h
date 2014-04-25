/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/schnorr.h>
#include <golle/random.h>
#include <openssl/bn.h>
#include <golle/errors.h>
#include <golle/numbers.h>

/*
 * The implementation of the commit function.
 * Used by other library function that want to avoid
 * creating a second context.
 */
golle_error golle_schnorr_commit_impl (const golle_schnorr_t *key,
				       golle_num_t r,
				       golle_num_t t,
				       BN_CTX *ctx);
