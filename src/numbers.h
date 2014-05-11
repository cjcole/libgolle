/*
 * Copyright (C) Anthony Arnold 2014
 */
#ifndef GOLLE_SRC_NUMBERS_H
#define GOLLE_SRC_NUMBERS_H

#include <golle/numbers.h>
#include <openssl/bn.h>

/* Calculate a/b mod p by inverse */
GOLLE_EXTERN golle_error golle_mod_div (golle_num_t out,
					const golle_num_t a,
					const golle_num_t b,
					const golle_num_t p,
					BN_CTX *ctx);
#endif
