/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_NUMBERS_H
#define LIBGOLLE_NUMBERS_H

#include "platform.h"
#include "errors.h"
#include "bin.h"

/*!
 * \file golle/numbers.h
 * \author Anthony Arnold
 * \copyright MIT License
 * \date 2014
 * \brief Describes various available number functions including
 * primality functions, generator finding, and arithmetic of large numbers.
 */

/*!
 * \defgroup numbers Large Numbers
 * @{
 *
 * This module wraps OpenSSL's `BIGNUM` type. However, it leaves the
 * type opaque, so that these headers do not rely on the OpenSSL
 * headers. If access is required, ::golle_num_t will cast to a `BIGNUM*`.
 *
 * Many functions here are simply wrappers around their OpenSSL analogues.
 * This is done for the same reason that we hide the `BIGNUM` type.
 */


/*!
 * \typedef golle_num_t
 * \brief Wraps `BIGNUM` in an opaque (OK, maybe _translucent_) way.
 */
typedef void * golle_num_t;


/*!
 * \brief Free a number.
 */
GOLLE_EXTERN void golle_num_delete (golle_num_t n);


/*!
 * \brief Generate a pseudo-random `size`-bit prime number.
 * \param bits The number of bits required.
 * \param size If non-zero, the algorithm is required to select a safe prime.
 * \param div If not `NULL`, `div` must divide the prime - 1
 * (i.e. \f$prime \mod div = 1\f$).
 * \return A prime ::golle_num_t, or `NULL` if generation failed.
 */
GOLLE_EXTERN golle_num_t golle_generate_prime (int bits, 
					       int safe, 
					       golle_num_t div);

/*!
 * \brief Test a number for proabable primality.
 * \param p A possible prime.
 * \return ::GOLLE_ERROR if the number is NULL. 
 * ::GOLLE_EMEM if memory allocation fails. ::GOLLE_NOT_PRIME if the
 * number is definitely composite, or ::GOLLE_PROBABLY_PRIME if the number
 * passes the primality test.
 */
GOLLE_EXTERN golle_error golle_test_prime (const golle_num_t p);


#endif
