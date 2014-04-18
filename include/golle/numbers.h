/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_NUMBERS_H
#define LIBGOLLE_NUMBERS_H

#include "platform.h"
#include "errors.h"
#include "bin.h"
#include <stdio.h>

GOLLE_BEGIN_C

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
 * \brief Create a new number.
 * \return A newly-allocated number, or `NULL` if failed.
 */
GOLLE_EXTERN golle_num_t golle_num_new (void);

/*!
 * \brief Free a number.
 */
GOLLE_EXTERN void golle_num_delete (golle_num_t n);

/*!
 * \brief Create a new number from a given native integer.
 * \param The value to set the newly allocated number.
 * \return A newly-allocated number, or `NULL` if failed.
 */
GOLLE_EXTERN golle_num_t golle_num_new_int (size_t i);

/*!
 * \brief Compare two numbers.
 * \param n1 The first number (left-hand side).
 * \param n2 The second number (right-hand side).
 * \return `-1` if `n1 < n2`. `1` if `n1 > n2`. `0` if `n1 == n2`.
 * \warning No parameter checking is done. If `n1` or `n2` is
 * `NULL`, behaviour is undefined.
 */
GOLLE_EXTERN int golle_num_cmp (const golle_num_t n1, const golle_num_t n2);

/*!
 * \brief Generate a pseudo-random `size`-bit prime number.
 * \param bits The number of bits required.
 * \param safe If non-zero, the algorithm is required to select a safe prime.
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

/*!
 * \brief Find a generator for the multiplicative subgroup of 
 * \f$\mathbb{Z}^{*}_{p}\f$ of order \f$q\f$ (\f$\mathbb{G}_{q}\f$).
 * \param g If not `NULL`, will be populated with the found generator.
 * \param p A large prime.
 * \param q Another prime with divides `p`.
 * \param n The number of attempts before failing with ::GOLLE_ENOTFOUND.
 * \return ::GOLLE_OK if a generator was found. ::GOLLE_ERROR if `p`
 * or `g` is `NULL`. ::GOLLE_EMEM if memory failed to allocate.
 * ::GOLLE_ECRYPTO if the crypto library fails. ::GOLLE_ENOTFOUND if a generator
 * could not be found in n attempts.
 * \warning This function assumes that `p` and `q` are valid primes, and that
 * `q` divides `p`.
 * \note A generator is calculated by taking a random number
 *  \f$h \in \mathbb{Z}^{*}_{p}\f$ and computing \f$g = h^{(p-1)/q} \mod p\f$.
 * If \f$g \neq 1\f$ then \f$g\f$ is a generator.
 * This technique is described in H. Delfs and H. Knebl, *Introduction to
 * Cryptography: Principles and Applications*, 2007, pp. 303-304.
 */
GOLLE_EXTERN golle_error golle_find_generator (golle_num_t g,
					       const golle_num_t p,
					       const golle_num_t q,
					       int n);


/*!
 * \brief Write the big-endian binary representation of a number into the given
 * binary buffer. The buffer will be resized to the number of bytes required.
 * \param n The number to write out.
 * \param bin The buffer that will be filled with the number.
 * \return ::GOLLE_OK on success. ::GOLLE_ERROR if any parameter is `NULL`.
 * ::GOLLE_EMEM if memory for the buffer couldn't be allocated.
 */
GOLLE_EXTERN golle_error golle_num_to_bin (const golle_num_t n, 
					   golle_bin_t *bin);

/*!
 * \brief Convert a big-endian binary buffer into a number.
 * \param bin The binary buffer.
 * \param n The number to populate.
 * \return ::GOLLE_OK on success. ::GOLLE_ERROR if any parameter is `NULL`.
 * ::GOLLE_EMEM if memory for the number couldn't be allocated.
 */
GOLLE_EXTERN golle_error golle_bin_to_num (const golle_bin_t *bin, 
					   golle_num_t n);

/*!
 * \brief Calculate \f$m = g^n \mod q\f$
 * \param out \f$m\f$
 * \param base \f$g\f$
 * \param exp \f$n\f$
 * \param mod \f$q\f$
 * \return ::GOLLE_ERROR if any argument is `NULL`.
 * ::GOLLE_ECRYPTO if the operation fails.
 * ::GOLLE_EMEM if resources run out.
 * ::GOLLE_OK if successful.
 */
GOLLE_EXTERN golle_error golle_num_mod_exp (golle_num_t out, 
					    const golle_num_t base, 
					    const golle_num_t exp, 
					    const golle_num_t mod);

/*!
 * \brief Print a number, in big-endian hexadecimal, to the given file pointer.
 * \param file The file pointer to print to.
 * \param num The number to print.
 * \return ::GOLLE_ERROR if either argument is `NULL`.
 * ::GOLLE_EMEM if the buffer allocation failed. ::GOLLE_OK otherwise.
 */
GOLLE_EXTERN golle_error golle_num_print (FILE *file, const golle_num_t num);

GOLLE_END_C

#endif
