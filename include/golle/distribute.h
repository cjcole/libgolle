/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_DISTRIBUTE_H
#define LIBGOLLE_DISTRIBUTE_H

#include "platform.h"
#include "errors.h"
#include "numbers.h"

GOLLE_BEGIN_C

/*!
 * \file golle/distribute.h
 * \author Anthony Arnold
 * \copyright MIT License
 * \date 2014
 * \brief Defines the protocol for generating a distributed public/private
 * key pair.
 */

/*!
 * \defgroup distribute Key Generation and Distribution
 * @{
 *
 * The key distribution protocol is an implementation of
 * Torben Pedersen's Threshold Cryptosystem without a Trusted Party.
 * D.W. Davies (Ed.): Advances in Cryptology - EUROCRYPT'91. LNCS 547, pp. 
 * 522-526, 1991.
 *
 * First, all peers must agree on primes \f$p\f$ and \f$q\f$, and a generator 
 * \f$g\f$ of \f$G_{q}\f$.
 *
 * A peer \f$P_{i}\f$ selects a random private key 
 * \f$x_{i} \in \mathbb{Z}_{q}\f$ 
 * and calculates \f$h_{i} = g^{x_{i}}\f$. 
 * \f$P_{i}\f$ then publishes a non-malleable commitment
 * to \f$h_{i}\f$ (see @ref commit).
 *
 * Once each other peer has received the commitment, \f$P_{i}\f$ 
 * then reveals \f$h_{i}\f$ and the commitment is verified.
 *
 * For each peer \f$P_{i}\f$, the public key \f$h = \prod_{i} h_{i}\f$. 
 *
 */


/*!
 * \struct golle_key_t
 * \brief A peer's key. Contains the peer's portion of the private key
 * and the public key elements.
 */
typedef struct golle_key_t {
  golle_num_t p; /*!< A 1024-bit prime st. \f$\alpha q + 1 = p\f$. */
  golle_num_t q; /*!< The value \f$q = (p - 1) / 2\f$. */
  golle_num_t g; /*!< A generator for \f$\mathbb{G}_{q}\f$ */
  golle_num_t x; /*!< A value \f$x \in \mathbb{Z}_{q}\f$.
		  \warning This is the private key. */
  golle_num_t h; /*!< The value \f$g^{x}\f$. Computed when \f$x\f$ is
		   generated. */
  golle_num_t h_product; /*!< The computed \f$\prod_{i} h_{i}\f$
			   from successive calls to ::golle_key_accum_h. */
} golle_key_t;

/*!
 * \brief Frees each member of the ::golle_key_t k.
 * \param k The key to free.
 */
GOLLE_INLINE void golle_key_cleanup (golle_key_t *k) {
  if (k) {
    golle_num_delete (k->p); k->p = NULL;
    golle_num_delete (k->q); k->q = NULL;
    golle_num_delete (k->g); k->g = NULL;
    golle_num_delete (k->x); k->x = NULL;
    golle_num_delete (k->h); k->h = NULL;
    golle_num_delete (k->h_product); k->h_product = NULL;
  }
}

/*!
 * \brief An alias for golle_key_cleanup()
 */
#define golle_key_clear(k) golle_key_cleanup(k)


/*!
 * \brief Generate a full public key description.
 * This should usually be done once, and be distributed
 * amongst each peer for verification.
 * \param key The key to generate public values for.
 * \param bits The number of bits in the key. If <= 0, defaults to 1024.
 * \param n The number of attempts to try to find a generator before failing.
 * \return ::GOLLE_OK if successful, ::GOLLE_EMEM if
 * any memory failed to be allocated. ::GOLLE_ERROR
 * if key is `NULL`. ::GOLLE_ECRYPTO if something
 * went wrong in the cryptography library. ::GOLLE_ENOTFOUND if a generator
 * couldn't be found within `n` attempts.
 *
 * \warning This function contains an implicit call to ::golle_key_cleanup.
 * \warning Finding a large safe prime `and` a generator can be slow.
 */
GOLLE_EXTERN golle_error golle_key_gen_public (golle_key_t *key, 
					       int bits, 
					       int n);

/*!
 * \brief Set the public key description.
 * \param key The key to set public values for.
 * \param p The value for \f$p\f$
 * \param g The value for \f$g\f$
 * \return ::GOLLE_OK if all values are valid. ::GOLLE_ERROR if any
 * parameter is `NULL`. ::GOLLE_EMEM if a value couldn't be allocated.
 * ::GOLLE_ENOTPRIME if either \f$p\f$ or \f$q\f$ fail the test for primality.
 * ::GOLLE_ECRYPTO if an error occurred during cryptography.
 * Cryptography failures include \f$q \nmid (p - 1)\f$, and
 * \f$g\f$ is not a generator of \f$\mathbb{G}_{q}\f$.
 * \warning This function contains an implicit call to ::golle_key_cleanup.
 */
GOLLE_EXTERN golle_error golle_key_set_public (golle_key_t *key,
					       const golle_num_t p,
					       const golle_num_t g);



/*!
 * \brief Generate a private key \f$x \in \mathbb{Z}_{q}\f$ and calculate
 * \f$h = g^{x}\f$. The `h` and `h_product` members will be set.
 * \param key The key to generate an \f$x\f$ for.
 * \return ::GOLLE_OK if successful. ::GOLLE_EMEM if
 * a value couldn't be allocated. ::GOLLE_ERROR if key, or 
 * any public key member is `NULL`.
 *
 * \warning This function will overwrite any existing private key value.
 * \warning This function assumes that the public key values are valid.
 * Always check the return values of ::golle_key_gen_public and
 * ::golle_key_set_public.
 * \note The `h_product` member is set to the value of `h`, but it
 * is not ready to be used until the `h` of each other peer is received
 * and included in the product using ::golle_key_accum_h.
 */
GOLLE_EXTERN golle_error golle_key_gen_private (golle_key_t *key);

/*!
 * \brief Calculate the product of all \f$h_{i}\f$ in order to get
 * \f$h = \prod_{i} h_{i}\f$. Call this function successively
 * for _each_ \f$h_{i}\f$, __not__ including the `h` member of the local
 * key.
 * \param key The key to multiple the `h_product` for.
 * \param h The \f$h\f$ value to multiply by the `h_product` of the `key`.
 * \return ::GOLLE_OK upon success. ::GOLLE_ERROR if any value is `NULL`.
 * ::GOLLE_EMEM if memory couldn't be allocated.
 */
GOLLE_EXTERN golle_error golle_key_accum_h (golle_key_t *key,
					    const golle_num_t h);

/*!
 * @}
 */

GOLLE_END_C

#endif
