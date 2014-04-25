/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_SCHNORR_H
#define LIBGOLLE_SCHNORR_H

#include "platform.h"
#include "numbers.h"
#include "errors.h"
#include "distribute.h"

GOLLE_BEGIN_C

/*!
 * \file golle/schnorr.h
 * \author Anthony Arnold
 * \copyright MIT License
 * \date 2014
 * \brief Schnorr Identification
 */
/*!
 * \defgroup schnorr Schnorr Identification Algorithm
 * @{
 * Given a cyclic group \f$\mathbb{G}_{q}\f$ of order
 * \f$q\f$ with generator \f$g\f$ (e.g. from an El Gamal
 * public key), and plaintext \f$x = log_{g}y\f$,
 * the prover picks \f$t = g^{r}\f$ for some
 * random \f$r \in \mathbb{Z}_{q}\f$ and send \f$t\f$ as
 * a commitment. The verifier sends a challenge \f$c \in \mathbb{Z}_{q}\f$,
 * and the prover then responds with \f$s = cx + r\f$. The verifier must
 * then verify that \f$g^{s} = ty^{c}\f$.
 */
/*!
 * \struct golle_schnorr_t
 * \brief A key used for the Schnorr Identification Algorithm
 */
typedef struct golle_schnorr_t {
  golle_num_t G; /*!< The value G, in the algorithm. */
  golle_num_t Y; /*!< The value Y, in the algorithm. */
  golle_num_t x; /*!< The private key. */
  golle_num_t q; /*!< The q value, of the cyclic group. */
} golle_schnorr_t;

/*!
 * \brief Clear all number values in a Schnorr key.
 * \param key The key to clear.
 */
GOLLE_INLINE void golle_schnorr_clear (golle_schnorr_t *key) {
  if (key) {
    golle_num_delete (key->G); key->G = NULL;
    golle_num_delete (key->Y); key->Y = NULL;
    golle_num_delete (key->q); key->q = NULL;
    golle_num_delete (key->x); key->x = NULL;
  }
}

/*!
 * \brief For an ElGamal public key, generate a random
 * \f$r\f$ and calculate \f$t\f$
 * \param key A key containing g and q.
 * \param[out] r \f$r\f$
 * \param[out] t \f$t\f$
 * \return ::GOLLE_OK, ::GOLLE_ERROR for `NULL`, or ::GOLLE_EMEM.
 */
GOLLE_EXTERN golle_error golle_schnorr_commit (const golle_schnorr_t *key,
					       golle_num_t r,
					       golle_num_t t);
/*!
 * \brief Calculate \f$s = r + cx \f$
 * \param key A key containing q, and private key x.
 * \param[out] s \f$s\f$
 * \param r \f$r\f$
 * \param c \f$c\f$
 * \return ::GOLLE_OK, ::GOLLE_ERROR for `NULL`, or ::GOLLE_EMEM.
 */
GOLLE_EXTERN golle_error golle_schnorr_prove (const golle_schnorr_t *key,
					      golle_num_t s,
					      const golle_num_t r,
					      const golle_num_t c);
/*!
 * \brief Verify \$fg^{s} = ty^{c}\f$
 * \param key A key containing g, h, and q.
 * \param s \f$s\f$
 * \param t \f$t\f$
 * \param y \f$t\f$
 * \param c \f$c\f$
 * \return ::GOLLE_OK, ::GOLLE_ERROR for `NULL`, or ::GOLLE_EMEM.
 * If the verification fails, returns ::GOLLE_ECRYPTO.
 */
GOLLE_EXTERN golle_error golle_schnorr_verify (const golle_schnorr_t *key,
					       const golle_num_t s,
					       const golle_num_t t,
					       const golle_num_t c);
/*!
 * @}
 */

GOLLE_END_C

#endif
