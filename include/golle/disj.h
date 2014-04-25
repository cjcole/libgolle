/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_DISJ_H
#define LIBGOLLE_DISJ_H

#include "platform.h"
#include "schnorr.h"
#include "numbers.h"
#include "types.h"

/*!
 * \file golle/disj.h
 * \author Anthony Arnold
 * \copyright MIT License
 * \date 2014
 * \brief Disjunctive Schnorr Identification
 */
/*!
 * \defgroup disj Disjunctive Schnorr Identification
 * @{
 * The disjunctive Schnorr Identification protocol
 * is similar to the @ref schnorr. However, it allows
 * the prover to use one of two different keys without
 * the verifier knowing which key was used.
 */
/*!
 * \struct golle_disj_t
 * \brief A structure to store all of the revelant values
 * required by the Disjunctive Schnorr Identification protocol.
 */
typedef struct golle_disj_t {
  golle_num_t r1; /*!< The first generated random value. */
  golle_num_t c1; /*!< The first generated challenge value. */
  golle_num_t c2; /*!< The second generated challenge value. */
  golle_num_t t1; /*!< The first calculated t value. */
  golle_num_t t2; /*!< The second calculated t value. */
  golle_num_t s1; /*!< The first calculated s value. */
  golle_num_t s2; /*!< The second calculated s value. */
} golle_disj_t;

/*!
 * \brief Clear all numbers out of a disjuntive schnorr structure.
 * \param d The structure to clear.
 */
GOLLE_INLINE void golle_disj_clear (golle_disj_t *d) {
  if (d) {
    golle_num_delete (d->r1); d->r1 = NULL;
    golle_num_delete (d->c1); d->c1 = NULL;
    golle_num_delete (d->t1); d->t1 = NULL;
    golle_num_delete (d->s1); d->s1 = NULL;
    golle_num_delete (d->c2); d->c2 = NULL;
    golle_num_delete (d->t2); d->t2 = NULL;
    golle_num_delete (d->s2); d->s2 = NULL;
  }
}

/*!
 * \brief Generate the commitments `t1` and `s2` to be sent
 * to the verifier.
 * \param key The Schnorr key, containing the `G` and `Y` values,
 * that the secret key is *not* associated with.
 * \param d The disjunct structure that will receive the 
 * `t1`, `r1`, `t2`, `c2`, and `s2` values.
 * \param k The number of bits that `c2` should be.
 * \return ::GOLLE_ERROR, ::GOLLE_OK, or ::GOLLE_EMEM.
 */
GOLLE_EXTERN golle_error golle_disj_commit (const golle_schnorr_t *key,
					    golle_disj_t *d,
					    size_t k);
/*!
 * \brief Output the proof that `x` is known. `s1`, `s2`, `c1`, and `c2` are
 * sent to the verifier.
 * \param key The schnorr key, containing the `G`, and `Y` values,
 * that the secret key is *not* associated with; the same key used
 * with golle_disj_commit().
 * \param real The schnorr key, containing the `G` and `Y` values,
 * and the secrete key value `x` that is associated with them.
 * \param c The random c value sent by the verifier.
 * \param d The disjunct structure that will receive
 * values `c1` and `s1`. `
 * \return ::GOLLE_ERROR, ::GOLLE_OK, or ::GOLLE_EMEM.
 */
GOLLE_EXTERN golle_error golle_disj_prove (const golle_schnorr_t *key,
					   const golle_schnorr_t *real,
					   const golle_num_t c,
					   golle_disj_t *d);
/*!
 * \brief Verify a proof sent by a prover.
 * \param k1 The first Schnorr public key.
 * \param k2 The second Schnorr public key.
 * \param d The collection of values received from the prover.
 * \return ::GOLLE_OK, ::GOLLE_ERROR for `NULL`, or ::GOLLE_EMEM.
 * If the verification fails, returns ::GOLLE_ECRYPTO.
 */
GOLLE_EXTERN golle_error golle_disj_verify (const golle_schnorr_t *k1,
					    const golle_schnorr_t *k2,
					    const golle_disj_t *d);
/*!
 * @}
 */
#endif
