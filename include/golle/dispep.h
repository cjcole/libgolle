/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_DISPEP_H
#define LIBGOLLE_DISPEP_H

#include "platform.h"
#include "elgamal.h"
#include "schnorr.h"
#include "errors.h"

GOLLE_BEGIN_C

/*!
 * \file golle/dispep.h
 * \author Anthony Arnold
 * \copyright MIT License
 * \date 2014
 * \brief DISPEP protocol.
 */
/*!
 * \defgroup dispep Disjunctive Plaintext Equivalence Proof
 * @{
 * The DISPEP protocol described in Jakobsson M. and Juels A., Millimix:
 * Mixing in Small Batches, DIMACS Technical Report 99-33, June 1999.
 *
 * The DISPEP protocol leverages the security of @ref disj in order to
 * prove that an El Gamal ciphertext \f$(\alpha,\beta)\f$ is a re-encryption
 * of one of two difference ciphertexts, without revealing which one.
 *
 * To use DISPEP, use golle_dispep_setup() to set up the two
 * ::golle_schnorr_t structures, and then use the results to
 * perform Disjuntive Schnorr proof.
 */

/*!
 * \brief Prepare the disjunctive schnorr key for use
 * by a prover and verifier.
 * \param r The El Gamal ciphertext that is a re-encryption of either
 * `e1` or `e2`.
 * \param e1 The first potential base ciphertext.
 * \param e2 The second potential base ciphertext.
 * \param[out] k1 The first Schnorr key.
 * \param[out] k2 The second Schnorr key.
 * \param key The El Gamal key associated with the re-encryption. 
 * Must contain `p`.
 * \return ::GOLLE_OK for success. ::GOLLE_ERROR for unexpected `NULL`.
 * ::GOLLE_EMEM for memory errors. ::GOLLE_ECRYPTO for encryption errors.
 */
GOLLE_EXTERN golle_error golle_dispep_setup (const golle_eg_t *r,
					     const golle_eg_t *e1,
					     const golle_eg_t *e2,
					     golle_schnorr_t *k1,
					     golle_schnorr_t *k2,
					     const golle_key_t *key);
/*!
 * @}
 */

GOLLE_END_C

#endif
