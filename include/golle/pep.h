/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_PEP_H
#define LIBGOLLE_PEP_H

#include "platform.h"
#include "elgamal.h"
#include "distribute.h"
#include "schnorr.h"

GOLLE_BEGIN_C


/*!
 * \file golle/pep.h
 * \author Anthony Arnold
 * \copyright MIT License
 * \date 2014
 * \brief PEP protocol.
 */
/*!
 * \defgroup pep Plaintext Equivalence Proof
 * @{
 * The PEP protocol described in Jakobsson M. and Juels A., Millimix:
 * Mixing in Small Batches, DIMACS Technical Report 99-33, June 1999.
 *
 * Consider the El Gamal encryptions \f$(a,b)\f$ and \f$(c,d)\f$ for some 
 * plaintext \f$m\f$. PEP allows the prover to prove that both ciphertexts 
 * are encryptions of the same ciphertext, without revealing what the plaintext
 * is.
 * 
 * First, it's easy to see due to the homomorphic property of El Gamal
 * that if \f$(a,b)\f$ and \f$(c,d)\f$ are encryptions of the same
 * plaintext, then \f$(a/c, b/d)\f$ is an encryption of \f$1\f$ and
 * forms a @ref schnorr public key. The Schnorr Identification Algorithm
 * is then used to complete the PEP protocol.
 */

/*!
 * \brief Make a Schnorr public key, \f$(G, Y)\f$
 * out of the two ciphertexts, \f$e_{1}\f$ and \f$e_{2}\f$.
 * \param egKey The key used in the Encryption of `e1` and `e2`.
 * \param e1 The first ciphertext.
 * \param r1 The random number used the the encryption of e1.
 * \param e2 The second ciphertext.
 * \param r2 The random number used the the encryption of e2.
 * \param[out] key The key to construct.
 * \return ::GOLLE_OK, ::GOLLE_EMEM, or ::GOLLE_ERROR.
 */
GOLLE_EXTERN golle_error golle_pep_set (const golle_key_t *egKey,
					const golle_eg_t *e1,
					const golle_num_t r1,
					const golle_eg_t *e2,
					const golle_num_t r2,
					golle_schnorr_t *key);
/*!
 * @}
 */

GOLLE_END_C

#endif

