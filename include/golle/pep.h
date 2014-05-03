/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_PEP_H
#define LIBGOLLE_PEP_H

#include "platform.h"
#include "distribute.h"
#include "schnorr.h"
#include "elgamal.h"

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
 * out of the ElGamal public key and store
 * the private key.
 * \param egKey The key used in the encryption and reencryption.
 * \param k The random number used in the reencryption. Becomes the
 * secret key x.
 * \param z A random number in \f$\mathbb{Z}_{q}\f$ chosen by the
 * verifier.
 * \param[out] key The key to construct.
 * \return ::GOLLE_OK, ::GOLLE_EMEM, or ::GOLLE_ERROR.
 */
GOLLE_EXTERN golle_error golle_pep_prover (const golle_key_t *egKey,
					   const golle_num_t k,
					   const golle_num_t z,
					   golle_schnorr_t *key);
/*!
 * \brief Make a Schnorr public key, \f$(G, Y)\f$
 * from two ciphertexts. The private key (i.e. the reencryption
 * factor) is not known. This function is used by the verifier
 * to check if the two ciphertexts are the same.
 * \param egKey The ElGamal key used in the encryption.
 * \param z A random number in \f$\mathbb{Z}_{q}\f$ chosen by the
 * verifier.
 * \param e1 The first ciphertext.
 * \param e2 The second ciphertext.
 * \param[out] key The key to construct.
 * \return ::GOLLE_OK, ::GOLLE_EMEM, or ::GOLLE_ERROR.
 */
GOLLE_EXTERN golle_error golle_pep_verifier (const golle_key_t *egKey,
					     const golle_num_t z,
					     const golle_eg_t *e1,
					     const golle_eg_t *e2,
					     golle_schnorr_t *key);
/*!
 * @}
 */

GOLLE_END_C

#endif

