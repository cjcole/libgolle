/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_ELGAMAL_H
#define LIBGOLLE_ELGAMAL_H

#include "platform.h"
#include "bin.h"
#include "distribute.h"
#include "numbers.h"
#include "errors.h"

GOLLE_BEGIN_C

/*!
 * \file golle/elgamal.h
 * \author Anthony Arnold
 * \copyright MIT License
 * \date 2014
 * \brief Describes functions for performing distributed ElGamal cryptography.
 */

/*!
 * \defgroup elgamal ElGamal
 * @{
 * Given a ::golle_key_t structure properly generated so that the user has
 * a the full public key in `h_product`, this module allows the user to
 * encrypt a message that the group can then work together to decrypt.
 *
 * Given a ::golle_key_t struct properly generated so that the user has
 * part of the private key in `x`, this module allows the user to partially
 * decrypt a message that was encrypted by another group member, as above.
 *
 * To encrypt a message \f$m \in \mathbb{G}\f$ using ElGamal,
 *  we select \f$r \xleftarrow{R} \{\mathbb{Z}^{*}_{q}\}\f$, then
 * calculate the ciphertext \f$c = (g^{r}, mh^{r})\f$.
 *
 * To decrypt a ciphertext \f$(a, b)\f$, we calculate \f$b/a^{x}\f$, where 
 * \f$a^{x} = \prod_{i=1}^{k}a^{x_{i}}\f$ for each of the \f$k\f$ members
 * of the group.
 *
 * Decryption is not needed by the Golle protocol, although we include it here
 * for verification and completeness. For more information on how ElGamal
 * is used in the Golle protocol, see @ref golle.
 */

/*!
 * \brief Encrypt a message.
 * \param key The ElGamal public key to use during encryption.
 * \param msg The message to encrypt. Must be <= the number of bits in `key->q`.
 * \param c1 An uninitialised buffer that will receive the value of \f$c_{1}\f$.
 * \param c2 An uninitialised buffer that will receive the value of \f$c_{2}\f$.
 * \return ::GOLLE_ERROR if any parameter is `NULL`. ::GOLLE_EOUTOFRANGE if
 * `msg` is too big. It must be split or reduced first. ::GOLLE_ECRYPTO if
 * an error happens during cryptography. ::GOLLE_EMEM if memory allocation
 * fails. ::GOLLE_OK if successful.
 */
GOLLE_EXTERN golle_error golle_eg_encrypt (golle_key_t *key,
					   golle_bin_t *msg,
					   golle_bin_t *c1,
					   golle_bin_t *c2);

/*!
 * \brief Decrypt a message.
 * \param xi An array of private key values, for each member of the group.
 * \param len The number of keys in `xi`.
 * \param c1 The first value of the ciphertext returned by golle_eg_encrypt().
 * \param c2 The second value returned by golle_eg_encrypt().
 * \param msg An unitialised buffer that will receive the decrypted message.
 * \return ::GOLLE_ERROR if any parameter is `NULL` or if `len` is `0`.
 * ::GOLLE_ECRYPTO if an error occurs during cryptography. 
 * ::GOLLE_EMEM if memory allocation fails. ::GOLLE_OK if successful.
 * \warning This function is never actually called during the Golle protocol.
 * it is provided here for completeness of the ElGamal cryptosystem and
 * for the purposes of testing. You may, however, use it as a general purpose
 * cryptosystem if encryption is asymmetric, with one encryptor and one
 * decryptor.
 */
GOLLE_EXTERN golle_error golle_eg_decrypt (golle_num_t *xi,
					   size_t len,
					   golle_bin_t *c1,
					   golle_bin_t *c2,
					   golle_bin_t *msg);

/*!
 * @}
 */


GOLLE_END_C

#endif
