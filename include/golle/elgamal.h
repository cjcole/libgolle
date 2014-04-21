/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_ELGAMAL_H
#define LIBGOLLE_ELGAMAL_H

#include "platform.h"
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
 * for verification and completeness.
 */

/*!
 * \struct golle_eg_t
 * \brief ElGamal ciphertex.
 */
typedef struct golle_eg_t {
  golle_num_t a; /*!< The first ciphertext element. */
  golle_num_t b; /*!< The second ciphertext element. */
} golle_eg_t;

/*!
 * \brief Clear memory allocated for the ciphertext.
 * \param cipher The ciphertext to clear.
 */
GOLLE_INLINE void golle_eg_clear (golle_eg_t *cipher) {
  if (cipher) {
    golle_num_delete (cipher->a); cipher->a = NULL;
    golle_num_delete (cipher->b); cipher->b = NULL;
  }
}

/*!
 * \brief Encrypt a number \f$m \in \mathbb{G}_{q}\f$.
 * \param key The ElGamal public key to use during encryption.
 * \param m The number to encrypt. \f$msg \in \mathbb{G}_{q}\f$
 * \param cipher A non-`NULL` ::golle_eg_t structure.
 * \param rand If the value pointed to is not `NULL`, it will be used as the
 * random value \f$r \in \mathbb{Z}^{*}_{q}\f$. Otherwise, a random
 * value will be collected and returned as new number, via golle_num_new().
 * If the argument itself is `NULL`, then a random value will be generated
 * but not returned.
 * \return ::GOLLE_ERROR if any parameter is `NULL`. ::GOLLE_EOUTOFRANGE if
 * \f$m >= {q}\f$. ::GOLLE_ECRYPTO if
 * an error happens during cryptography. ::GOLLE_EMEM if memory allocation
 * fails. ::GOLLE_OK if successful.
 * \note It is assumed that \f$m \in \mathbb{G}_{q}\f$ by computing
 * \f$ m = g^{n} \mod q\f$ prior to encrypting.
 */
GOLLE_EXTERN golle_error golle_eg_encrypt (golle_key_t *key,
					   golle_num_t m,
					   golle_eg_t *cipher,
					   golle_num_t *rand);

/*!
 * \brief Decrypt a message.
 * \param key The key containing the primes used for modulus operations.
 * \param xi An array of private key values, for each member of the group.
 * \param len The number of keys in `xi`.
 * \param cipher A non-`NULL` ciphertext value from golle_eg_encrypt().
 * \param m The decrypted number.
 * \return ::GOLLE_ERROR if any parameter is `NULL` or if `len` is `0`.
 * ::GOLLE_ECRYPTO if an error occurs during cryptography. 
 * ::GOLLE_EMEM if memory allocation fails. ::GOLLE_OK if successful.
 * \warning This function is never actually called during the Golle protocol.
 * it is provided here for completeness of the ElGamal cryptosystem and
 * for the purposes of testing. You may, however, use it as a general purpose
 * cryptosystem if encryption is asymmetric, with one encryptor and one
 * decryptor.
 */
GOLLE_EXTERN golle_error golle_eg_decrypt (golle_key_t *key,
					   golle_num_t *xi,
					   size_t len,
					   const golle_eg_t *cipher,
					   golle_num_t m);

/*!
 * @}
 */

GOLLE_END_C

#endif
