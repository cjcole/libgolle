/*
 * Copyright (C) Anthony Arnold 2014
 */
#ifndef LIBGOLLE_GOLLE_H
#define LIBGOLLE_GOLLE_H

#include "platform.h"
#include "types.h"
#include "distribute.h"
#include "errors.h"
#include "commit.h"
#include "elgamal.h"

GOLLE_BEGIN_C

/*!
 * \file golle/golle.h
 * \author Anthony Arnold
 * \copyright MIT License
 * \date 2014
 * \brief Golle interface
 */
/*!
 * \defgroup golle The Golle protocol interface
 * @{
 * The Golle interface is a strong wrapper around most of the
 * subprotocols that make up the Golle protocol. It allows the client
 * code to set up a series of callbacks and have the library perform
 * most of the work. The callbacks are raised when input is required
 * from the client or when data is required to be sent.
 *
 * Because this interface is basically the implementation of the protocol,
 * if all the client wants to do is "play Mental Poker", then this, and the
 * key distribution module, are the
 * only interfaces needed. All of the other interfaces are provided as a
 * handy reference implementation and as a description of how the inner
 * machinery of the Golle protocol works. However if the client wishes
 * more fine-grained control over the protocol then the headers for each
 * subprotocol are available; this interface can be used as a reference
 * implementation for the protocol as a whole.
 *
 * \note There are aspects of this protocol currently missing. As a result,
 * some functionality is __not__ available. The shortcomings of the current
 * implementation can be summarised as follows:
 *
 *  - No proof of subset membership or proof of correct decryption is performed.
 *  - Millimix is not implemented, so multiple rounds are not allowed.
 *
 * The building blocks for these features are implemented in @ref dispep.
 */
/*! 
 * Used to indicate that a selected item is for all peers. 
 */
#define GOLLE_FACE_UP SIZE_MAX 
/*!
 * \struct golle_t
 * \brief The main Golle structure.
 * \note All of the callbacks must be filled out in order the the
 * protocol to work. If the protocol comes across a `NULL` callback
 * at any point, it will fail and the fail will propagate all the way
 * to the callsite. It can be difficult for the client to figure out
 * at what point the protocol failed, so always check that the callbacks
 * are set appropriately.
 * \note Also note that the number of peers, including the local client,
 * must be invariant. If at any point the number of peers changes,
 * the current "game" will be invalid and must be started from
 * the first round again.
 */
typedef struct golle_t golle_t;

/*!
 * \typedef golle_bcast_commit_t
 * \brief A callback used to broadcast a commitment.
 */
typedef golle_error (*golle_bcast_commit_t) (golle_t *, 
					     golle_bin_t *, 
					     golle_bin_t *);
/*!
 * \typedef golle_bcast_secret_t
 * \brief A callback for broadcasting the secret parts of a commitment.
 */
typedef golle_error (*golle_bcast_secret_t) (golle_t *, 
					     golle_eg_t *, 
					     golle_bin_t *);
/*!
 * \typedef golle_accept_commit_t
 * \brief A callback for accepting the commitment of a peer.
 */
typedef golle_error (*golle_accept_commit_t) (golle_t *, 
					      size_t, 
					      golle_bin_t *, 
					      golle_bin_t *);
/*!
 * \typedef golle_accept_eg_t
 * \brief A callback for accepting ciphertext from a peer.
 */
typedef golle_error (*golle_accept_eg_t) (golle_t *, 
					  size_t, 
					  golle_eg_t *, 
					  golle_bin_t *);
/*!
 * \typedef golle_reveal_rand_t
 * \brief A callback for revealing a random number and
 * the randomness used to encrypt it in a previous operation.
 */
typedef golle_error (*golle_reveal_rand_t)(golle_t *, 
					   size_t, 
					   size_t, 
					   golle_num_t);
/*!
 * \typedef golle_accept_rand_t
 * \brief A callback for accepting a random number and
 * the randomness used to encrypt it in a previous operation.
 */
typedef golle_error (*golle_accept_rand_t)(golle_t *, 
					   size_t, 
					   size_t*, 
					   golle_num_t);
/*!
 * \typedef golle_accept_crypt_t
 * \brief A callback for accepting a encrypted selection
 * from a peer.
 */
typedef golle_error (*golle_accept_crypt_t)(golle_t *, golle_eg_t *, size_t);
/*!
 * \typedef golle_bcast_crypt_t
 * \brief A callback for broadcasting an encrypted selection.
 */
typedef golle_error (*golle_bcast_crypt_t)(golle_t *, const golle_eg_t *);

struct golle_t {
  /*! The number of peers connected to. */
  size_t num_peers; 
  /*! The number of distinct items in the set 
   * (e.g. number of cards in a deck). */
  size_t num_items; 
  /*! The ElGamal key, which must be set up via the
   * @ref distribute module prior to using the Golle interface.
   */
  golle_key_t *key; 
  /*! The callback which will be invoked when a commitment should be
   * send to all peers. The parameters are `rsend` and `hash`. */
  golle_bcast_commit_t bcast_commit;
  /*! The callback which will be invoked when a commitment's secret values
   * should be revealed to all peers. */
  golle_bcast_secret_t bcast_secret;
  /*! The callback which will be invoked when the protocol requires
   * a commitment from a peer. The client should receive the commitment
   * from the designated peer in the first parameter and return it by
   * populating the final two buffers which correspond to `rsend` and
   * `hash` respectively.*/
  golle_accept_commit_t accept_commit;
  /*! The callback which will be invoked when the protocol requires
   * a ciphertext from a peer. The client should receive the ciphertext
   * buffer from the peer indicated in the first parameter and return it
   * in the second parameter. The
   * ciphertext corresponds to the `secret` member of a commitment.
   * The third parameter corresponds to the `rkeep` buffer of a commitment.
   * Thus the protocol will receive the full commitment for verification.
   */
  golle_accept_eg_t accept_eg;
  /*! The callback which will be invoked when the protocol needs
   * to reveal a random number and the randomness that was used to
   * encrypt it in a previous operation. The first parameter will indicate
   * the peer to send it to (or GOLLE_FACE_UP if it is to be broadcast). 
   * After being sent, the local client should do one of two things:
   *  1. If the peers that reveal the value do not include the local client,
   *     then the local client should call golle_check_selection().
   *  2. If the local client must receive the selection, then the callback
   *     should call golle_reveal_selection(). If the local client is
   *     the _only_ peer to reveal the selection, it must follow up with a
   *     call to golle_reduce_selection().
   */
  golle_reveal_rand_t reveal_rand;
  /*! The callback which will be invoked when the protocol needs
   * to receive a random number and the randomness that was used to encrypt
   * it in a previous operation. The first parameter will indicate
   * the peer to receive it from.
   */
  golle_accept_rand_t accept_rand;
  /*! The callback which will be invoked when the protocol needs
   * to receive an encrypted selection from another peer. This occurs when
   * a selection has been revealed to one peer secretly (e.g. revealing a card
   * face-down to one player). The callback should receive the ciphertext from
   * the peer in paramter 2 and populate the argument in parameter 1.
   */
  golle_accept_crypt_t accept_crypt;
  /*! The callback which will be invoked when the protocol needs
   * to send an encrypted selection to every other peer. This occurs when
   * a selection has been revealed to one peer secretly (e.g. revealing a card
   * face-down to one player). The callback should broadcast the ciphertext 
   * argument to all other peers. */
  golle_bcast_crypt_t bcast_crypt;
  /*! Reserved for private data used by the implementation.
   * Do not set. Do not clear. Just leave it alone. */
  void *reserved; 
};

/*!
 * \brief Establish the group structure. This is the first step to perform
 * before dealing any rounds.
 * \param golle The Golle Structure. Must have a valid key, and
 * `num_peers` and `num_items` must be > 0.
 * \return ::GOLLE_ERROR if `golle` is `NULL`, or a member is invalid.
 * ::GOLLE_EMEM if memory allocation fails. ::GOLLE_ECRYPTO if any
 * internal crypto operation fails (indicates a bad key). Upon success,
 * returns ::GOLLE_OK.
 */
GOLLE_EXTERN golle_error golle_initialise (golle_t *golle);

/*!
 * \brief Releases any memory used by the Golle interface stored in
 * the `reserved` member.
 * \param golle The structure to release.
 * \note This function does not release the key, and does not
 * free the golle structure.
 * \warning The Golle structure must be reinitialised with
 * golle_initialise() if it is to be used again.
 */
GOLLE_EXTERN void golle_clear (golle_t *golle);

/*!
 * \brief Participate in selecting a random element from the set.
 * The behaviour of the implementation will depend on the round number.
 * \param golle The golle structure.
 * \param round The round number, zero-based.
 * \param peer The peer who is to receive the selected item. Set to SIZE_MAX
 * if the item is meant to be broadcast.
 * \return ::GOLLE_ERROR for any NULLs or if `peer` is too large, or if `round > 0`
 * and the first round hasn't been finished yet. ::GOLLE_ECRYPTO for internal
 * cryptographic errors. ::GOLLE_ENOCOMMIT if a commitment from a peer is invalid.
 * ::GOLLE_OK for success.
 * \note Selections are indexed internally, starting at zero and incrementing.
 * If a collision occurs, the collision will be discarded but the index will not
 * be reused.
 */
GOLLE_EXTERN golle_error golle_generate (golle_t *golle, 
					 size_t round, 
					 size_t peer);

/*!
 * \brief Call this function after golle_generate() if the local
 * peer is to reveal received random selections as an actual item in the set.
 * \param golle The golle structure.
 * \param[out] selection Receives the revealed selection.
 * \return ::GOLLE_EMEM for memory errors. ::GOLLE_ERROR for `NULL` errors.
 * ::GOLLE_ECRYPTO for cryptography errors. ::GOLLE_OK for success.
 */
GOLLE_EXTERN golle_error golle_reveal_selection (golle_t *golle,
						 size_t *selection);
/*!
 * \brief Call this function after golle_reveal_selection() if the local
 * peer is the only peer receiving a random selection. The peer must
 * reduce the selection and output a proof that it has been done
 * correctly.
 * \param golle The golle structure.
 * \param c The reduced item, returned from golle_reveal_selection().
 * \param collision If a collision occurs, will be populated with the
 * index of the found collision.
 * \return ::GOLLE_EMEM for memory errors. ::GOLLE_ERROR for `NULL` errors.
 * ::GOLLE_ECRYPTO for cryptography errors. ::GOLLE_ECOLLISION if the
 * reduced item has already been 'dealt'. ::GOLLE_OK for success.
 * \note If a collision occurs, the selection inditicated by `collision`
 * will be discarded and must be done again. The selection id will not
 * be reused.
 */
GOLLE_EXTERN golle_error golle_reduce_selection (golle_t *golle,
						 size_t c,
						 size_t *collision);
/*!
 * \brief Call this function in the ::golle_reveal_rand_t callback
 * when some other peer is receiving the reduced item. The function
 * will accept proof from the other peer that the item was reduced
 * correctly and will check for collisions.
 * \param golle The golle structure.
 * \param peer The peer from which to accept proof.
 * \param collision If a collision occurs, will be populated with the
 * index of the found collision.
 * \return ::GOLLE_EMEM for memory errors. ::GOLLE_ERROR for `NULL` errors.
 * ::GOLLE_ECRYPTO for cryptography errors. ::GOLLE_ECOLLISION if the
 * reduced item has already been 'dealt'. ::GOLLE_OK for success.
 * \note If a collision occurs, the selection inditicated by `collision`
 * will be discarded and must be done again. The selection id will not
 * be reused.
 */
GOLLE_EXTERN golle_error golle_check_selection (golle_t *golle,
						size_t peer,
						size_t *collision);
/*!
 * @}
 */
GOLLE_END_C

#endif
