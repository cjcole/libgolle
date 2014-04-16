/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_GOLLE_H
#define LIBGOLLE_GOLLE_H

#include "bin.h"
#include "platform.h"
#include "errors.h"
#include "list.h"
#include "set.h"
#include "commit.h"
#include "distribute.h"



/*!
 * \file golle/golle.h
 * \author Anthony Arnold
 * \copyright MIT License
 * \date 2014
 * \brief The main interface to the golle library.
 */

/*!
 * \defgroup golle Golle state functions
 * @{
 *
 * Due to ElGamal's multiplicative homomorphism, the value 
 * \f$C = \prod_{i}g^{r_{i}}\f$ can be calculated by each member of the group
 * once each member has shared their own ciphertext \f$c\f$. 
 *
 * For a member to determine the final message in the protocol, the member
 * must receive (securely) the plaintext message \f$m_{i}\f$ and the random
 * value \f$r_{i}\f$ from member \f$i\f$. The decrypting member can then
 * verify that the encryption was correct. To get the final value, the
 * member calculates \f$\sum_{i}r_{i} \mod d\f$, where \f$d\f$ is the number
 * of items in the set. The result gives the index into the set.
 */



/*!
 * \struct golle_t
 * \brief An opaque pointer, represents a Golle state.
 */
typedef struct golle_t golle_t;


/*!
 * \typedef golle_comp_t
 * \brief A comparison function which compares elements.
 * - Return < 0 if the first argument is "less than" the second.
 * - Return > 0 if the first argument is "greater than" the second.
 * - Return 0 if both arguments are equal.
 */
typedef int (*golle_comp_t) (const void *, const void *);


/*!
 * \typedef golle_peer_t
 * Represents a peer within the state.
 */
typedef int golle_peer_t;


/*!
 * \struct golle_rand_t
 * \brief Represents a randomly-selected element.
 * Always send the commitment first, then the selection.
 * Each peer should verify the commitment.
 */
typedef struct golle_rand_t {
  golle_commit_t commitment; /*!< A non-malleable commitment to the selection. */
  golle_bin_t selection; /*!< A randomly-selected item, encrypted. */
} golle_rand_t;

/*!
 * \brief Create a new Golle state.
 * \param[out] state Assigned the allocated object. 
 * \return ::GOLLE_EMEM if memory couldn't be allocated.
 * ::GOLLE_ERROR if state is NULL. Otherwise return ::GOLLE_OK.
 */
GOLLE_EXTERN golle_error golle_new (golle_t **state);

/*!
 * \brief Deallocate a Golle state.
 * \param state The state to free.
 */
GOLLE_EXTERN void golle_delete (golle_t *state);


/*!
 * \brief Set the distinct elements that will be
 * allocated at random by the protocol.
 * \param state The Golle state to set the elements for.
 * \param set The set of elements. Will overwrite any existing ones.
 * \return ::GOLLE_OK if successful. ::GOLLE_ERROR if state or set is
 * NULL. ::GOLLE_EEMPTY if the set is empty. ::GOLLE_ETOOFEW if a replacement
 * would result in too few elements being available for all peers.
 */
GOLLE_EXTERN golle_error golle_elements_set (golle_t *state,
					     golle_set_t *set);


/*!
 * \brief Set the distinct elements that will be
 * allocated at random by the protocol.
 * \param state The Golle state to set the elements for.
 * \param list  The list of elements. Will overwrite any existing ones.
 * \param comp A comparison function for comparing elements.
 * \return ::GOLLE_OK if successful. ::GOLLE_ERROR if state or set is
 * NULL. ::GOLLE_EEMPTY if the set is empty. ::GOLLE_ETOOFEW if a replacement
 * would result in too few elements being available for all peers. 
 * ::GOLLE_EEXISTS if there are any duplicate elements in the \p list.
 */
GOLLE_EXTERN golle_error golle_elements_list (golle_t *state,
					      golle_list_t *list,
					      golle_comp_t *comp);


/*!
 * \brief Set the distinct elements that will be
 * allocated at random by the protocol.
 * \param state The Golle state to set the elements for.
 * \param array  The array of elements. Will overwrite any existing ones.
 * \param len The number of items in the array.
 * \param size The size of each item in the array.
 * \param comp A comparison function for comparing elements.
 * \return ::GOLLE_OK if successful. ::GOLLE_ERROR if state or set is
 * NULL. ::GOLLE_EEMPTY if the set is empty. ::GOLLE_ETOOFEW if a replacement
 * would result in too few elements being available for all peers. 
 * ::GOLLE_EEXISTS if there are any duplicate elements in the \p array.
 */
GOLLE_EXTERN golle_error golle_elements_array (golle_t *state,
					       void *array,
					       size_t len,
					       size_t size,
					       golle_comp_t *comp);


/*!
 * \brief Add a peer to the state.
 * \param state The state to add the peer to.
 * \param[out] peer Receives the new peer's id.
 * \return ::GOLLE_ERROR if state or peer is NULL.
 * ::GOLLE_ETOOFEW if a new peer would result in more peers than elements.
 * ::GOLLE_OK otherwise. Could also return ::GOLLE_EMEM if out of resources.
 * ::GOLLE_EINVALID if attempting to add a peer in the middle of a round.
 */
GOLLE_EXTERN golle_error golle_peer_add (golle_t *state,
					 golle_peer_t *peer);


/*!
 * \brief Remove a peer from the state.
 * \param state The state to remove the peer from.
 * \param peer The id of the peer to remove.
 * \return ::GOLLE_ERROR if state is NULL.
 * ::GOLLE_ENOTFOUND if the peer doesn't belong to the state.
 * ::GOLLE_OK if successful. ::GOLLE_EINVALID if attempting to remove a peer 
 * in the middle of a round.
 */
GOLLE_EXTERN golle_error golle_peer_remove (golle_t *state,
					    golle_peer_t peer);


/*!
 * \brief Set the key state after public key distribution
 * has occurred.
 * \param state The state to set the keys for.
 * \param key The key object. The public key elements, incluing `h_product`
 * must be set.
 * \return ::GOLLE_OK if the set succeeded. ::GOLLE_ERROR if any parameter is
 * `NULL` or if the `key` is invalid. ::GOLLE_EINVALID if attempting
 * to set the key in the middle of the round.
 */
GOLLE_EXTERN golle_error golle_set_session_key (golle_t *state,
						const golle_key_t *key);

/*!
 * \brief Clear the list of dealt cards, ready for a new round.
 * \param state The state to prepare.
 * \return ::GOLLE_ERROR if state is NULL. ::GOLLE_EINVALID if a
 * current round is already in place. ::GOLLE_EEMPTY if the key hasn't
 * been set yet.
 */
GOLLE_EXTERN golle_error golle_round_begin (golle_t *state);

/*!
 * \brief Finish a round. Operations that can only
 * be completed in between rounds will be available.
 * \param state The state to finish the round on.
 * \return ::GOLLE_ERROR if state is NULL. ::GOLLE_EINVALID if
 * the state was not in a round. ::GOLLE_OK if successful.
 */
GOLLE_EXTERN golle_error golle_round_end (golle_t *state);


/*!
 * \brief Randomly select an element.
 * \param state The state to select from.
 * \param rand Gets the encrypted selected element and the bit commitment.
 * \return ::GOLLE_ERROR if any parameter is NULL. ::GOLLE_EINVALID if
 * the state was not in a round. ::GOLLE_OK if successful. ::GOLLE_ECRYPTO
 * if a cryptography error occurred.
 */
GOLLE_EXTERN golle_error golle_select (golle_t *state, golle_rand_t *rand);


/*!
 * \brief Store a commitment from a peer.
 * \param state The state to store against.
 * \param peer The peer that sent the commitment.
 * \param commit The commitment values (`rsend` and `hash`).
 * \return ::GOLLE_ERROR if any parameter is NULL. ::GOLLE_EINVALID if
 * the state is not in a round. ::GOLLE_EEXISTS if a commitment from the
 * peer has already been recieved for this selection. ::GOLLE_ENOCOMMIT if
 * the commitment is not valid. ::GOLLE_OK if successful.
 */
GOLLE_EXTERN golle_error golle_commitment_store (golle_t *state,
						 golle_peer_t peer,
						 const golle_commit_t *commit);

/*!
 * \brief Accumulate the given selection.
 * \param state The state to add the selection to.
 * \param peer The id of the peer that the selection is from.
 * \param select The encrypted selection bytes from the peer and the remaining
 * parameters required to validate the commitment (`rkeep`).
 * \return ::GOLLE_ERROR if any parameter is NULL. GOLLE_INVALID if
 * the state is not in a round. ::GOLLE_EEXISTS if a selection from the
 * peer has already been received. ::GOLLE_ENOTFOUND if a commitment from
 * the peer has not been received for this selection. ::GOLLE_ENOCOMMIT if
 * the commitment test failed (the commitment was not honoured).
 */
GOLLE_EXTERN golle_error golle_selection_store (golle_t *state,
						golle_peer_t peer,
						const golle_commit_t *select);


/*!
 * \brief Get the additive homomorphism of the encrypted selections.
 * Retrieves the fully-encrypted selection.
 * \param state The state to get the selection from.
 * \param[out] selection The selection, encrypted with all peers' keys.
 * \return ::GOLLE_ERROR if any parameter is NULL. ::GOLLE_EINVALID if the
 * state was not in a round. ::GOLLE_ETOOFEW if a selection for one or more
 * peers was not stored yet. ::GOLLE_EEXISTS if the resulting selection
 * was already in the set (the selection process must begin again).
 */
GOLLE_EXTERN golle_error golle_selection_get (golle_t *state,
					      golle_bin_t *selection);


/*!
 * Decrypt the selection with the state's private key. May be a partial
 * decryption.
 * \param state The state which will decrypt the selection.
 * \param selection The selection to decrypt. Will be replaced with plaintext.
 * \return ::GOLLE_ERROR if any parameter is NULL. 
 * ::GOLLE_EEMPTY if a private key
 * has not been stored for this state. ::GOLLE_ECRYPTO if a cryptography error
 * occured.
 */
GOLLE_EXTERN golle_error golle_selection_decrypt (golle_t *state,
						  golle_bin_t *selection);


/*!
 * @}
 */

#endif
