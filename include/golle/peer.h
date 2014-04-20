/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_PEER_H
#define LIBGOLLE_PEER_H

#include "platform.h"
#include "errors.h"
#include "distribute.h"
#include "commit.h"
#include "types.h"

GOLLE_BEGIN_C

/*!
 * \file golle/peer.h
 * \author Anthony Arnold
 * \copyright MIT License
 * \date 2014
 * \brief Interface for peer maintenance.
 */
/*!
 * \defgroup peer Peers
 * @{
 * 
 * This module helps with the maintenance of a set of peers
 * and the distribution of keys. For a more detailed explanation
 * of how the key distribution protocol works, see @ref distribute.
 */
/*!
 * \typedef golle_peer_t
 * \brief Represents a peer within a set of peers.
 */
typedef int golle_peer_t;

/*!
 * \struct golle_peer_set_t
 * \brief An abstraction over the ::golle_set_t type,
 * made specifically for handling a set of ::golle_peer_t.
 * Allows for adding and removing peers, storing and verifying
 * commitments (see @ref commit) from peers, and building a 
 * distributed key (see @ref distribute).
 */
typedef struct golle_peer_set_t golle_peer_set_t;

/*!
 * \enum golle_peer_key_state
 * \brief Identifies what state the key for a peer set is in.
 */
typedef enum golle_peers_key_state {
  GOLLE_KEY_UNDEFINED, /*!< The state of the key is undefined. */
  GOLLE_KEY_EMPTY, /*!< The `p`, `q`, and `g` elements must be set. */
  GOLLE_KEY_INCOMPLETE, /*!< Not all peers have contributed to the key yet. */
  GOLLE_KEY_READY /*!< The key is ready to be used. */
} golle_peer_key_state;

/*!
 * \brief Construct a new ::golle_peer_set_t.
 * \return A new ::golle_peer_set_t, or `NULL` if allocation failed.
 */
GOLLE_EXTERN golle_peer_set_t *golle_peers_new (void);

/*!
 * \brief Free a peer set.
 * \param The set to deallocate.
 * \note All peers will become invalid after removal.
 */
GOLLE_EXTERN void golle_peers_delete (golle_peer_set_t *set);

/*!
 * \brief Get the numbers of peers in a set.
 * \param set The set to retrieve the number of peers for.
 * \return The number of peers. If `set` is `NULL`, returns 0.
 */
GOLLE_EXTERN size_t golle_peers_size (golle_peer_set_t *set);

/*!
 * \brief Add a peer to a set.
 * \param set The set to add to.
 * \param[out] peer Receives the added peer.
 * \return ::GOLLE_OK if successful. ::GOLLE_ERROR if any parameter is `NULL`.
 * ::GOLLE_EMEM if the peer couldn't be allocated.
 * \note Adding a peer changes a ready key state to incomplete.
 */
GOLLE_EXTERN golle_error golle_peers_add (golle_peer_set_t *set,
					  golle_peer_t *peer);
/*!
 * \brief Remove a peer from a set.
 * \param set The set to remove from.
 * \param peer The peer to remove.
 * \return ::GOLLE_OK if successful. ::GOLLE_ERROR if any paramter is `NULL`.
 * ::GOLLE_ENOTFOUND if the peer didn't belong to the set.
 * \note The peer will become invalid after removal.
 * \note Removing a peer that has already contributed to the key means
 * all peer contributions are removed and new ones must be set.
 */
GOLLE_EXTERN golle_error golle_peers_erase (golle_peer_set_t *set,
					    golle_peer_t peer);

/*!
 * \brief Set the public parts (not including `h`) of the key.
 * \param set The peer set to set the key for.
 * \param key The key, with the appropriate members set, to use.
 * \return ::GOLLE_OK if successful. ::GOLLE_ERROR if `set` is `NULL`.
 * ::GOLLE_EINVALID if any part of the `key` is invalid. ::GOLLE_EMEM
 * if a memory allocation error occured.
 * \note Setting a `NULL` key will result in the key being emptied
 * and the state set back to ::GOLLE_KEY_EMPTY. 
 * \note If a new key is set successfully, the key state will either be
 * ::GOLLE_KEY_READY if no peers are added, or ::GOLLE_KEY_INCOMPLETE
 * if there are peers in the set.
 */
GOLLE_EXTERN golle_error golle_peers_set_key (golle_peer_set_t *set,
					      golle_key_t *key);

/*!
 * \brief Get the current state of the key.
 * \param set The set to check.
 * \return The state of the key. If `set` is `NULL`, the key state
 * is ::GOLLE_KEY_UNDEFINED. If the key has not been set up via
 * golle_peers_set_key(), the state is ::GOLLE_KEY_EMPTY. If
 * not all peers have contributed to the global key via
 * golle_peers_commit() and golle_peers_verify(), the key state
 * is ::GOLLE_KEY_INCOMPLETE. If all peers have contributed to the
 * key, then the key is ready to use and the state is ::GOLLE_KEY_READY.
 */
GOLLE_EXTERN golle_peer_key_state golle_peers_get_state (golle_peer_set_t *set);

/*!
 * \brief Check whether a peer has set it's key yet.
 * \param set The set to check against.
 * \param peer The peer to check.
 * \return Zero if the peer has not contributed to the key state,
 * Non-zero if the peer has contributed to the key state.
 * \note Peers that don't belong to the set will always return zero.
 * \note If either parameter is `NULL`, the function returns zero.
 */
GOLLE_EXTERN int golle_peers_check_key (golle_peer_set_t *set,
					golle_peer_t peer);

/*!
 * \brief Record a commitment to a key for a peer.
 * \param set The set to record against.
 * \param peer The peer to record for.
 * \param rsend The rsend value of the commitment to store. 
 * This will overwrite an existing commitment.
 * \param hash The hash value of the commitment to store.
 * This will overwrite an existing commitment.
 * \return ::GOLLE_OK if the commitment was stored successfully.
 * ::GOLLE_ERROR if any parameter is `NULL`. ::GOLLE_EINVALID if
 * the peer is not a member of the set. ::GOLLE_EEXISTS if a key
 * for the peer has already been verified.
 */
GOLLE_EXTERN golle_error golle_peers_commit (golle_peer_set_t *set,
					     golle_peer_t peer,
					     golle_bin_t *rsend,
					     golle_bin_t *hash);
/*!
 * \brief Verify a commitment to a key for a peer.
 * \param set The set to verify with.
 * \param peer The peer to verify for.
 * \param rkeep The rkeep of the commitment record.
 * \param secret The secret of the commitment record.
 * \return ::GOLLE_OK if the commitment was successfully verified.
 * ::GOLLE_ERROR if any parameter is `NULL`. ::GOLLE_EINVALID if
 * the peer is not a member of the set. ::GOLLE_EEXISTS if a key
 * for the peer has already been verified. ::GOLLE_ENOTFOUND if
 * a commitment for the peer does not exist. ::GOLLE_ENOCOMMIT
 * if the commitment test fails.
 * \note If verification is successful, the peer's key will
 * be accumulated into the global public key.
 * \note If the function results in all peers having verified
 * their key, the state of the peer set will become ::GOLLE_KEY_READY.
 */
GOLLE_EXTERN golle_error golle_peers_verify (golle_peer_set_t *set,
					     golle_peer_t peer,
					     golle_bin_t *rkeep,
					     golle_bin_t *secret);

/*!
 * \brief Gets the full public key, if ready.
 * \param set The set to get the key for.
 * \return If `set` is not `NULL`, and the state of the key is
 * ::GOLLE_KEY_READY, then return the key. Otherwise, return `NULL`.
 * \note The key returned is a pointer to the key held internally
 * by the state. Do not free it, do not alter it. When the state
 * is deleted, the key becomes invalid.
 */
GOLLE_EXTERN golle_key_t *golle_peers_get_key (golle_peer_set_t *set);

/*!
 * \brief Gets a commitment to the local h value.
 * \param set The set to generate the commitment for.
 * \param commit Will be populated with the value of the generated commitment.
 * \return ::GOLLE_OK if successful. ::GOLLE_ERROR if any argument is `NULL`.
 * ::GOLLE_EINVALID if the `h` value of the key isn't set yet (the state
 * is ::GOLLE_KEY_EMPTY). ::GOLLE_EMEM if memory allocation failed.
 * \note Do not delete the returned commitment. It will be deleted when
 * the set is deleted. Subsequent calls to golle_peers_get_commitment()
 * will delete the old save commitment, so you should copy or finish
 * with the returned commitement before calling this function again.
 */
GOLLE_EXTERN golle_error golle_peers_get_commitment (golle_peer_set_t *set,
						     golle_commit_t **commit);

/*!
 * @}
 */

GOLLE_END_C

#endif
