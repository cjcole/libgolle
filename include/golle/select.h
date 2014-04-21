/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_SELECT_H
#define LIBGOLLE_SELECT_H

#include "platform.h"
#include "peer.h"
#include "types.h"
#include "errors.h"

GOLLE_BEGIN_C

/*!
 * \file golle/select.h
 * \author Anthony Arnold
 * \copyright MIT License
 * \date 2014
 * \brief Object selection based on the Golle Protocol.
 */
/*!
 * \defgroup select Object Selection
 * @{
 *
 * Once a key has been correctly set up and
 * peers have been verified (see @ref peer) the resulting
 * ::golle_peer_set_t can be used to create a ::golle_select_t
 * object. The ::golle_select_t type is given an object count
 * \f$n\f$ from which random objects are selected according to the
 * Golle Protocol. The value \f$i\f$ of a selected object is usually
 * an index into an array somewhere (or in the case of dealing cards,
 * each number \f$i \in \{0, ..., 51\}\f$ represents a unique card in
 * a deck.) If the selected number is an array index, care must be taken
 * to ensure that the index refers to the same value at each peer node.
 *
 * If the number of players in the ::golle_peer_set_t used to create
 * the ::golle_select_t must change, then the ::golle_select_t
 * should be discarded and a new one created after the ::golle_peer_set_t
 * is back into a ready key state (::GOLLE_KEY_READY).
 */
/*!
 * \struct golle_select_t
 * \brief An opaque structure that manages a peer's participation
 * in the Golle protocol.
 */
typedef struct golle_select_t golle_select_t;

/*!
 * \typedef golle_select_callback_t
 * \brief This kind of callback function is invoked three different ways
 * when a call is made to golle_select_object(). 
 *
 * In the first call, the buffers contain the commitment
 * buffers from ::golle_commit_t (see @ref commit). They are,
 * respectively, the `rsend` field followed by the `hash` field.
 * The receiving peer will store them via golle_select_peer_commit().
 *
 * In the second call, the buffers contain the verification
 * buffers (including the actual selection value). They are,
 * respectively, the `rkeep` field followed by the `secret` field.
 * The receiving peer will store them via via golle_select_peer_verify().
 *
 * In the third call, the buffers contain the selected object index
 * and a random value. The receiving peer should store them
 * via golle_select_accumulate(). 
 *
 * In the first two instances the two ::golle_bin_t buffers should
 * be sent to each peer. 
 *
 * In the third instance, the two buffers should be sent to any
 * peer to whom the selection should be revealed. The receiving
 * peer(s) will pass the received buffers to golle_select_reveal().
 * The first buffer will be the the `ri` parameter, the 
 * second buffer will be the `rand` parameter.
 *
 * It is up to the sending protocol
 * to be able to tell the difference between the two buffers
 * (it's really important). The best way is to send them
 * separately, with a distinct order.
 *
 * If any error occurs, return it and force the
 * selection to abort.
 */
typedef golle_error (*golle_select_callback_t) (const golle_select_t *,
						const golle_bin_t *,
						const golle_bin_t *);

/*!
 * \brief Construct a new ::golle_select_t struct based on a
 * ::golle_peer_set_t and a number of objects.
 * \param select Will receive the pointer to the new struct
 * \param peers The ::golle_peer_set_t that has a ready key.
 * \param n The number of objects in the selection set.
 * \return ::GOLLE_OK if everything went OK. ::GOLLE_ERROR if
 * any parameter is NULL. ::GOLLE_EINVALID if the calling
 * golle_peers_get_key (set) returns `NULL`. ::GOLLE_EEMPTY if
 * `n` is zero or if there are no peers in the set. 
 * ::GOLLE_EMEM if memory couldn't be allocated.
 */
GOLLE_EXTERN golle_error golle_select_new (golle_select_t **select,
					   golle_peer_set_t *peers,
					   size_t n);

/*!
 * \brief Free the resources associated with the select structure.
 * \param select The select structure to free.
 * \note The key derived from the ::golle_peer_set_t passed to
 * golle_select_new() will not be freed. You must do this yourself.
 * As such, the key must outlive the ::golle_select_t.
 */
GOLLE_EXTERN void golle_select_delete (golle_select_t *select);

/*!
 * \brief Begin a selection round by selecting a random g^i.
 * \param select The collection to select from.
 * \param commit The commitment callback.
 * \param verify The verification callback.
 * \param reveal The final callback which reveals the selection.
 * \return ::GOLLE_ERROR if any parameter is `NULL`.
 * ::GOLLE_EMEM if memory allocation fails.
 * ::GOLLE_ECRYPTO if an error happens in the crypto library.
 * ::GOLLE_EABORT if any callback fails.
 * ::GOLLE_OK if successful.
 */
GOLLE_EXTERN golle_error golle_select_object (golle_select_t *select,
					      golle_select_callback_t commit,
					      golle_select_callback_t verify,
					      golle_select_callback_t reveal);
/*!
 * \brief Store a commitment from a peer.
 * \param select The select structure to store the commitment in.
 * \param peer The peer to store the commitment for.
 * \param rsend The rsend of the commitment to store.
 * \param hash The hash of the commitment to store.
 * \return ::GOLLE_ERROR if any parameter is `NULL`.
 * ::GOLLE_ENOTFOUND if the peer doesn't exist in the set that
 * was used to create the select struct.
 * ::GOLLE_EEXISTS if a commitment was already stored for the given peer.
 * ::GOLLE_EMEM for memory errors.
 * ::GOLLE_OK for success.
 * \note These values should have been received from a peer via
 * a call to golle_select_object() at the remote end.
 */
GOLLE_EXTERN golle_error golle_select_peer_commit (golle_select_t *select,
						   golle_peer_t peer,
						   golle_bin_t *rsend,
						   golle_bin_t *hash);
/*!
 * \brief Verify a commitment from a peer. The `secret` is
 * stored for later revelation.
 * \param select The select structure that stored the commitment.
 * \param peer The peer to verify for.
 * \param rkeep The rkeep of the commitment.
 * \param secret The secret of the commitment.
 * \return ::GOLLE_ERROR if any param is `NULL`.
 * ::GOLLE_ENOTFOUND if the peer hadn't previously stored a commitment.
 * ::GOLLE_EEXISTS if the commitment had already been verified.
 * ::GOLLE_EMEM for memory errors.
 * ::GOLLE_ENOCOMMIT if commitment verification failed!
 * ::GOLLE_OK for success.
 * \note These values should have been received from a peer via
 * a call to golle_select_object() at the remote end.
 */
GOLLE_EXTERN golle_error golle_select_peer_verify (golle_select_t *select,
						   golle_peer_t peer,
						   golle_bin_t *rkeep,
						   golle_bin_t *secret);
/*!
 * \brief Accept a reveal from a peer. The reveal goes
 * toward the calculation of the final object.
 * \param select The select structure.
 * \param peer The peer who is revealing their r and rand.
 * \param r The r value selected by the peer in their own call to 
 * golle_select_object().
 * \param rand The rand value generated by the peer in their own
 * call to golle_select_object().
 * \return ::GOLLE_ERROR if any parameter is `NULL`.
 * ::GOLLE_ENOTFOUND if the peer is not valid or has not verified its
 * commitment yet.
 * ::GOLLE_EEXISTS if values for the peer have already been received.
 * ::GOLLE_EABORT if the encryption value does not match the one 
 * set by the peer previously.
 * ::GOLLE_EMEM for memory errors.
 * ::GOLLE_OK for success.
 */
GOLLE_EXTERN golle_error golle_select_reveal (golle_select_t *select,
					      golle_peer_t peer,
					      golle_bin_t *r,
					      golle_bin_t *rand);

/*!
 * \brief Begin the next round. Clears all commitments.
 * \param select The structure to begin the next round for.
 * \return ::GOLLE_ERROR if `select` is `NULL`. ::GOLLE_OK
 * if successful.
 */
GOLLE_EXTERN golle_error golle_select_next_round (golle_select_t *select);

/*!
 * \brief Resets the state, clearing all commitments and
 * all records of selected objects.
 * \param select The structure to reset.
 * \return ::GOLLE_ERROR if `select` is `NULL`. ::GOLLE_OK if successful.
 */
GOLLE_EXTERN golle_error golle_select_reset (golle_select_t *select);

/*!
 * @}
 */
GOLLE_END_C

#endif
