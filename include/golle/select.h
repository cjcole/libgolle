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
 * \brief Construct a new ::golle_select_t struct based on a
 * ::golle_peer_set_t and a number of objects.
 * \param select Will receive the pointer to the new struct
 * \param set The ::golle_peer_set_t that has a ready key.
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
 * @}
 */
GOLLE_END_C

#endif
