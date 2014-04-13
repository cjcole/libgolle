/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_SET_H
#define LIBGOLLE_SET_H

#include "platform.h"
#include "errors.h"
#include "types.h"
#include <stdlib.h>

/*!
 * \file golle/set.h
 * \author Anthony Arnold
 * \copyright MIT License
 * \date 2014
 * \brief Describes operations for working on generic sets.
 */

GOLLE_BEGIN_C

/*!
 * \defgroup set Set functions
 * @{
 * Functions and structs for working with
 * a set structure. The set is implemented as
 * an RB Tree. No duplicates are allowed. as such
 * each element of the set is disctinct and makes
 * it easier to find collisions.
 */

/*!
 * \struct golle_set_t
 * \brief An opaque pointer to a set of objects.
 */
typedef struct golle_set_t golle_set_t;

/*!
 * \typedef golle_set_comp_t
 * \brief A comparison function. Must return < 0 if the left parameter
 * comes first in a strict weak ordering. Return > 0 if the left
 * parameter comes second in a strict weak ordering.
 * Return 0 if the two parameters are considered equal.
 */
typedef int (*golle_set_comp_t) (const void *, const void *);

/*!
 * \struct golle_set_iterator_t
 * \brief A type used for iterating through all of the items in a set.
 */
typedef struct golle_set_iterator_t golle_set_iterator_t;

/*!
 * \brief Allocate a new set.
 * \param num_items Estimated number of items the set will hold.
 * \param item_size Number of bytes required to hold one item (guess if needed).
 * \param[out] set Pointer to the pointer which will hold the address of 
 * the new set.
 * \param comp The function used to compare items.
 * \return ::GOLLE_OK if successful, or ::GOLLE_EMEM if memory couldn't be 
 * allocated. ::GOLLE_ERROR if \p set or \p comp is \p NULL.
 */
GOLLE_EXTERN golle_error golle_set_new (golle_set_t **set, 
					size_t num_items, 
					size_t item_size,
					golle_set_comp_t comp);

/*!
 * \brief Deallocate a set.
 * \param set The set to be destroyed.
 */
GOLLE_EXTERN void golle_set_delete (golle_set_t *set);

/*!
 * \brief Get the number of items in a set.
 * \param set The set to query.
 * \return The number of items in the \p set, or \p 0 if \p set it \p NULL.
 */
GOLLE_EXTERN size_t golle_set_size (const golle_set_t *set);


/*!
 * \brief Insert an item into a set.
 * The item will be copied into the set if the set does not already contain it.
 *
 * \param set The set to insert into.
 * \param item The element to insert into the set.
 * \param size The size of the element.
 * \return ::GOLLE_OK if the \p item was inserted. ::GOLLE_EEXISTS if the \p set
 * already contains the item. ::GOLLE_EMEM if the \p set did not contain enough
 * space to insert the \p item, and no more could be allocated. ::GOLLE_ERROR if
 * \p set is \p NULL.
 *
 * \warning Insertion invalidates iterators.
 */
GOLLE_EXTERN golle_error golle_set_insert (golle_set_t *set, 
					   const void *item, 
					   size_t size);



/*!
 * \brief Remove an item from a set.
 * The item will be removed from the set and the allocated space freed.
 *
 * \param set The set to remove from.
 * \param item The element to remove from the set.
 * \return ::GOLLE_OK if the \p item was removed. ::GOLLE_ENOTFOUND if the
 * \p set didn't contain the \p item based on the given \p comp function.
 * ::GOLLE_ERROR if \p set is \p NULL.
 * 
 * \warning Erasure invalidates iterators.
 */
GOLLE_EXTERN golle_error golle_set_erase (golle_set_t *set,
					  const void *item);


/*!
 * \brief Remove all items from a set.
 * \param set The set to clear.
 * \return ::GOLLE_OK if the set was cleared. ::GOLLE_ERROR if the
 * set is `NULL`.
 *
 * \warning Iterators will be invalidated.
 */
GOLLE_EXTERN golle_error golle_set_clear (golle_set_t *set);

/*!
 * \brief Find an item in a set.
 *
 * \param set The set to search in.
 * \param item The item to search for.
 * \param[out] found Receives a pointer to the found item, or \p NULL if not found.
 * \return ::GOLLE_OK if the item was found. ::GOLLE_ENOTFOUND if the set
 * didn't contain the item. ::GOLLE_ERROR if set is \p NULL.
 *
 * \warning If you want to alter the returned item, copy it, remove it,
 * then insert it again. It is not safe to alter the data unless
 * you can guarantee that it will not effect the strict weak ordering. It's
 * safer to do it the former way.
 */
GOLLE_EXTERN golle_error golle_set_find (const golle_set_t *set, 
					 const void *item,
					 const void **found);


/*!
 * \brief Create an iterator to iterate over the given set. The iterator begins
 * by pointing to before the first element in the set.
 *
 * \param set The set to iterate over.
 * \param[out] iter Receives the address of the new iterator.
 * \return ::GOLLE_OK if the iterator was created. ::GOLLE_EMEM if the iterator
 * couldn't be allocated. ::GOLLE_ERROR if \p set or \p iter is \p NULL.
 *
 */
GOLLE_EXTERN golle_error golle_set_iterator (const golle_set_t *set, 
					     golle_set_iterator_t **iter);


/*! 
* \brief Get the next value of the iterator.
 * \param iter The iterator.
 * \param[out] item Is populated with the next item pointed to by the iterator.
 * \return ::GOLLE_OK if the operation was successful. ::GOLLE_ERROR if iter or
 * value is \p NULL. ::GOLLE_END if the iterator is at the end of the set.
 *
 * \warning If you want to alter the returned item, copy it, remove it,
 * then insert it again. It is not safe to alter the data unless
 * you can guarantee that it will not effect the strict weak ordering. It's
 * safer to do it the former way.
 */
GOLLE_EXTERN golle_error golle_set_iterator_next (golle_set_iterator_t * iter,
						  const void **item);


/*!
 * \brief Reset the iterator to its initial position (just before the first
 * item).
 *
 * \param iter The iterator.
 *
 * \return ::GOLLE_OK if successful. ::GOLLE_ERROR if iter is \p NULL.
 */
GOLLE_EXTERN golle_error golle_set_iterator_reset (golle_set_iterator_t *iter);

/*!
 * \brief Free resources for a set iterator.
 * \param iter The iterator.
 */
GOLLE_EXTERN void golle_set_iterator_free (golle_set_iterator_t *iter);


#if defined (DEBUG)
/*!
 * \brief Test the validity of the set.
 */
GOLLE_EXTERN golle_error golle_set_check (golle_set_t *set);
#endif

/*!
 * @}
 */

GOLLE_END_C

#endif
