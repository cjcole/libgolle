/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_LIST_H
#define LIBGOLLE_LIST_H

#include "platform.h"
#include "errors.h"
#include "types.h"


GOLLE_BEGIN_C


/*!
 * \file golle/list.h
 * \author Anthony Arnold
 * \copyright MIT License
 * \date 2014
 * \brief Describes the structures and operations for working with singly-linked
 * lists.
 */


/*!
 * \defgroup list Singly-linked lists
 * @{
 * Contains structures and functions for maintaining a
 * singly-linked list (or a LIFO queue).
 */

/*!
 * \struct golle_list_t
 * \brief An opaque pointer to a singly-linked list.
 */
typedef struct golle_list_t golle_list_t;


/*!
 * \struct golle_list_iterator_t
 * \brief A type used for iterating through all the items in a list.
 */
typedef struct golle_list_iterator_t golle_list_iterator_t;


/*!
 * \brief Allocate a new list.
 * \param[out] list Pointer which will hold the address of the list.
 * \return ::GOLLE_OK if successful. ::GOLLE_EMEM if memory couldn't be 
 * allocated. ::GOLLE_ERROR if \p list is NULL.
 */
GOLLE_EXTERN golle_error golle_list_new (golle_list_t **list);

/*!
 * \brief Deallocate a list.
 * \param list The list to be destroyed.
 */
GOLLE_EXTERN void golle_list_delete (golle_list_t *list);

/*!
 * \brief Get the number of items in a list.
 * \param list The list to test.
 * \return The number of items in the list. If \p list is NULL,
 * returns 0.
 */
GOLLE_EXTERN size_t golle_list_size (const golle_list_t *list);

/*!
 * \brief Get the element at the head of the list.
 * \param list The list to query.
 * \param[out] item Recieves the item value.
 * \return ::GOLLE_OK if the operation was successful. ::GOLLE_ERROR if any
 * parameter is NULL. ::GOLLE_EEMPTY if the \p list is empty.
 */
GOLLE_EXTERN golle_error golle_list_top (const golle_list_t *list, void **item);


/*!
 * \brief Append an item to the list.
 * The item will be copied.
 *
 * \param list The list to append to.
 * \param item The element to append into the list.
 * \param size The size of the element (used in memcpy).
 * \return ::GOLLE_OK if the item was appended. 
 * ::GOLLE_EMEM if memory couldn't be
 * allocated, or ::GOLLE_ERROR if \p list if NULL.
 */
GOLLE_EXTERN golle_error golle_list_push (golle_list_t *list,
					  const void *item,
					  size_t size);


/*!
 * \brief Append many identical items to the list.
 * The item will be copied multiple times.
 *
 * \param list The list to append to.
 * \param item The element to append into the list. If \p item is NULL,
 *  \p size is ignored and the item in the list is set to NULL.
 * \param size The size of the element (used in \p memcpy). If \p size is 0, 
 * the item will be set to NULL in the \p list.
 * \param count The number of new items to append.
 * \return ::GOLLE_OK if the item was appended. 
 * ::GOLLE_EMEM if memory couldn't be
 * allocated, or ::GOLLE_ERROR if \p list if NULL.
 */
GOLLE_EXTERN golle_error golle_list_push_many (golle_list_t *list,
					       const void *item,
					       size_t size,
					       size_t count);

/*!
 * \brief Remove the first item in the list.
 * \param list The list to remove from.
 * \return ::GOLLE_OK if an item was removed. 
 * ::GOLLE_EEMPTY if the \p list is empty.
 * ::GOLLE_ERROR if \p list is NULL.
 */
GOLLE_EXTERN golle_error golle_list_pop (golle_list_t *list);


/*!
 * \brief Remove the first count items from the front of the list.
 * \param list The list to remove from.
 * \param count The number of items to remove.
 * \return ::GOLLE_OK if an item was removed. ::GOLLE_EEMPTY if there are less
 * than \p count items in the \p list (note, they will not be removed).
 * ::GOLLE_ERROR if \p list is NULL.
 */
GOLLE_EXTERN golle_error golle_list_pop_many (golle_list_t *list, size_t count);


/*!
 * \brief Remove all items from a list. The equivalent of

     golle_list_pop_many(list, golle_list_size(list));

 * \param list The list to clear.
 * \return ::GOLLE_OK if the \p list was cleared. ::GOLLE_ERROR if \p list was
 * NULL.
 */
GOLLE_EXTERN golle_error golle_list_pop_all (golle_list_t *list);

/*!
 * \brief Create an iterator to iterate over the given list. The iterator begins
 * by pointing to before the first element in the list.
 *
 * \param list The list to iterate over.
 * \param[out] iter Receives the address of the new iterator.
 * \return ::GOLLE_OK if the iterator was created. ::GOLLE_EMEM if the iterator
 * could't be allocated. ::GOLLE_ERROR if \p list or \p iter is NULL.
 */
GOLLE_EXTERN golle_error golle_list_iterator (golle_list_t *list,
					      golle_list_iterator_t **iter);


/*!
 * \brief Free any resources associated with an iterator.
 * \param iter The iterator to free.
 */
GOLLE_EXTERN void golle_list_iterator_free (golle_list_iterator_t *iter);

/*!
 * \brief Get the next value of the iterator.
 * \param iter The iterator.
 * \param[out] item Is populated with the next item pointed to by the iterator.
 * \return ::GOLLE_OK if the operation was successful. 
 * ::GOLLE_ERROR if \p iter or
 *  \p value is NULL. ::GOLLE_END if the iterator is at the end of the list.
 *
 * \warning The returned pointer is the address of the item in the list. 
 *  Be wary.
 */
GOLLE_EXTERN golle_error golle_list_iterator_next (golle_list_iterator_t *iter,
						   void **item);

/*!
 * \brief Set the iterator back to its initial state.
 * \param iter The iterator to rest.
 * \return ::GOLLE_OK if the operation was successful. ::GOLLE_ERROR if \p iter
 * is NULL.
 */
GOLLE_EXTERN golle_error golle_list_iterator_reset (golle_list_iterator_t *iter);

/*!
 * \brief Insert an item into the list at the given location.
 * If the operation is successful, a call to golle_list_iterator_next
 * with the given iter parameter will return the inserted item.
 *
 * \param iter The location to insert the item at. The item will be inserted
 * just after the node that iter currently points to. If iter is in its
 * initial state, the item will be prepended. If iter is at the end of the
 * list, the item will be appended.
 *
 * \param item The item to insert into the list.
 * \param size The size of item.
 *
 * \return ::GOLLE_OK if the operation was successful. ::GOLLE_EMEM if the
 * new element couldn't be allocated. ::GOLLE_ERROR if \p iter is NULL.
 */
GOLLE_EXTERN golle_error golle_list_insert_at (golle_list_iterator_t *iter,
					       const void *item,
					       size_t size);

/*!
 * \brief Erase the item at the given position. If the operation is successful,
 * a call to golle_list_iterator_next with the same iter parameter will return
 * the item that previously came after the removed item (i.e. the iterator is
 * set to the item that preceeds the removed item.)
 *
 * \param iter The location to remove an item from.
 *
 * \return ::GOLLE_OK if the operation was successful. ::GOLLE_ENOTFOUND if the
 * iterator is not pointing to an element (it is at the very start or very
 * end of the list). ::GOLLE_ERROR if \p iter is NULL.
 */
GOLLE_EXTERN golle_error golle_list_erase_at (golle_list_iterator_t *iter);

/*!
 *@}
 */

GOLLE_END_C

#endif
