/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_BIN_H
#define LIBGOLLE_BIN_H

#include "types.h"
#include "platform.h"

/*!
 * \file golle/bin.h
 * \author Anthony Arnold
 * \copyright MIT License
 * \date 2014
 * \brief Defines a structure for a binary buffer.
 *
 * It is best to use the ::golle_bin_t struct in two distinct ways.
 * Either allocate your own buffer and then assign the `bin` and `size`
 * members of the struct yourself (ensuring that `size` is correct) and
 * then free the buffer yourself. Or,
 * use the ::golle_bin_new and ::golle_bin_delete functions to handle
 * the allocation and deallocation for you. Mixing these two techniques
 * _could_ lead to problems, even though the ::golle_bin_delete function
 * is defined to try to detect such problems.
 */

/*!
 * \defgroup bin Binary buffers
 * @{
 */

/*!
 * \struct golle_bin_t
 * Represents a binary buffer.
 *
 * \warning You can fill in the values of this structure if
 * necessary, but use the ::golle_bin_create function
 * whenever possible to avoid disparity between the `size`
 * member and the allocated size of `bin`.
 */
typedef struct golle_bin_t {
  size_t size; /*!< Size, in bytes, of bin. */
  void *bin; /*!< Binary bytes. */
} golle_bin_t;


/*!
 * \brief Create a new binary buffer of a given size.
 * \param size The size of the buffer to allocate.
 * \return The allocated buffer, or NULL if allocation failed.
 * \note This function only performs one `malloc`. It allocates
 * enough space for the structure _and_ the `bin` data itself.
 * The returned object's `bin` member will point to the address
 * just after the object.
 * \warning Do no independantly `free` the `bin` member of a
 * ::golle_bin_t structure allocated with this function.
 * `free` the whole structure or, even better, call
 * ::golle_bin_delete. 
 * 
 * It is not usually a good idea to
 * set the members of a structure returned by this function.
 */
GOLLE_EXTERN golle_bin_t *golle_bin_new (size_t size);

/*!
 * \brief Deallocates resources held by a ::golle_bin_t structure.
 * \param buff The structure to free.
 * \note This function will check the address of the `bin` member
 * of `buff`. If it points to the address just passed the object,
 * it will free the object. If it points elsewhere, it will _also_ free
 * the `bin` member separately.
 */
GOLLE_EXTERN void golle_bin_delete (golle_bin_t *buff);

/*!
 * \brief Makes a copy of `buff` via ::golle_bin_new.
 * \param buff The buffer to copy.
 * \return A new buffer, or `NULL` if either buff was `NULL` or
 * if ::golle_bin_new returned `NULL`.
 * \note You should delete this copy with ::golle_bin_delete.
 */
GOLLE_EXTERN golle_bin_t *golle_bin_copy (golle_bin_t *buff);

/*!
 * @}
 */

#endif
