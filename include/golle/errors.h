/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_ERRORS_H
#define LIBGOLLE_ERRORS_H

/*!
 * \file golle/errors.h
 * \brief Error constants
 */

/*!
 * Return values.
 */
typedef enum {
  GOLLE_OK = 0, /*< Success */

  GOLLE_ERROR = -1, /*< General error code. */
  GOLLE_EMEM = -2, /*< Out of memory or resources. */
  GOLLE_EEXISTS = -3, /*< The specified element already exists. */
  GOLLE_ENOTFOUND = -4, /*< The specified element does not exist. */
  GOLLE_EEMPTY = -5, /*< The container has no elements. */

  GOLLE_END = 1 /*< Indicates an iterator has reached the end of a sequence. */

} golle_error;

/*!
 * A shorthand way of stating assertions.
 * Only use inside a function which returns a golle_error.
 */
#define GOLLE_ASSERT(x,r) do { if ((x) == 0) { return (r); } } while(0)

#endif
