/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_ERRORS_H
#define LIBGOLLE_ERRORS_H

#include "platform.h"

GOLLE_BEGIN_C

/*!
 * \file golle/errors.h
 * \brief Error constants
 */

/*!
 * Error codes and return values.
 */
typedef enum golle_error {
  GOLLE_OK = 0, /*!< Success */

  GOLLE_ERROR = -1, /*!< General error code. */
  GOLLE_EMEM = -2, /*!< Out of memory or resources. */
  GOLLE_EEXISTS = -3, /*!< The specified element already exists. */
  GOLLE_ENOTFOUND = -4, /*!< The specified element does not exist. */
  GOLLE_EEMPTY = -5, /*!< The container has no elements. */
  GOLLE_EOUTOFRANGE = -6, /*!< The given size or index is invalid. */
  GOLLE_ETOOFEW = -7, /*!< There are not enough elements available. */
  GOLLE_EINVALID = -8, /*!< Requested an invalid operation. */
  GOLLE_ENOTPRIME = -9, /*!< The given number failed the test for primality. */
  GOLLE_ENOCOMMIT = -10, /*!< The given commitment failed. */
  GOLLE_ECRYPTO = -11, /*!< An error occurred during cryptography. */
  GOLLE_EABORT = -12, /*!< The operation should abort. */

  GOLLE_END = 1, /*!< An iterator has reached the end of a sequence. */
 
  GOLLE_COMMIT_PASSED = 1, /*!< Bit commitment verification passed. */
  GOLLE_COMMIT_FAILED = 0, /*!< Bit commitment verification failed. */

  GOLLE_PROBABLY_PRIME = 1, /*!< The number has passed the primality test. */
  GOLLE_NOT_PRIME = 0 /*!< The number is definitely not prime. */

} golle_error;


/*!
 * A shorthand way of stating assertions.
 * Only use inside a function which returns non-void.
 */
#define GOLLE_ASSERT(x,r) do { if ((x) == 0) { return (r); } } while(0)

/*!
 * Avoid compile-time warnings about unused parameters.
 */
#define GOLLE_UNUSED(x) (void)(x)

GOLLE_END_C

#endif
