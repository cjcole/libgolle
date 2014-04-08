/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_BIN_H
#define LIBGOLLE_BIN_H

#include "config.h"
#include "types.h"

/*!
 * \file golle/bin.h
 * \author Anthony Arnold
 * \copyright MIT License
 * \date 2014
 * \brief Defines a structure for a binary buffer.
 */

/*!
 * \defgroup bin Binary buffers
 * @{
 */

/*!
 * \struct golle_bin_t
 * Represents a binary buffer.
 */
typedef struct golle_bin_t {
  void *bin; /*!< Binary bytes. */
  size_t size; /*!< Size, in bytes, of bin. */
} golle_bin_t;

/*!
 * @}
 */

#endif
