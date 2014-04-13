/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_RANDOM_H
#define LIBGOLLE_RANDOM_H

#include "bin.h"
#include "errors.h"
#include "platform.h"

/*!
 * \file golle/random.h
 * \author Anthony Arnold
 * \copyright MIT License
 * \date 2014
 * \brief Wrapper functions for collecting random data.
 */

/*!
 * \defgroup random Random Data
 * @{
 * Functions provide wrappers around OpenSSL's
 * random data generation functions. The
 * golle_random_seed() function will attempt to
 * set up a hardware random number generator if
 * one is available.
 *
 * A well-behaved application will call golle_random_clear()
 * before exiting.
 */

/*!
 * \brief Seed the system's random generator.
 * \return GOLLE_OK or GOLLE_ERROR.
 */
GOLLE_EXTERN golle_error golle_random_seed ();

/*!
 * \brief Fill the buffer with random data.
 * \param buffer A buffer to be filled. The `bin` part will be filled
 * with `size` bytes.
 * \return GOLLE_ERROR or GOLLE_OK.
 */
GOLLE_EXTERN golle_error golle_random_generate (golle_bin_t *buffer);

/*!
 * \brief Safely destroy the random state. This function
 * should be called before application exit.
 * \return Always returns GOLLE_OK.
 */
GOLLE_EXTERN golle_error golle_random_clear ();

/*!
 * @}
 */

#endif

