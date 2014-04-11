/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_SRC_RANDOM_H
#define LIBGOLLE_SRC_RANDOM_H

#include <golle/bin.h>
#include <golle/errors.h>

/*
 * Seed the system's random generator.
 */
extern golle_error golle_random_seed ();

/*
 * Fill the buffer with random data.
 */
extern golle_error golle_random_generate (golle_bin_t *buffer);

/*
 * Safely destroy the random state.
 */
extern golle_error golle_random_clear ();

#endif

