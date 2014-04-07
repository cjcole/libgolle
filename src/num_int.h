/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_SRC_NUM_DEF_H
#define LIBGOLLE_SRC_NUM_DEF_H

#include "config.h"

#if !defined(uintmax_t) 
#if HAVE_STDINT_H
#include <stdint.h>
#elif HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#endif

typedef uintmax_t golle_int_t [1];

#endif
