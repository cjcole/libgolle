/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_TYPES_H
#define LIBGOLLE_TYPES_H


/*
 * \file golle/types.h
 * \author Anthony Arnold
 * \copyright MIT License
 * \date 2014
 * \brief Include for commonly-used types and functions.
 */

#include "config.h"

#if !defined(size_t) 
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#elif HAVE_STDLIB_H
#include <stdlib.h>
#endif
#endif

#if !defined(uintmax_t)
#if HAVE_STDINT_H
#include <stdint.h>
#elif HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#endif

#if !defined (malloc)
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#endif

#endif
