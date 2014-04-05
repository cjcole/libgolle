/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_SRC_ALIGN_H
#define LIBGOLLE_SRC_ALIGN_H

#include "golle/platform.h"
#include <stddef.h>

#define DEFAULT_ALIGN sizeof (size_t) /* be pessimistic */


GOLLE_INLINE size_t golle_align_to (size_t size, size_t target) {
  size_t mod = size % target;
  if (mod) {
    size += target - mod;
  }
  return size;
}


#define GOLLE_ALIGN(a) golle_align_to ((a), DEFAULT_ALIGN)

#endif
