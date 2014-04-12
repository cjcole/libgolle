/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/bin.h>
#include <string.h>
#include <assert.h>

enum {
  BUFFER_SIZE = 1024 /* 1KB */
};


int main () {
  golle_bin_t *buffer = golle_bin_new (BUFFER_SIZE);

  assert (buffer);
  assert (buffer->size == BUFFER_SIZE);

  golle_bin_t *copy = golle_bin_copy (buffer);
  assert (copy);
  assert (copy->size == buffer->size);
  assert (memcmp (copy->bin, buffer->bin, buffer->size) == 0);

  golle_bin_delete (buffer);
  golle_bin_delete (copy);
}
