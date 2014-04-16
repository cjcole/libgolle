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

  assert (golle_bin_resize (buffer, buffer->size * 2) == GOLLE_OK);
  assert (buffer->size == BUFFER_SIZE * 2);

  golle_bin_delete (buffer);
  golle_bin_delete (copy);

  golle_bin_t local;
  assert (golle_bin_init (&local, BUFFER_SIZE) == GOLLE_OK);
  assert (local.bin);
  assert (local.size == BUFFER_SIZE);
  golle_bin_release (&local);
}
