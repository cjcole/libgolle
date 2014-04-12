/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/bin.h>
#if HAVE_STRING_H
#include <string.h>
#endif

#define BIN_LOCAL(b) (((char *)b) + sizeof (golle_bin_t))

golle_bin_t *golle_bin_new (size_t size) {
  golle_bin_t *bin = malloc (size + sizeof (*bin));

  if (!bin) {
    return NULL;
  }

  bin->size = size;
  bin->bin = BIN_LOCAL(bin);

  return bin;
}


void golle_bin_delete (golle_bin_t *buff) {
  if (!buff)
    return;

  if (buff->bin != NULL &&
      buff->bin != BIN_LOCAL (buff)) {
    free (buff->bin);
  }
  free (buff);
}


golle_bin_t *golle_bin_copy (golle_bin_t *buff) {
  golle_bin_t *copy = NULL;

  if (buff && buff->bin) {
    copy = golle_bin_new (buff->size);
  }
  if (copy) {
    memcpy (copy->bin, buff->bin, buff->size);
  }

  return copy;
}
