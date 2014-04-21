/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/bin.h>
#if HAVE_STRING_H
#include <string.h>
#endif

/* Safely clear a buffer's memory */
#define CLEAR_BUFF(b) \
  do { if ((b)->bin) { memset ((b)->bin, 0, (b)->size); } } while (0)

/* Determine the address of a local buffer
 * if allocated with golle_bin_new() */
#define BIN_LOCAL(b) (((char *)b) + sizeof (golle_bin_t))

golle_error golle_bin_init (golle_bin_t *buff, size_t size) {
  /* Allocate data an existing buffer. */
  GOLLE_ASSERT (buff, GOLLE_ERROR);
  buff->bin = malloc (size);
  GOLLE_ASSERT (buff->bin, GOLLE_EMEM);
  buff->size = size;
  return GOLLE_OK;
}

void golle_bin_release (golle_bin_t *buff) {
  if (buff && buff->bin) {
    /* Zeroing memory is safer. */
    CLEAR_BUFF (buff);
    free (buff->bin);
  }
}

golle_bin_t *golle_bin_new (size_t size) {
  /* Allocate enough room for the
   * bin object and the data buffer in one.
   */
  golle_bin_t *bin = malloc (size + sizeof (*bin));
  GOLLE_ASSERT (bin, NULL);

  /* The data is part of the bin memory block. */
  bin->size = size;
  bin->bin = BIN_LOCAL(bin);
  CLEAR_BUFF (bin);
  
  return bin;
}

void golle_bin_delete (golle_bin_t *buff) {
  if (!buff)
    return;

  /* Always zero to be safe. */
  CLEAR_BUFF (buff);

  if (buff->bin != NULL &&
      buff->bin != BIN_LOCAL (buff)) 
    {
      /* Only free the data individually if
       * it wasn't allocated as part of the bin. */
      free (buff->bin);
    }
  free (buff);
}

golle_bin_t *golle_bin_copy (const golle_bin_t *buff) {
  golle_bin_t *copy = NULL;

  if (buff && buff->bin) {
    /* Allocate a new buffer */
    copy = golle_bin_new (buff->size);
  }
  if (copy) {
    memcpy (copy->bin, buff->bin, buff->size);
  }

  return copy;
}

golle_error golle_bin_resize (golle_bin_t *buff, size_t size) {
  GOLLE_ASSERT (buff, GOLLE_ERROR);
  GOLLE_ASSERT (size, GOLLE_ERROR);
  /*
   * This function is essentially a 
   * realloc for buffers.
   */

  if (buff->bin == BIN_LOCAL (buff)) {
    /* force a malloc */
    buff->bin = NULL;
  }

  void * newbin = realloc (buff->bin, size);
  GOLLE_ASSERT (newbin, GOLLE_EMEM);

  buff->bin = newbin;
  buff->size = size;
  return GOLLE_OK;
}
