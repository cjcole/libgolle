/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/bin.h>
#include <golle/errors.h>
#include <golle/platform.h>

#if GOLLE_WINDOWS
#include <Ntsecapi.h>

#if GOLLE_MSC
#pragma comment(lib, "Advapi32.lib")
#endif

#else /* Everyone else read from /dev/[u]random */

#include <stdio.h>

enum {
  /* Read in smaller blocks. */
  RAND_BLOCK_SIZE = 128
};

#endif


/* Forward declaration. Platform-specific is down below. */
static golle_error rand_gen_impl (size_t len, void *buf);


golle_error golle_random_generate (golle_bin_t *buffer) {
  GOLLE_ASSERT (buffer, GOLLE_ERROR);
  return rand_gen_impl (buffer->size, buffer->bin);
}



#if GOLLE_WINDOWS
static golle_error rand_gen_impl (size_t len, void *buf) {
    GOLLE_ASSERT (RtlGenRandom (buf, len), GOLLE_ECRYPTO);
    return GOLLE_OK;
}
#else
static golle_error rand_gen_impl (size_t len, void *buf) {
  /* Prefer urandom */
  FILE *fp = fopen ("/dev/urandom", "r");

  if (!fp) {
    /* OK, use /dev/random */
    fp = fopen ("/dev/random", "r");
  }

  GOLLE_ASSERT (fp, GOLLE_EFILE);

  size_t data_read = 0;
  while (data_read < len) {
    size_t toread = len - data_read;
    if (toread > RAND_BLOCK_SIZE) {
      toread = RAND_BLOCK_SIZE;
    }

    size_t result = fread ((char *)buf + data_read, 1, toread, fp);
    if (result == 0) {
      break;
    }

    data_read += result;
  }

  fclose (fp);
  GOLLE_ASSERT (data_read >= len, GOLLE_EFILE);

  return GOLLE_OK;
}
#endif
