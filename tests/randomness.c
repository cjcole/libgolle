/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/random.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* This is not a randomness test. It is simply a test that the random
   functions behave correctly on your system (i.e. it generates SOMETHING
   that your system deems random.
*/

enum {
  DATA_SIZE = 4096
};

int main (void) {
  golle_bin_t buff;

  buff.size = DATA_SIZE;
  buff.bin = malloc (DATA_SIZE * 2);

  assert (buff.bin);
  memset (buff.bin, 0, DATA_SIZE * 2);

  golle_error err = golle_random_generate (&buff);
  if (err) {
    goto out;
  }

  err = memcmp (buff.bin, (char*)buff.bin + DATA_SIZE, DATA_SIZE);
  err = err == 0;
  free (buff.bin);
  golle_random_clear ();
 out:
  return err;
}
