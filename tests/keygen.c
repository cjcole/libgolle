/*
 * Copyright (C) Anthony Arnold 2014
 */


#include <golle/distribute.h>
#include <golle/random.h>
#include <assert.h>
#include <limits.h>

enum {
  NUM_BITS = 64 /* Just a small prime. */
};

int main () {
  golle_key_t key = { 0 };

  assert (golle_key_gen_public (&key, NUM_BITS, INT_MAX) == GOLLE_OK);

  assert (golle_test_prime (key.p) == GOLLE_PROBABLY_PRIME);
  assert (golle_test_prime (key.q) == GOLLE_PROBABLY_PRIME);

  golle_key_cleanup (&key);
  golle_random_clear ();
  return 0;
}
