/*
 * Copyright (C) Anthony Arnold 2014
 */


#include <golle/distribute.h>
#include <golle/elgamal.h>
#include <golle/random.h>
#include <assert.h>
#include <limits.h>

enum {
  MSG_SIZE = 8,
  NUM_BITS = 16 /* Doing smaller key for speed */
};

int main (void) {
  golle_key_t key = { 0 };
  golle_eg_t cipher = { 0 };
  assert (golle_key_gen_public (&key, NUM_BITS, INT_MAX) == GOLLE_OK);
  assert (golle_key_gen_private (&key) == GOLLE_OK);

  /* Make a random number */
  golle_bin_t orig;
  assert (golle_bin_init (&orig, MSG_SIZE) == GOLLE_OK);
  assert (golle_random_generate (&orig) == GOLLE_OK);
  golle_num_t n = golle_num_new ();
  assert (n);
  assert (golle_bin_to_num (&orig, n) == GOLLE_OK);

  /* m must be in G */
  golle_num_t m = golle_num_new ();
  assert (m);
  assert (golle_num_mod_exp (m, key.g, n, key.q) == GOLLE_OK);

  /* Encrypt */
  golle_num_t a, b, r = NULL;
  assert (a = golle_num_new ());
  assert (b = golle_num_new ());
  assert (golle_eg_encrypt (&key, m, &cipher, &r) == GOLLE_OK);

  /* Decrypt */
  golle_num_t p = golle_num_new ();
  assert (p);
  assert (golle_eg_decrypt (&key, &key.x, 1, &cipher, p) == GOLLE_OK);

  /* Are they the same? */
  assert (golle_num_cmp (m, p) == 0);

  golle_eg_clear (&cipher);
  golle_num_delete (p);
  golle_num_delete (n);
  golle_num_delete (m);
  golle_num_delete (r);
  golle_bin_release (&orig);
  golle_key_cleanup (&key);
  golle_random_clear ();
  return 0;
}
