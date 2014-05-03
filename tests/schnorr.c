/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <assert.h>
#include <golle/schnorr.h>
#include <golle/distribute.h>
#include <limits.h>
#include <golle/random.h>
#include <golle/elgamal.h>
#include <stdio.h>
#include <openssl/bn.h>

enum {
  NUM_BITS = 256
};

int main (void) {
  /* Generate an ElGamal key */
  golle_key_t key = { 0 };
  assert (golle_key_gen_public (&key, NUM_BITS, INT_MAX) == GOLLE_OK);
  assert (golle_key_gen_private (&key) == GOLLE_OK);
  
  /* Compute the Schnorr key (Y, G) */
  golle_schnorr_t sk = { 0 };
  sk.Y = BN_dup (key.h_product);
  assert (sk.Y);
  sk.G = BN_dup (key.g);
  assert (sk.G);
  sk.x = BN_dup (key.x);
  assert (sk.x);
  sk.q = BN_dup (key.q);
  assert (sk.q);
  sk.p = BN_dup (key.p);
  assert (sk.p);

  /* Commit to proving that we know the private key. */
  golle_num_t r = golle_num_new ();
  assert (r);
  golle_num_t t = golle_num_new ();
  assert (t);
  assert (golle_schnorr_commit (&sk, r, t) == GOLLE_OK);

  /* Verifier responds with challenge */
  golle_num_t c = golle_num_rand (sk.q);
  assert (c);

  /* Prover outputs proof */
  golle_num_t s = golle_num_new ();
  assert (s);
  assert (golle_schnorr_prove (&sk, s, r, c) == GOLLE_OK);

  /* Verifier checks the proof */
  assert (golle_schnorr_verify (&sk, s, t, c) == GOLLE_OK);

  /* Check that we can't cheat. */
  do {
    /* Set a bad x */
    assert (golle_num_generate_rand (sk.x, sk.q) == GOLLE_OK);
  } while (BN_cmp (sk.x, key.x) == 0);
  
  /* Commit to proving that we 'know' x. */
  assert (golle_schnorr_commit (&sk, r, t) == GOLLE_OK);
  /* reuse c, it's OK */
  assert (golle_schnorr_prove (&sk, s, r, c) == GOLLE_OK);
  /* Make sure this doesn't get through */
  assert (golle_schnorr_verify (&sk, s, t, c) == GOLLE_ECRYPTO);

  golle_num_delete (r);
  golle_num_delete (t);
  golle_num_delete (c);
  golle_num_delete (s);
  golle_random_clear ();
  golle_key_clear (&key);
  golle_schnorr_clear (&sk);

  return 0;
}
