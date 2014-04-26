/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <assert.h>
#include <golle/schnorr.h>
#include <golle/distribute.h>
#include <limits.h>
#include <stdlib.h>
#include <time.h>
#include <golle/random.h>
#include <golle/elgamal.h>
#include <stdio.h>
#include <openssl/bn.h>

enum {
  NUM_BITS = 160
};

#define STR(S) #S
#define PRN(N) prn(STR(N), N)

static void prn (const char *id, const golle_num_t n) {
  printf ("%s = 0x", id);
  golle_num_print (stdout, n);
  printf ("\n");
}

int main (void) {
  srand (time (0));

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

  PRN (sk.G);
  PRN (sk.Y);
  PRN (sk.p);
  PRN (sk.q);
  PRN (sk.x);

  /* Commit to proving that we know the private key. */
  golle_num_t r = golle_num_new ();
  assert (r);
  golle_num_t t = golle_num_new ();
  assert (t);
  assert (golle_schnorr_commit (&sk, r, t) == GOLLE_OK);
  PRN(r);

  /* Verifier responds with challenge */
  golle_num_t c = golle_num_rand (key.q);
  assert (c);
  PRN(c);

  /* Prover outputs proof */
  golle_num_t s = golle_num_new ();
  assert (s);
  assert (golle_schnorr_prove (&sk, s, r, c) == GOLLE_OK);
  PRN(s);

  /* Verifier checks the proof */
  assert (golle_schnorr_verify (&sk, s, t, c) == GOLLE_OK);
  
  golle_num_delete (r);
  golle_num_delete (t);
  golle_num_delete (c);
  golle_num_delete (s);
  golle_random_clear ();
  golle_key_clear (&key);
  golle_schnorr_clear (&sk);

  return 0;
}
