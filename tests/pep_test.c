/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <assert.h>
#include <golle/schnorr.h>
#include <golle/distribute.h>
#include <golle/pep.h>
#include <limits.h>
#include <stdlib.h>
#include <time.h>
#include <golle/random.h>
#include <golle/elgamal.h>
#include <openssl/bn.h>
#include <stdio.h>

#define STR(N) #N

#define PRN(N) \
  printf ("%s = ", STR(N)); \
  golle_num_print (stdout, N); \
  printf ("\n")

enum {
  NUM_BITS = 16
};

int main (void) {
  srand (time (0));

  /* Generate an ElGamal key */
  golle_key_t key = { 0 };
  assert (golle_key_gen_public (&key, NUM_BITS, INT_MAX) == GOLLE_OK);
  assert (golle_key_gen_private (&key) == GOLLE_OK);
  PRN (key.g);
  PRN (key.q);
  PRN (key.h);

  /* Create a random value to encrypt. */
  golle_num_t v = golle_num_new_int (rand ());
  assert (v);
  assert (golle_num_mod_exp (v, key.g, v, key.q) == GOLLE_OK);
  PRN (v);
  
  /* Encrypt it twice */
  golle_eg_t e1 = { 0 }, e2 = { 0 };
  golle_num_t r1 = NULL, r2 = NULL;
  assert (golle_eg_encrypt (&key, v, &e1, &r1) == GOLLE_OK);
  assert (golle_eg_encrypt (&key, v, &e2, &r2) == GOLLE_OK);
  PRN(e1.a);
  PRN(e1.b);
  PRN(r1);
  PRN(e2.a);
  PRN(e2.b);
  PRN(r2);
  
  /* Compute the Schnorr key (Y, G) */
  golle_schnorr_t sk = { 0 };
  assert (golle_pep_set (&key, &e1, r1, &e2, r2, &sk) == GOLLE_OK);
  PRN (sk.G);
  PRN (sk.Y);
  PRN (sk.x);

  /* Commit to proving that we know x. */
  golle_num_t r = golle_num_new ();
  assert (r);
  golle_num_t t = golle_num_new ();
  assert (t);
  assert (golle_schnorr_commit (&sk, r, t) == GOLLE_OK);
  PRN (t);
  PRN (r);

  /* Verifier responds with challenge */
  golle_num_t c = golle_num_rand (sk.q);
  assert (c);
  PRN (c);

  /* Prover outputs proof */
  golle_num_t s = golle_num_new ();
  assert (s);
  assert (golle_schnorr_prove (&sk, s, r, c) == GOLLE_OK);
  PRN (s);

  /* Verifier checks the proof */
  assert (golle_schnorr_verify (&sk, s, t, c) == GOLLE_OK);
  
  golle_num_delete (v);
  golle_num_delete (r);
  golle_num_delete (t);
  golle_num_delete (c);
  golle_num_delete (s);
  golle_num_delete (r1);
  golle_num_delete (r2);
  golle_schnorr_clear (&sk);
  golle_key_clear (&key);
  golle_random_clear ();

  return 0;
}
