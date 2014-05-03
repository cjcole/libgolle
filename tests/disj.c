/*
 * Copyright (C) Anthony Arnold 2014
 */
#include <golle/numbers.h>
#include <golle/disj.h>
#include <golle/elgamal.h>
#include <golle/schnorr.h>
#include <openssl/bn.h>
#include <limits.h>
#include <assert.h>

enum {
  NUM_BITS = 160
};

static void copy_eg_key (const golle_key_t *src, golle_key_t *dest) {
  assert (dest->p = golle_num_dup (src->p));
  assert (dest->q = golle_num_dup (src->q));
  assert (dest->g = golle_num_new ());
  assert (golle_find_generator (dest->g, dest->p, dest->q, INT_MAX) == GOLLE_OK);
}

static void make_schnorr_key (const golle_key_t *key,
			      golle_schnorr_t *sk)
{
  sk->Y = golle_num_dup (key->h_product);
  assert (sk->Y);
  sk->G = golle_num_dup (key->g);
  assert (sk->G);
  sk->x = golle_num_dup (key->x);
  assert (sk->x);
  sk->q = golle_num_dup (key->q);
  assert (sk->q);
  sk->p = golle_num_dup (key->p);
  assert (sk->p);
}

int main (void) {
  /* Generate two ElGamal keys using the same p, q values */
  golle_key_t key1 = { 0 }, key2 = { 0 };
  assert (golle_key_gen_public (&key1, NUM_BITS, INT_MAX) == GOLLE_OK);
  assert (golle_key_gen_private (&key1) == GOLLE_OK);
  
  copy_eg_key (&key1, &key2);
  assert (golle_key_gen_private (&key2) == GOLLE_OK);

  /* Compute the Schnorr Keys */
  golle_schnorr_t sk1 = { 0 }, sk2 = { 0 };
  make_schnorr_key (&key1, &sk1);
  make_schnorr_key (&key2, &sk2);

  /* Commit to proving that we know one of the private keys.
     We'll arbitrarily choose the first one. */
  golle_disj_t d = { 0 };
  assert (golle_disj_commit (&sk2, &sk1, &d) == GOLLE_OK);
  
  /* Verifier responds with challenge */
  golle_num_t c = golle_num_rand (key2.q);
  assert (c);

  /* Prover outputs proof */
  assert (golle_disj_prove (&sk2, &sk1, c, &d) == GOLLE_OK);

  /* Verifier checks. */
  assert (golle_disj_verify (&sk1, &sk2, &d) == GOLLE_OK);

  /* Ensure that we can't cheat if we don't know one of the xs */
  /* Dummy-up a new key that we "don't know". i.e., all of the
     other parameters are based on a different key.
  */
  assert (golle_num_generate_rand (sk1.x, sk1.q) == GOLLE_OK);
  assert (golle_disj_commit (&sk2, &sk1, &d) == GOLLE_OK);
  assert (golle_disj_prove (&sk2, &sk1, c, &d) == GOLLE_OK);
  assert (golle_disj_verify (&sk1, &sk2, &d) == GOLLE_ECRYPTO);

  /* Cleanup */
  golle_num_delete (c);
  golle_schnorr_clear (&sk1);
  golle_schnorr_clear (&sk2);
  golle_key_clear (&key1);
  golle_key_clear (&key2);
  golle_disj_clear (&d);
  return 0;
}
