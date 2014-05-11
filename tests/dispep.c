/*
 * Copyright (C) Anthony Arnold 2014
 */
#include <golle/numbers.h>
#include <golle/distribute.h>
#include <golle/disj.h>
#include <golle/dispep.h>
#include <limits.h>
#include <assert.h>

enum {
  NUM_BITS = 160
};

int main(void) {
  /* Generate an ElGamal key */
  golle_key_t key = { 0 };
  assert (golle_key_gen_public (&key, NUM_BITS, INT_MAX) == GOLLE_OK);
  assert (golle_key_gen_private (&key) == GOLLE_OK);

  /* Get two random values to encrypt */
  golle_num_t r1 = golle_num_rand (key.p);
  assert (r1);
  golle_num_t r2 = golle_num_rand (key.p);
  assert (r2);
  assert (golle_num_mod_exp (r1, key.g, r1, key.q) == GOLLE_OK);
  assert (golle_num_mod_exp (r2, key.g, r2, key.q) == GOLLE_OK);

  /* Encrypt the first value */
  golle_eg_t r = { 0 };
  assert (golle_eg_encrypt (&key, r1, &r, NULL) == GOLLE_OK);

  /* Re-encrypt the value. */
  golle_eg_t re = { 0 };
  assert (golle_eg_reencrypt (&key, &r, &re, NULL) == GOLLE_OK);

  /* Encrypt the second value */
  golle_eg_t s = { 0 };
  assert (golle_eg_encrypt (&key, r2, &s, NULL) == GOLLE_OK);

  /* Compute the Schnorr Keys */
  golle_schnorr_t sk1 = { 0 }, sk2 = { 0 };
  assert (golle_dispep_setup (&r, &re, &s, &sk1, &sk2, &key) == GOLLE_OK);

  /* Commit to proving that re is a re-encryption of ONE OF the other
   ciphertext. In this case we arbitrarily chose the first. */
  golle_disj_t d = { 0 };
  assert (golle_disj_commit (&sk2, &sk1, &d) == GOLLE_OK);
  
  /* Verifier responds with challenge */
  golle_num_t c = golle_num_rand (key.q);
  assert (c);

  /* Prover outputs proof */
  assert (golle_disj_prove (&sk2, &sk1, c, &d) == GOLLE_OK);

  /* Verifier checks. */
  assert (golle_disj_verify (&sk1, &sk2, &d) == GOLLE_OK);

  /* Cleanup */
  golle_num_delete (r1);
  golle_num_delete (r2);
  golle_eg_clear (&re);
  golle_eg_clear (&r);
  golle_eg_clear (&s);
  golle_schnorr_clear (&sk1);
  golle_schnorr_clear (&sk2);
  golle_key_clear (&key);
  golle_disj_clear (&d);
}
