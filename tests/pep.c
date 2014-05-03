/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <assert.h>
#include <golle/schnorr.h>
#include <golle/distribute.h>
#include <golle/pep.h>
#include <limits.h>
#include <golle/random.h>
#include <golle/elgamal.h>
#include <openssl/bn.h>

enum {
  NUM_BITS = 160
};

int main (void) {

  /* Generate an ElGamal key */
  golle_key_t key = { 0 };
  assert (golle_key_gen_public (&key, NUM_BITS, INT_MAX) == GOLLE_OK);
  assert (golle_key_gen_private (&key) == GOLLE_OK);

  /* Create a random value to encrypt. */
  golle_num_t v = golle_num_rand (key.q);
  assert (v);
  assert (golle_num_mod_exp (v, key.g, v, key.q) == GOLLE_OK);
  
  /* Encrypt it twice with the same public key.
   Save the random value used for reencryption. */
  golle_eg_t e1 = { 0 }, e2 = { 0 };
  golle_num_t k = NULL;
  assert (golle_eg_encrypt (&key, v, &e1, NULL) == GOLLE_OK);
  assert (golle_eg_reencrypt (&key, &e1, &e2, &k) == GOLLE_OK);
  
  /* Verifier picks a random number z */
  golle_num_t z = golle_num_rand (key.q);
  assert (z);
  assert (golle_num_mod_exp (z, key.g, z, key.q) == GOLLE_OK);

  /* Compute the Schnorr key (Y, G) */
  golle_schnorr_t skp = { 0 }, skv = { 0 };
  /*  assert (golle_pep_verifier (&key, z, &e1, &e2, &skp) == GOLLE_OK);*/
  assert (golle_pep_prover (&key, k, z, &skp) == GOLLE_OK); 
  assert (golle_pep_verifier (&key, z, &e1, &e2, &skv) == GOLLE_OK);

  /* Commit to proving that we know x.
     That is, we're proving that the two encryptions are
     of the same plaintext. */
  golle_num_t r = golle_num_new ();
  assert (r);
  golle_num_t t = golle_num_new ();
  assert (t);
  assert (golle_schnorr_commit (&skp, r, t) == GOLLE_OK);

  /* Verifier responds with challenge */
  golle_num_t c = golle_num_rand (key.q);
  assert (c);

  /* Prover outputs proof */
  golle_num_t s = golle_num_new ();
  assert (s);
  assert (golle_schnorr_prove (&skp, s, r, c) == GOLLE_OK);

  /* Verifier checks the proof */
  assert (golle_schnorr_verify (&skv, s, t, c) == GOLLE_OK);

  golle_num_delete (z);
  golle_num_delete (v);
  golle_num_delete (r);
  golle_num_delete (t);
  golle_num_delete (c);
  golle_num_delete (s);
  golle_num_delete (k);
  golle_schnorr_clear (&skp);
  golle_schnorr_clear (&skv);
  golle_key_clear (&key);
  golle_eg_clear (&e1);
  golle_eg_clear (&e2);
  golle_random_clear ();

  return 0;
}
