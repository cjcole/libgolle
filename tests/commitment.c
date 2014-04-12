/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/commit.h>
#include <golle/random.h>
#include <assert.h>

enum {
  SECRET_SIZE = 64
};

int main () {
  /* Bob has a secret. */
  golle_bin_t *bob_secret = golle_bin_new (64);
  assert (bob_secret);
  assert (golle_random_generate (bob_secret) == GOLLE_OK);


  /* He makes a commitment to the secret. */
  golle_commit_t *commitment = golle_commit_new (bob_secret);
  assert (commitment);

  /*
   * ....
   *
   * He sends one random value and the hash to Alice.
   *
   * ....
   */


  /* Alice stores them. */
  golle_commit_t alice_store;
  alice_store.hash = golle_bin_copy (commitment->hash);
  alice_store.rsend = golle_bin_copy (commitment->rsend);

  assert (alice_store.hash);
  assert (alice_store.rsend);


  /*
   * ...
   *
   * Bob now sends his secret and the other random value.
   * ...
   *
   */


  /* Alice stores them */
  alice_store.rkeep = golle_bin_copy (commitment->rkeep);
  alice_store.secret = golle_bin_copy (commitment->secret);
  /* You may want to also send hash and rsend, and verify that
   * they haven't changed.
   */

  /* She then verifies the hash */
  assert (golle_commit_verify (&alice_store) == GOLLE_COMMIT_PASSED);
  

  /* What happens if bob changed his secret? */
  assert (golle_random_generate (alice_store.secret) == GOLLE_OK);
  assert (golle_commit_verify (&alice_store) == GOLLE_COMMIT_FAILED);


  golle_commit_delete (commitment);
}
