/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/distribute.h>
#include <golle/peer.h>
#include <assert.h>
#include <limits.h>
#include <golle/random.h>

enum {
  NUM_BITS = 160
};

static golle_key_t SHARED_KEY = { 0 };

/*
 * Set shared key parts.
 */
static void set_shared_key (golle_peer_set_t *set) {
  assert (golle_peers_set_key (set, &SHARED_KEY) == GOLLE_OK);
  assert (golle_peers_get_state (set) == GOLLE_KEY_INCOMPLETE);
}

/* Add peers */
static void add_peers (golle_peer_set_t *set, 
		       golle_peer_t *p1, 
		       golle_peer_t *p2)
{
  assert (golle_peers_add (set, p1) == GOLLE_OK);
  assert (golle_peers_add (set, p2) == GOLLE_OK);
  assert (golle_peers_size (set) == 2);
}

/* Commit and send commitment to peer, then send h and confirm */
static void send_h (golle_peer_set_t *set,
		    golle_peer_set_t *peer,
		    golle_peer_t id)
{
  /* Get commitment */
  golle_commit_t *commit;
  assert (golle_peers_get_commitment (set, &commit) == GOLLE_OK);

  /* Send to peer */
  assert (golle_peers_commit (peer, id, commit->rsend, commit->hash) 
	  == GOLLE_OK);

  /* Verify with peer */
  assert (golle_peers_verify (peer, id, commit->rkeep, commit->secret)
	  == GOLLE_OK);

  assert (golle_peers_check_key (peer, id));
}

/*
 * This program is like the distribution test,
 * except it uses the peer set capabilities.
 */
int main (void) {
  /* Three peers, A,B,C */
  golle_peer_set_t *A, *B, *C;

  golle_peer_t
    A_b,
    A_c,
    B_a,
    B_c,
    C_a,
    C_b;

  /* Generate the keys. */
  assert (golle_key_gen_public (&SHARED_KEY,
				NUM_BITS,
				INT_MAX) == GOLLE_OK);

  /* Each peer creates a set and sets the shared key parts. */
  assert (A = golle_peers_new ());  
  assert (B = golle_peers_new ());  
  assert (C = golle_peers_new ());

  /* Add peers */
  add_peers (A, &A_b, &A_c);
  add_peers (B, &B_a, &B_c);
  add_peers (C, &C_a, &C_b);

  /* All three should have empty keys */
  assert (golle_peers_get_state (A) == GOLLE_KEY_EMPTY);
  assert (golle_peers_get_state (B) == GOLLE_KEY_EMPTY);
  assert (golle_peers_get_state (C) == GOLLE_KEY_EMPTY);

  /* Set the shared keys */
  set_shared_key (A);
  set_shared_key (B);
  set_shared_key (C);

  /* Commit and send commitment to peers */
  send_h (A, B, B_a);
  send_h (A, C, C_a);

  /* B & S should be incomplete */
  assert (golle_peers_get_state (B) == GOLLE_KEY_INCOMPLETE);
  assert (golle_peers_get_state (C) == GOLLE_KEY_INCOMPLETE);

  send_h (B, A, A_b);
  send_h (B, C, C_b);
  send_h (C, B, B_c);
  send_h (C, A, A_c);

  /* All three should now have full keys */
  assert (golle_peers_get_state (A) == GOLLE_KEY_READY);
  assert (golle_peers_get_state (B) == GOLLE_KEY_READY);
  assert (golle_peers_get_state (C) == GOLLE_KEY_READY);

  /* All thread should return valid keys */
  assert (golle_peers_get_key (A));
  assert (golle_peers_get_key (B));
  assert (golle_peers_get_key (C));

  /* Erase a peer and go back to incomplete (keey the p,q, and g terms. */
  assert (golle_peers_erase (A, A_b) == GOLLE_OK);
  assert (golle_peers_get_state (A) == GOLLE_KEY_INCOMPLETE);

  /* Set a NULL key and go back to empty */
  assert (golle_peers_set_key (A, NULL) == GOLLE_OK);
  assert (golle_peers_get_state (A) == GOLLE_KEY_EMPTY);

  /* ERRORS */
  assert (golle_peers_size (NULL) == 0);
  assert (golle_peers_add (NULL, NULL) == GOLLE_ERROR);
  assert (golle_peers_add (A, NULL) == GOLLE_ERROR);
  assert (golle_peers_erase (A, -1) == GOLLE_ENOTFOUND);
  assert (golle_peers_erase (NULL, 0) == GOLLE_ERROR);
  assert (golle_peers_set_key (NULL, NULL) == GOLLE_ERROR);
  golle_key_t fake = { 0 };
  assert (golle_peers_set_key (A, &fake) == GOLLE_EINVALID);
  assert (golle_peers_get_state (NULL) == GOLLE_KEY_UNDEFINED);
  assert (golle_peers_check_key (NULL, 0) == 0);
  assert (golle_peers_check_key (A, A_b) == 0);
  assert (golle_peers_commit (NULL, 0, NULL, NULL) == GOLLE_ERROR);
  golle_bin_t foo;
  assert (golle_peers_commit (A, -1, &foo, &foo) == GOLLE_EINVALID);
  assert (golle_peers_commit (A, A_c, NULL, NULL) == GOLLE_ERROR);
  assert (golle_peers_commit (A, A_c, &foo, NULL) == GOLLE_ERROR);
  assert (golle_peers_verify (NULL, 0, NULL, NULL) == GOLLE_ERROR);
  assert (golle_peers_verify (A, -1, &foo, &foo) == GOLLE_EINVALID);
  assert (golle_peers_verify (A, A_c, NULL, NULL) == GOLLE_ERROR);
  assert (golle_peers_verify (A, A_c, &foo, NULL) == GOLLE_ERROR);
  assert (golle_peers_get_key (NULL) == NULL);
  assert (golle_peers_get_commitment (NULL, NULL) == GOLLE_ERROR);
  assert (golle_peers_get_commitment (A, NULL) == GOLLE_ERROR);

  /* Clean up */
  golle_peers_delete (A);
  golle_peers_delete (B);
  golle_peers_delete (C);
  golle_key_clear (&SHARED_KEY);
  golle_random_clear ();

  return 0;
}
