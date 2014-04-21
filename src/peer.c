/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/peer.h>
#include <golle/numbers.h>
#include <golle/set.h>
#include <golle/config.h>
#include <assert.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif

typedef struct golle_peer_impl_t {
  golle_peer_t id;
  golle_num_t h;
  golle_commit_t commit;
} golle_peer_impl_t;

struct golle_peer_set_t {
  golle_set_t *peers;
  golle_peer_t next_id;
  golle_key_t key;
  golle_peer_key_state state;
  golle_commit_t *commit;
};

/*
 * Do an action for each peer in the set.
 */
typedef void (*each_peer_t) (golle_peer_impl_t *, void *);

static golle_error for_each_peer (golle_peer_set_t *set,
				  void *state,
				  each_peer_t cb) 
{
  /* Iterate over the whole set of peers */
  golle_set_iterator_t *iter;
  golle_error err = golle_set_iterator (set->peers, &iter);

  while (err == GOLLE_OK) {
    /* Get the next item as a binary buffer */
    const golle_bin_t *bin;
    err = golle_set_iterator_next (iter, &bin);
    if (err == GOLLE_OK) {
      /* Cast to a peer object then call the callback */
      golle_peer_impl_t *p = (golle_peer_impl_t *)bin->bin;
      cb (p, state);
    }
  }
  if (err == GOLLE_END) {
    err = GOLLE_OK;
  }
  golle_set_iterator_free (iter);
  return err;
}

/*
 * Compare two peers.
 */
static int compare_peers (const golle_bin_t *lhs, const golle_bin_t *rhs) {
  assert (lhs);
  assert (rhs);
  assert (lhs->bin);
  assert (rhs->bin);

  golle_peer_impl_t *left = (golle_peer_impl_t *)lhs->bin;
  golle_peer_impl_t *right = (golle_peer_impl_t *)rhs->bin;
  return left->id - right->id;
}

/*
 * Find a peer inside the set.
 */
static golle_peer_impl_t *find_peer (golle_peer_t peer,
				     golle_set_t *set)
{
  golle_error err;
  golle_peer_impl_t pred;
  const golle_bin_t *found;
  
  pred.id = peer;
  err = golle_set_find (set, &pred, sizeof (pred), &found);
  if (err == GOLLE_OK) {
    /* It's just a simple cast. */
    return (golle_peer_impl_t *)found->bin;
  }
  return NULL;
}

/*
 * Clear the h value of a single peer
 */
static void clear_single_peer_h (golle_peer_impl_t *p, void *unused) {
  GOLLE_UNUSED (unused);
  golle_num_delete (p->h);
  p->h = NULL;
}

/*
 * Clear the h value of all peers.
 */
static golle_error clear_peer_h (golle_peer_set_t *set) {
  /* Use the for_each and callback technique */
  return for_each_peer (set, NULL, &clear_single_peer_h);
}

/*
 * Free memory associated with a peer.
 */
static void clear_peer (golle_peer_impl_t *p, void *unused) {
  /* Clear all of the buffers and numbers. */
  GOLLE_UNUSED (unused);
  golle_num_delete (p->h);
  golle_commit_clear (&p->commit);
  p->h = NULL;
}

/*
 * Free memory associated with all peers.
 */
static void clear_peers (golle_peer_set_t *set) {
  /* Use the for_each and callback technique */
  for_each_peer (set, NULL, &clear_peer);
}

/*
 * Clear the public key h for each peer and locally.
 */
static golle_error clear_h (golle_peer_set_t *set) {
  GOLLE_ASSERT (set, GOLLE_ERROR);

  /* Clear the h of each peer */
  golle_error err = clear_peer_h (set);
  GOLLE_ASSERT (err == GOLLE_OK, err);

  /* Clear the local key */
  golle_num_delete (set->key.h);
  set->key.h = NULL;
  golle_num_delete (set->key.h_product);
  set->key.h_product = NULL;

  /* Maintain key state */
  if (set->state > GOLLE_KEY_INCOMPLETE) {
    set->state = GOLLE_KEY_INCOMPLETE;
  }
  return GOLLE_OK;
}

/*
 * Count up if the peer is ready.
 */
static void peer_ready (golle_peer_impl_t *p, void *r) {
  size_t *ready = (size_t*)r;
  if (p->h) {
    (*ready)++;
  }
}

/*
 * If all peers have a valid h value, then the
 * set is ready.
 */
static golle_error set_ready (golle_peer_set_t *set) {
  /* Use the for_each and callback to count
   * how many peers are ready
   */
  size_t ready = 0;
  golle_error err = for_each_peer (set, &ready, &peer_ready);

  /* Every peer must be ready for the key to be ready */
  if (err == GOLLE_OK) {
    if (ready == golle_peers_size (set)) {
      set->state = GOLLE_KEY_READY;
    }
    else {
      set->state = GOLLE_KEY_INCOMPLETE;
    }
  }
  return err;
}

golle_peer_set_t *golle_peers_new (void) {
  /* Allocate a new peer struct and a new set of peers */
  golle_peer_set_t *set = malloc (sizeof (*set));
  GOLLE_ASSERT (set, NULL);
  memset (set, 0, sizeof (*set));

  golle_error err = golle_set_new (&set->peers, &compare_peers);
  if (err != GOLLE_OK) {
    free (set);
    set = NULL;
  }
  else {
    set->state = GOLLE_KEY_EMPTY;
  }

  return set;
}

void golle_peers_delete (golle_peer_set_t *set) {
  if (set) {
    golle_key_clear (&set->key);
    clear_peers (set);
    golle_commit_delete (set->commit);
    golle_set_delete (set->peers);
    free (set);
  }
}

size_t golle_peers_size (golle_peer_set_t *set) {
  GOLLE_ASSERT (set, 0);
  return golle_set_size (set->peers);
}

golle_error golle_peers_add (golle_peer_set_t *set,
			     golle_peer_t *peer) 
{
  GOLLE_ASSERT (set, GOLLE_ERROR);
  GOLLE_ASSERT (peer, GOLLE_ERROR);

  /* Make a new peer and add it to the set */
  golle_peer_impl_t p;
  memset (&p, 0, sizeof (p));

  /* Get the next incremental id.
   * IDs don't have to be sequential, and
   * there can be gaps. There just can't be
   * duplicates. */
  p.id = set->next_id++;
  golle_error err = golle_set_insert (set->peers,
				      &p,
				      sizeof (p));
  if (err != GOLLE_OK) {
    return err;
  }

  /* Maintain the key state */
  if (set->state == GOLLE_KEY_READY) {
    set->state = GOLLE_KEY_INCOMPLETE;
  }
  *peer = p.id;
  return GOLLE_OK;
}

golle_error golle_peers_erase (golle_peer_set_t *set,
			       golle_peer_t peer)
{
  GOLLE_ASSERT (set, GOLLE_ERROR);
  golle_error err;
  int clear_state = 0;
  
  /* Find the peer */
  golle_peer_impl_t *p = find_peer (peer, set->peers);
  GOLLE_ASSERT (p, GOLLE_ENOTFOUND);

  /* Check the key state */
  if (p->h) {
    /* A non-NULL h means the peer has contributed to the key. */
    clear_state = 1;
  }
  
  /* Erase the peer from the set. */
  clear_peer (p, NULL);
  err = golle_set_erase (set->peers, p, sizeof (*p));

  if (err != GOLLE_OK) {
    return err;
  }
  /* Maintain the key state */
  if (clear_state) {
    err = clear_h (set);
  }
  return err;
}

golle_error golle_peers_set_key (golle_peer_set_t *set,
				 golle_key_t *key)
{
  GOLLE_ASSERT (set, GOLLE_ERROR);
  if (key) {
    GOLLE_ASSERT (key->p, GOLLE_EINVALID);
    GOLLE_ASSERT (key->g, GOLLE_EINVALID);
  }
  golle_error err = GOLLE_OK;

  /* Must clear everyone's h value. */
  err = clear_h (set);
  GOLLE_ASSERT (err == GOLLE_OK, err);

  /* Free existing resources. */
  golle_key_clear (&set->key);

  if (!key) {
    /* Clear the key and reset the state */
    set->state = GOLLE_KEY_EMPTY;
  }
  else {
    /* Set the public key. */
    err = golle_key_set_public (&set->key,
				key->p,
				key->g);

    /* Generate private bits */
    if (err == GOLLE_OK) {
      err = golle_key_gen_private (&set->key);
    }
    /* Maintain state */
    if (err == GOLLE_OK) {
      set->state = GOLLE_KEY_INCOMPLETE;
    }
  }

  return err;
}

golle_peer_key_state golle_peers_get_state (golle_peer_set_t *set) {
  GOLLE_ASSERT (set, GOLLE_KEY_UNDEFINED);
  return set->state;
}

int golle_peers_check_key (golle_peer_set_t *set,
			   golle_peer_t peer) 
{
  /* Peer must exist and have a valid h value */
  GOLLE_ASSERT (set, 0);
  golle_peer_impl_t *p = find_peer (peer, set->peers);
  GOLLE_ASSERT (p, 0);
  if (!p->h) {
    return 0;
  }
  return 1;
}

golle_error golle_peers_commit (golle_peer_set_t *set,
				golle_peer_t peer,
				golle_bin_t *rsend,
				golle_bin_t *hash)
{
  GOLLE_ASSERT (set, GOLLE_ERROR);
  GOLLE_ASSERT (rsend, GOLLE_ERROR);
  GOLLE_ASSERT (hash, GOLLE_ERROR);
  
  /* Get the peer record. */
  golle_peer_impl_t *p = find_peer (peer, set->peers);
  GOLLE_ASSERT (p, GOLLE_EINVALID);

  /* If the h value is set, the peer has already commited and
   * contributed to the key.
   */
  if (p->h) {
    return GOLLE_EEXISTS;
  }

  /* Replace the (possibly-empty) existing commitment. */
  golle_bin_t *new_rsend = golle_bin_copy (rsend);
  GOLLE_ASSERT (new_rsend, GOLLE_EMEM);

  golle_bin_t *new_hash = golle_bin_copy (hash);
  if (!new_hash) {
    golle_bin_delete (new_rsend);
    return GOLLE_EMEM;
  }
  golle_bin_delete (p->commit.rsend);
  golle_bin_delete (p->commit.hash);

  p->commit.rsend = new_rsend;
  p->commit.hash = new_hash;
  return GOLLE_OK;
}

golle_error golle_peers_verify (golle_peer_set_t *set,
				golle_peer_t peer,
				golle_bin_t *rkeep,
				golle_bin_t *secret)
{
  golle_bin_t *keep_copy = NULL, *secret_copy = NULL;
  golle_num_t h = NULL;
  golle_error err = GOLLE_OK;
  golle_peer_impl_t *p;
  golle_commit_t test;

  GOLLE_ASSERT (set, GOLLE_ERROR);
  GOLLE_ASSERT (rkeep, GOLLE_ERROR);
  GOLLE_ASSERT (secret, GOLLE_ERROR);

  p = find_peer (peer, set->peers);
  GOLLE_ASSERT (p, GOLLE_EINVALID);
  GOLLE_ASSERT (p->h == NULL, GOLLE_EEXISTS);
  GOLLE_ASSERT (p->commit.hash, GOLLE_ENOTFOUND);
  GOLLE_ASSERT (p->commit.rsend, GOLLE_ENOTFOUND);

  /* Fill in the whole commitment. */
  if (!(keep_copy = golle_bin_copy (rkeep))) {
    err = GOLLE_EMEM;
    goto error;
  }
  if (!(secret_copy = golle_bin_copy (secret))) {
    err = GOLLE_EMEM;
    goto error;
  }

  /* Check the commitment. */
  test.secret = secret_copy;
  test.hash = p->commit.hash;
  test.rkeep = keep_copy;
  test.rsend = p->commit.rsend;
  err = golle_commit_verify (&test);
  if (err != GOLLE_COMMIT_PASSED) {
    if (err == GOLLE_COMMIT_FAILED) {
      err = GOLLE_ENOCOMMIT;
    }
    goto error;
  }
  err = GOLLE_OK;

  /* Commitment passed, set the h value */
  if (!(h = golle_num_new ())) {
    err = GOLLE_EMEM;
    goto error;
  }
  
  if ((err = golle_bin_to_num (secret, h)) != GOLLE_OK) {
    goto error;
  }

  /* Accumulate the h product */
  if ((err = golle_key_accum_h (&set->key, h)) != GOLLE_OK) {
    goto error;
  }

  /* Set final values */
  golle_bin_delete (p->commit.rkeep);
  golle_bin_delete (p->commit.secret);
  golle_num_delete (p->h);
  p->commit.rkeep = keep_copy;
  p->commit.secret = secret_copy;
  p->h = h;

  return set_ready (set);

 error:
  golle_bin_delete (keep_copy);
  golle_bin_delete (secret_copy);
  golle_num_delete (h);
  return err;
}

golle_key_t *golle_peers_get_key (golle_peer_set_t *set) {
  GOLLE_ASSERT (set, NULL);
  GOLLE_ASSERT (set->state == GOLLE_KEY_READY, NULL);
  return &set->key;
}

golle_error golle_peers_get_commitment (golle_peer_set_t *set,
					golle_commit_t **commit)
{
  GOLLE_ASSERT (set, GOLLE_ERROR);
  GOLLE_ASSERT (commit, GOLLE_ERROR);
  GOLLE_ASSERT (set->key.h, GOLLE_EINVALID);
  GOLLE_ASSERT (set->state > GOLLE_KEY_EMPTY, GOLLE_EINVALID);

  /* Get h as a blob */
  golle_bin_t blob = { 0 };
  GOLLE_ASSERT (golle_num_to_bin (set->key.h, &blob) == GOLLE_OK, GOLLE_EMEM);

  /* Commit to the blob */
  golle_commit_t *c = golle_commit_new (&blob);
  golle_bin_release (&blob);
  GOLLE_ASSERT (c, GOLLE_EMEM);

  /* Store for later */
  golle_commit_delete (set->commit);
  set->commit = c;

  *commit = c;
  return GOLLE_OK;
}
