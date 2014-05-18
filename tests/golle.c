/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>

enum {
  KEY_BITS = 160
};

/*
 * This test sets up a "game" between two players.
 * They each get dealt one card from the deck.
 * Shows how to use callbacks.
 */

/* Each player maintains distinct golle structure.
 * In reality, players are likely to be on different
 * computers.
 */
golle_t players[2];
golle_key_t keys[2] = { {0}, {0} };
golle_commit_t commits[2];
golle_eg_t ciphers[2];
golle_num_t rands[2][2];
size_t rs[2][2];
pthread_mutex_t muts[2] = {
  PTHREAD_MUTEX_INITIALIZER,
  PTHREAD_MUTEX_INITIALIZER
};
pthread_cond_t conds[2] = {
  PTHREAD_COND_INITIALIZER,
  PTHREAD_COND_INITIALIZER
};

/* Get the opposite player's index */
static size_t get_opp_index (golle_t *player) {
  if (player == &players[0])
    return 1;
  else {
    assert (player == &players[1]);
    return 0;
  }
}

/* Send the ciphertext to the other player */
static golle_error bcast_crypt (golle_t *player,
				const golle_eg_t *cipher)
{
  size_t index = get_opp_index (player);
  pthread_mutex_lock (&muts[index]);
  assert (ciphers[index].a = golle_num_dup (cipher->a));
  assert (ciphers[index].b = golle_num_dup (cipher->b));
  pthread_cond_signal (&conds[index]);
  pthread_mutex_unlock (&muts[index]);
  return GOLLE_OK;  
}

/* Accept a ciphertext from the other player */
static golle_error accept_crypt (golle_t *player,
				 golle_eg_t *cipher,
				 size_t from)
{
  size_t index = !get_opp_index (player);
  assert (index == !from);
  pthread_mutex_lock (&muts[index]);
  pthread_cond_wait (&conds[index], &muts[index]);
  assert (cipher->a = golle_num_dup (ciphers[index].a));
  assert (cipher->b = golle_num_dup (ciphers[index].b));
  golle_eg_clear (&ciphers[index]);
  pthread_mutex_unlock (&muts[index]);
}

/* Commitment broadcast just sends to the other player */
static golle_error bcast_commit (golle_t *player,
				 golle_commit_t *commit)
{
  size_t index = get_opp_index (player);
  pthread_mutex_lock (&muts[index]);
  assert (commits[index].hash = golle_bin_copy (commit->hash));
  assert (commits[index].rsend = golle_bin_copy (commit->rsend));
  pthread_cond_signal (&conds[index]);
  pthread_mutex_unlock (&muts[index]);
  return GOLLE_OK;
}

/* Send commitment secret to other player for verification */
static golle_error bcast_secret (golle_t *player,
				 golle_eg_t *secret,
				 golle_bin_t *rkeep) {
  size_t index = get_opp_index (player);
  pthread_mutex_lock (&muts[index]);
  assert (commits[index].rkeep = golle_bin_copy (commit->rkeep));
  assert (ciphers[index].a = golle_num_dup (secret->a));
  assert (ciphers[index].b = golle_num_dup (secret->b));
  pthread_cond_signal (&conds[index]);
  pthread_mutex_unlock (&muts[index]);
  return GOLLE_OK;
}

/* Accept the commitment from the other peer */
static golle_error accept_commit (golle_t *player,
				  size_t from,
				  golle_bin_t *rsend,
				  golle_bin_t *hash)
{
  size_t index = !get_opp_index (player);
  assert (index == !from);
  pthread_mutex_lock (&muts[index]);
  pthread_cond_wait (&conds[index], &muts[index]);
  assert (rsend = golle_bin_copy (commits[index].rsend));
  assert (hash = golle_bin_copy (commits[index].hash));
  pthread_mutex_unlock (&muts[index]);
  return GOLLE_OK;
}

/* Accept the ciphertext and rkeep values from the other peer */
static golle_error accept_eg (golle_t *player,
			      size_t from,
			      golle_eg_t *cipher,
			      golle_bin_t *rkeep)
{
  size_t index = !get_opp_index (player);
  assert (index == !from);
  pthread_mutex_lock (&muts[index]);
  pthread_cond_wait (&conds[index], &muts[index]);

  rkeep->size = commits[index].rkeep->size;
  rkeep->bin = commits[index].rkeep->bin;

  assert (cipher->a = golle_num_dup (ciphers[index].a));
  assert (cipher->b = golle_num_dup (ciphers[index].b));

  golle_eg_clear (&ciphers[index]);
  golle_commit_clear (&commits[index]);

  pthread_mutex_unlock (&muts[index]);
  return GOLLE_OK;
}

/* Accept randomness from another player (or self) */
static golle_error accept_rand (golle_t *player,
				size_t from,
				size_t *r,
				golle_num_t rand)
{
  size_t index = !get_opp_index (player);
  pthread_mutex_lock (&muts[index]);
  if (index != from) {
    pthread_cond_wait (&conds[index], &muts[index]);
  }
  *r = rs[index][from];
  assert (golle_num_cpy (rand, rands[index][from]) == GOLLE_OK);
  golle_num_delete (rands[index][from]);
  pthread_mutex_unlock (&muts[index]);
  return GOLLE_OK;
}

/* Reveal randomness to other player (or self) */
static golle_error reveal_rand (golle_t *player,
				size_t to,
				size_t r,
				golle_num_t rand)
{
  size_t index = !get_opp_index (player);
  if (to == SIZE_MAX) {
    /* broadcast */
    pthread_mutex_lock (&muts[0]);
    rs[0][index] = r;
    assert (rands[0][index] = golle_num_dup (rand));
    if (index != 0) {
      pthread_cond_signal (&conds[0]);
    }
    pthread_mutex_unlock (&muts[0]);
    

    pthread_mutex_lock (&muts[1]);
    rs[1][index] = r;
    assert (rands[1][index] = golle_num_dup (rand));
    if (index != 0) {
      pthread_cond_signal (&conds[1]);
    }
    pthread_mutex_unlock (&muts[1]);
  }
  else {
    pthread_mutex_lock (&muts[to]);

    rs[to][index] = r;
    assert (rands[to][index] = golle_num_dup (rand));


    if (index != to) {
      pthread_cond_signal (&conds[0]);
    }
    pthread_mutex_unlock (&muts[0]);
  }
  
  golle_error err = GOLLE_OK;
  size_t coll;
  if (to == SIZE_MAX || to == index) {
    size_t selection;
    assert (golle_reveal_selection (player, &selection) == GOLLE_OK);
    printf ("Peer %d received card %d\n", index, selection);
    if (to == index) {
      golle_error err = golle_reduce_selection (player, selection, &coll);
    }
  }
  else {
    err = golle_check_selection (player, to, &coll);
  }

  if (err != GOLLE_ECOLLISION) {
    assert (err == GOLLE_OK);
  }
  return err;
}

/* Do key distribution */
static void setup_key (golle_t *player, 
		       golle_key_t *key,
		       golle_num_t p, 
		       golle_num_t g) 
{
  assert (golle_key_set_public (key, p, g) == GOLLE_OK);
  assert (golle_key_gen_private (key) == GOLLE_OK);
  player->key = key;
}

/* Initialise a player's data */
static void initialise_player (golle_t *player) {
  player->num_items = 52; /* A deck of cards */
  player->num_peers = 2; /* Two players */

  /* Fill in callbacks */
  player->bcast_commit = &bcast_commit;
  player->bcast_secret = &bcast_secret;
  player->accept_commit = &accept_commit;
  player->accept_eg = &accept_eg;
  player->reveal_rand = &reveal_rand;
  player->accept_rand = &accept_rand;
  player->bcast_crypt = &bcast_crypt;
  player->accept_crypt = &accept_crypt;

  assert (golle_initialise (player) == GOLLE_OK);
}

void *deal(void *arg) {
  golle_t *player = arg;

  /* Deal a card to each player */
  while (1) {
    /* Deal a card to player 0 */    
    /* Should always work */
    assert (golle_generate (player, 0, 0) == GOLLE_OK);

    /* Could fail with collision. */
    golle_error err = golle_generate (player, 0, 1);
    if (err != GOLLE_ECOLLISION) {
      GOLLE_ASSERT (err == GOLLE_OK);
      break;
    }
    printf ("Collision\n");
    /* Collision - try again */
  }
  printf ("Done\n");
  return NULL;
}

int main (void) {
  golle_key_t global_key = { 0 };
  /* Initialise the global key that the player's agree on first. */
  assert (golle_key_gen_public (&global_key, KEY_BITS, (size_t)-1) == GOLLE_OK);
  setup_key (&players[0], &keys[0], global_key.p, global_key.g);
  setup_key (&players[1], &keys[1], global_key.p, global_key.g);
  golle_key_clear (&global_key);

  /* Accumulate the h product */
  assert (golle_key_accum_h (&keys[1], keys[0].h) == GOLLE_OK);
  assert (golle_key_accum_h (&keys[0], keys[1].h) == GOLLE_OK);

  /* Keys are now ready */
  initialise_player (&players[1]);
  initialise_player (&players[0]);

  /* Deal cards */
  pthread_t threads[2];
  pthread_init (&threads[0], NULL, &deal, &players[0]);
  pthread_init (&threads[1], NULL, &deal, &players[1]);
  pthread_join (threads[0]);
  pthread_join (threads[1]);

  golle_clear (&players[1]);
  golle_clear (&players[0]);
  golle_key_clear (&keys[0]);
  golle_key_clear (&keys[1]);
  pthread_cond_destroy (&conds[0]);
  pthread_cond_destroy (&conds[1]);
  pthread_mutex_destroy (&muts[0]);
  pthread_mutex_destroy (&muts[1]);
}
