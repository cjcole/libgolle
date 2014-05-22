/*
 * Copyright (C) Anthony Arnold 2014
 */
#include "globals.h"
#include "socklib.h"
#include <golle.h>
#include <arpa/inet.h>
#include <string.h>

static int *straw;
static int local_player;


static golle_commit_t commit = { 0 };
static golle_eg_t local = { 0 };
static size_t to_me_r;
static golle_num_t to_me_rand;

/* Callback for broadcasting a commitment */
static golle_error bcast_commit (golle_t *g,
			  golle_bin_t *rsend,
			  golle_bin_t *hash)
{
  GOLLE_UNUSED (g);
  commit.rsend = golle_bin_copy (rsend);
  GOLLE_ASSERT (commit.rsend, GOLLE_EMEM);
  commit.hash = golle_bin_copy (hash);
  GOLLE_ASSERT (commit.hash, GOLLE_EMEM);
  printf ("Broadcasting commitment.\n");

  /* Send to peer */
  if (send_buffer (opponent, rsend) != 0) {
    fprintf (stderr, "Error sending random buffer.\n");
    return GOLLE_ERROR;
  }
  if(send_buffer (opponent, hash) != 0) {
    fprintf (stderr, "Error sending hash.\n");
    return GOLLE_ERROR;
  }
  return GOLLE_OK;
}


/* Callback for broadcasting a secret */
static golle_error bcast_secret (golle_t *g,
				 golle_eg_t *secret,
				 golle_bin_t *rkeep)
{
  GOLLE_UNUSED (g);
  /* Copy locally */
  commit.rkeep = golle_bin_copy (rkeep);
  GOLLE_ASSERT (commit.rkeep, GOLLE_EMEM);
  local.a = golle_num_dup (secret->a);
  GOLLE_ASSERT (local.a, GOLLE_EMEM);
  local.b = golle_num_dup (secret->b);
  GOLLE_ASSERT (local.b, GOLLE_EMEM);

  printf ("Broadcasting ciphertext.\n");
    printf ("a = ");
    golle_num_print (stdout, secret->a);
    printf ("\nb = ");
    golle_num_print (stdout, secret->b);
    printf ("\n");

  /* Send to peer  */
  if (send_eg (opponent, secret) != 0) {
    fprintf (stderr, "Error sending ciphertext.\n");
    return GOLLE_ERROR;
  }
  else if( send_buffer (opponent, rkeep) != 0) {
    fprintf (stderr, "Error sending random buffer.\n");
    return GOLLE_ERROR;
  }
  return GOLLE_OK;
}

/* Callback for accepting a commitment */
static golle_error accept_commit (golle_t *g,
				  size_t from,
				  golle_bin_t *rsend,
				  golle_bin_t *hash)
{
  GOLLE_UNUSED (g);
  if (from == (size_t)local_player) {
    printf ("Accepting own commitment\n");
    /* Copy local values */
    golle_error err = golle_bin_resize (rsend, commit.rsend->size);
    if (err != GOLLE_OK) {
      return err;
    }
    memcpy (rsend->bin, commit.rsend->bin, rsend->size);
    golle_bin_delete (commit.rsend);

    err = golle_bin_resize (hash, commit.hash->size);
    if (err != GOLLE_OK) {
      return err;
    }
    memcpy (hash->bin, commit.hash->bin, hash->size);
    golle_bin_delete (commit.hash);
  }
  else {
    printf ("Accepting commitment from %s\n", opponent_name);
    if (recv_buffer (opponent, rsend) != 0) {
      fprintf (stderr, "Error receiving random block.\n");
      return GOLLE_ERROR;
    }
    if (recv_buffer (opponent, hash) != 0) {
      fprintf (stderr, "Error receiving hash.\n");
      return GOLLE_ERROR;
    }
  }
  return GOLLE_OK;
}

static golle_error accept_eg (golle_t *g,
			      size_t from,
			      golle_eg_t *eg,
			      golle_bin_t *rkeep)
{
  GOLLE_UNUSED (g);
  if (from == (size_t)local_player) {
    printf ("Accepting own ciphertext\n");
    golle_error err = golle_bin_resize (rkeep, commit.rkeep->size);
    if (err != GOLLE_OK) {
      return err;
    }
    memcpy (rkeep->bin, commit.rkeep->bin, rkeep->size);
    golle_bin_delete (commit.rkeep);

    eg->a = local.a;
    eg->b = local.b;
  }
  else {
    printf ("Accepting ciphertext from %s\n", opponent_name);
    eg->a = golle_num_new ();
    GOLLE_ASSERT (eg->a, GOLLE_EMEM);
    eg->b = golle_num_new ();
    GOLLE_ASSERT (eg->b, GOLLE_EMEM);
    
    if (recv_eg (opponent, eg) != 0) {
      fprintf (stderr, "Error receiving ciphertext.\n");
      return GOLLE_ERROR;
    }
    printf ("Received a = ");
    golle_num_print (stdout, eg->a);
    printf ("\nReceived b = ");
    golle_num_print (stdout, eg->b);
    printf ("\n");
    if (recv_buffer (opponent, rkeep) != 0) {
      fprintf (stderr, "Error receiving random block.\n");
      return GOLLE_ERROR;
    }

  }
  return GOLLE_OK;
}

static golle_error reveal_rand (golle_t *g,
				size_t to,
				size_t r,
				golle_num_t rand)
{
  printf ("Revealing the selected value.\n");

  /* Always face-up */
  GOLLE_ASSERT (to == SIZE_MAX, GOLLE_ERROR);
  
  to_me_r = r;
  to_me_rand = golle_num_dup (rand);
  GOLLE_ASSERT (to_me_rand, GOLLE_EMEM);

  printf ("Sending encryption base %ld and randomness ", r);
  golle_num_print (stdout, rand);
  printf (" to %s\n", opponent_name);

  uint32_t nr = htonl ((uint32_t)r);
  if (send (opponent, &nr, 4, 0) != 4) {
    perror ("draw");
    return GOLLE_ERROR;
  }

  if (send_num (opponent, rand) != 0) {
    return GOLLE_ERROR;
  }

  size_t selection;
  golle_error err =  golle_reveal_selection (g, &selection);
  if (err == GOLLE_OK) {
    *straw = (int)selection;
  }
  return err;
}

static golle_error accept_rand (golle_t *g,
				size_t from,
				size_t *r,
				golle_num_t rand)
{
  GOLLE_UNUSED (g);
  if (from == (size_t)local_player) {
  printf ("Accepting own randomness.\n");
    *r = to_me_r;
    GOLLE_ASSERT (golle_num_cpy (rand, to_me_rand) == GOLLE_OK, GOLLE_EMEM);
    golle_num_delete (to_me_rand);
  }
  else {
    printf ("Accepting encryption base and randomness from %s.\n",
	    opponent_name);
    uint32_t nr;
    if (recv (opponent, &nr, 4, 0) != 4) {
      perror ("draw");
      return GOLLE_ERROR;
    }
    *r = ntohl (nr);
    printf ("Received base %ld\n", *r);

    if (recv_num (opponent, rand) != 0) {
      return GOLLE_ERROR;
    }
    printf ("Received randomness ");
    golle_num_print (stdout, rand);
    printf ("\n");
  }
  return GOLLE_OK;
}

int draw_straws (int *local, int *remote) {
  golle_t golle;

  if (is_listener) {
    local_player = 1;
  } else {
    local_player = 0;
  }

  /* Create the structure */
  golle.key = &key;
  golle.num_peers = 2; /* Including local peer */
  golle.num_items = NUMBER_OF_STRAWS;

  /* Set up callbacks */
  golle.bcast_commit = &bcast_commit;
  golle.bcast_secret = &bcast_secret;
  golle.accept_commit = &accept_commit;
  golle.accept_eg = &accept_eg;
  golle.reveal_rand = &reveal_rand;
  golle.accept_rand = &accept_rand;
  
  /* Initialise the golle structure */
  golle_error err = golle_initialise (&golle);
  if (err != GOLLE_OK) {
    fprintf (stderr, "Golle initialisation failed.\n");
    return (int)err;
  }

  /* Keep drawing until two distinct straws are drawn. */
  while (1) {

    printf ("Drawing first straw for ");
    if (!is_listener) {
      printf ("me\n");
      straw = local;
    }
    else {
      printf ("%s\n", opponent_name);
      straw = remote;
    }
    golle_error err = golle_generate (&golle, 0, SIZE_MAX); /* For the non-listener */
    if (err != GOLLE_OK) {
      /* Shouldn't fail */
      fprintf (stderr, "Error %d while drawing first straw.\n", err);
      return err;
    }
    printf ("First straw drawn: %d\n", *straw);

    printf ("Drawing second straw for ");
    if (is_listener) {
      printf ("me\n");
      straw = local;
    }
    else {
      printf ("%s\n", opponent_name);
      straw = remote;
    }
    err = golle_generate (&golle, 0, SIZE_MAX); /* For the listener */
    if (err == GOLLE_ECOLLISION) {
      fprintf (stderr, "Collision, starting over.\n");
      continue;
    }
    else if (err != GOLLE_OK) {
      fprintf (stderr, "Error %d while drawing second straw.\n", err);
      return err;
    }
    else {
      /* Two straws drawn */
      printf ("Second straw drawn: %d\n", *straw);
      break;
    }
  }

  /* Done */
  golle_clear (&golle);
  return 0;
}
