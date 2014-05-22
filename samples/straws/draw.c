/*
 * Copyright (C) Anthony Arnold 2014
 */
#include "globals.h"
#include "socklib.h"
#include <golle.h>
#include <arpa/inet.h>
#include <string.h>

static int *straw;
static size_t local_player;


static golle_commit_t commit = { 0 };
static golle_eg_t local = { 0 };
static size_t to_me_r;
static golle_num_t to_me_rand;
static golle_t golle;

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
  if (from == local_player) {
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
  if (from == local_player) {
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
  if (to == local_player || to == GOLLE_FACE_UP) {
    printf ("Storing local crypto values.\n");
    to_me_r = r;
    to_me_rand = golle_num_dup (rand);
    GOLLE_ASSERT (to_me_rand, GOLLE_EMEM);
  }

  if (to != local_player) {
    printf ("Sending encryption exponent %ld and randomness ", r);
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
  }
  
  golle_error err = GOLLE_OK;
  if (to == local_player || to == GOLLE_FACE_UP) {
    size_t selection;
    err =  golle_reveal_selection (g, &selection);
    if (err == GOLLE_OK) {
      *straw = (int)selection;
    }
    if (to == local_player) {
      size_t coll;
      err = golle_reduce_selection (g, selection, &coll);
    }
  }
  else {
    size_t coll;
    err = golle_check_selection (g, to, &coll);
  }
  return err;
}

static golle_error accept_rand (golle_t *g,
				size_t from,
				size_t *r,
				golle_num_t rand)
{
  GOLLE_UNUSED (g);
  if (from == local_player) {
    printf ("Accepting local crypto values.\n");
    *r = to_me_r;
    GOLLE_ASSERT (golle_num_cpy (rand, to_me_rand) == GOLLE_OK, GOLLE_EMEM);
    golle_num_delete (to_me_rand);
  }
  else {
    printf ("Accepting crypto values from %s.\n",
	    opponent_name);
    uint32_t nr;
    if (recv (opponent, &nr, 4, 0) != 4) {
      perror ("draw");
      return GOLLE_ERROR;
    }
    *r = ntohl (nr);
    printf ("Received exponent %ld\n", *r);

    if (recv_num (opponent, rand) != 0) {
      return GOLLE_ERROR;
    }
    printf ("Received randomness ");
    golle_num_print (stdout, rand);
    printf ("\n");
  }
  return GOLLE_OK;
}

static golle_error bcast_crypt (golle_t *g,
				const golle_eg_t *eg)
{
  GOLLE_UNUSED (g);
  printf ("Sending encrypted selection to %s\n",
	  opponent_name);

  /* Just send to the other player */
  if (send_eg (opponent, eg) != 0) {
    return GOLLE_ERROR;
  }
  return GOLLE_OK;
}

static golle_error accept_crypt (golle_t *g,
				 golle_eg_t *eg,
				 size_t from)
{
  GOLLE_ASSERT (from != local_player, GOLLE_ERROR);
  GOLLE_UNUSED (g);
  eg->a = golle_num_new ();
  GOLLE_ASSERT (eg->a, GOLLE_EMEM);
  eg->b = golle_num_new ();
  GOLLE_ASSERT (eg->b, GOLLE_EMEM);

  printf ("Accepting encrypted selection from %s\n",
	  opponent_name);

  /* Accept from the opponent */
  if (recv_eg (opponent, eg) != 0) {
    return GOLLE_ERROR;
  }
  return GOLLE_OK;
}

static const char *for_name (int me) {
  if (me) {
    return "me";
  }
  else {
    return opponent_name;
  }
}

static golle_error draw_first (void) {
  printf ("Drawing first straw for %s\n", for_name (!is_listener));
  /* For the non-listener */
  golle_error err = golle_generate (&golle, 0, GOLLE_FACE_UP); 
  if (err != GOLLE_OK) {
    /* Shouldn't fail */
    fprintf (stderr, "Error %d while drawing first straw.\n", err);
    return err;
  }
  printf ("First straw drawn: %d\n", *straw);
  return GOLLE_OK;
}

static golle_error draw_second (void) {
  printf ("Drawing second straw for %s\n", for_name (is_listener));
 /* For the listener */
  golle_error err = golle_generate (&golle, 0, GOLLE_FACE_UP);
  if (err == GOLLE_ECOLLISION) {
    fprintf (stderr, "Collision, starting over.\n");
  }
  return err;
}

int draw_straws (int *local, int *remote) {

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
  golle.bcast_crypt = &bcast_crypt;
  golle.accept_crypt = &accept_crypt;
  
  /* Initialise the golle structure */
  golle_error err = golle_initialise (&golle);
  if (err != GOLLE_OK) {
    fprintf (stderr, "Golle initialisation failed.\n");
    return (int)err;
  }

  /* Keep drawing until two distinct straws are drawn. */
  while (1) {
    if (is_listener) {
      straw = remote;
    }
    else {
      straw = local;
    }
    err = draw_first ();
    if (err != GOLLE_OK) {
      break;
    }
    if (straw == remote) {
      straw = local;
    }
    else {
      straw = remote;
    }
    err = draw_second ();
    if (err == GOLLE_OK) {
      /* Two straws drawn */
      printf ("Second straw drawn: %d\n", *straw);
      if (*local == *remote) {
	fprintf (stderr, "Error: both straws equal. IMPOSSIBLE\n");
	err = GOLLE_ERROR;
      }
      break;
    }
    else if (err != GOLLE_ECOLLISION) {
      fprintf (stderr, "Error %d while drawing second straw.\n", err);
      break;
    }
  }

  /* Done */
  golle_clear (&golle);
  return err;
}
