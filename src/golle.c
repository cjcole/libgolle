/*
 * Copyright (C) Anthony Arnold 2014
 */
#include <golle/golle.h>
#include <golle/config.h>
#include <golle/numbers.h>
#include <golle/elgamal.h>
#include <golle/list.h>
#include <golle/pep.h>
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <openssl/bn.h>
#include "numbers.h"

/* Represents data sent by a peer */
typedef struct peer_data_t {
  golle_commit_t commitment;
  golle_eg_t cipher;
  BIGNUM randomness;
  size_t r;
} peer_data_t;

/* The reserved data */
typedef struct golle_res_t {
  /* The set S = { E(g^(ni) } for n = num_items and i in [0, num_peers) */
  golle_eg_t *S;
  /* The index of the items, g^n. */
  BIGNUM *items;
  /* Data send by peers. */
  peer_data_t *peer_data;
  /* The product of all ciphertexts */
  golle_eg_t product;
  /* A list of encrypted selections for checking collisions */
  golle_list_t *selections;
} golle_res_t;

/* Copy an ElGamal ciphertext */
static golle_error eg_copy (golle_eg_t *dest, const golle_eg_t *src) {
  if (!(dest->a = golle_num_dup (src->a)) ||
      !(dest->b = golle_num_dup (src->b)))
    {
      return GOLLE_EMEM;
    }
  return GOLLE_OK;
}

/* Use Schnorr to test for ciphertext equivalence. */
static golle_error collision_test (const golle_t *golle,
				   const golle_eg_t *e1, 
				   const golle_eg_t *e2) 
{
  golle_error err = GOLLE_OK;
  BN_CTX *ctx;
  BIGNUM *b;
  if (!GOLLE_EG_FULL (e1) || !GOLLE_EG_FULL(e2)) {
    /* No collision, selection already discarded. */
    return GOLLE_OK;
  }
  /* Context for div */
  ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);
  BN_CTX_start (ctx);
  if (!(b = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  
  /* b = (m1 * h ^ r1) / (m2 * h ^ r2) */
  if ((err = golle_mod_div (b, e1->b, e2->b, golle->key->p, ctx)) != GOLLE_OK)
    {
      goto out;
    }
  /* If b == h then D(e1 / e2) == 1 (so D(e1) == D(e2)) */
  if (golle_num_cmp (b, golle->key->h_product) != 0) {
    err = GOLLE_OK;
  }
  else {
    /* Plaintexts are equal. This is a collision. */
    err = GOLLE_ECOLLISION;
  }

 out:
  BN_CTX_free (ctx);
  return err;
}

/* Check the given encryption against existing selection
 * ciphertexts. If a collision is found, the collision is
 * discarded. Otherwise, the new ciphertext is added.
 */
static golle_error check_for_collisions (golle_t *golle,
					 const golle_eg_t *cipher,
					 size_t *collision)
{
  golle_list_iterator_t *iter;
  golle_res_t *r = golle->reserved;
  golle_error err = golle_list_iterator (r->selections, &iter);
  if (err == GOLLE_OK) {
    void *item;
    size_t index = 0;
    while ( (err = golle_list_iterator_next (iter, &item)) == GOLLE_OK) {
      err = collision_test (golle, item, cipher);
      if (err == GOLLE_ECOLLISION) {
	/* Collision found at index. Discard the existing item. */
	golle_eg_clear (item);
	*collision = index;
	err = GOLLE_ECOLLISION;
	break;
      }
      else if (err != GOLLE_OK) {
	break;
      }
      index++;
    }
    golle_list_iterator_free (iter);
    if (err == GOLLE_END) {
      err = GOLLE_OK;
    }
  }

  if (err == GOLLE_OK) {
    /* No collision. Insert the item. */
    golle_eg_t copy = { 0 };
    err = eg_copy (&copy, cipher);
    if (err == GOLLE_OK) {
      err = golle_list_push (r->selections, &copy, sizeof (copy));
    }
     golle_eg_clear (&copy);
  }
  return err;
}

/* Clear all of the items from the list. */
static void clear_selections (golle_list_t *selections) {
  golle_list_iterator_t *iter;
  golle_error err = golle_list_iterator (selections, &iter);
  if (err == GOLLE_OK) {
    void *item;
    while ( (err = golle_list_iterator_next (iter, &item)) == GOLLE_OK) {
      golle_eg_clear (item);
    }
    golle_list_iterator_free (iter);
  }
}

/* Compute the item set. This is g^n for each item number n. */
static golle_error precompute_items (BIGNUM *items,
				     size_t num_items,
				     const golle_key_t *key)
{
  golle_error err = GOLLE_OK;
  size_t i = 0;
  /* A context for mod_exp in a loop. */
  BN_CTX *ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);
  BN_CTX_start (ctx);

  /* Temporary for the exponent. */
  BIGNUM *t = BN_CTX_get (ctx);
  if (!t) {
    err = GOLLE_EMEM;
  }

  /* Compute each exponential */
  for (;err == GOLLE_OK && i < num_items; i++) {
    BIGNUM *b = items + i;
    BN_init (b);
    if (!BN_set_word (t, i)) {
      err = GOLLE_EMEM;
    }
    else if (!BN_mod_exp (b, key->g, t, key->p, ctx)) {
      err = GOLLE_EMEM;
    }
  }

  BN_CTX_end (ctx);
  BN_CTX_free (ctx);
  if (err != GOLLE_OK) {
    /* Clean up everything that was initialised. */
    for (size_t j = 0; j < i; j++) {
      BN_clear (items + j);
    }
  }
  return err;
}

/* Compute the S set. */
static golle_error precompute_S (golle_eg_t *S,
				 size_t num_peers,
				 size_t num_items,
				 const golle_key_t *key)
{
  
  golle_error err = GOLLE_OK;
  size_t i = 0;
  /* A context for mod_exp in a loop. */
  BN_CTX *ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);
  BN_CTX_start (ctx);

  /* Temporary for the exponent. */
  BIGNUM *t = BN_CTX_get (ctx);
  if (!t) {
    err = GOLLE_EMEM;
  }

  /* Compute each exponential */
  for (;err == GOLLE_OK && i < num_peers; i++) {
    golle_eg_t *eg = S + i;

    if (!BN_set_word (t, i * num_items)) {
      err = GOLLE_EMEM;
    }
    else if (!BN_mod_exp (t, key->g, t, key->q, ctx)) {
      err = GOLLE_EMEM;
    }
    else {
      err = golle_eg_encrypt (key, t, eg, NULL);
    }
  }

  BN_CTX_end (ctx);
  BN_CTX_free (ctx);
  if (err != GOLLE_OK) {
    /* Clean up everything that was initialised. */
    for (size_t j = 0; j < i; j++) {
      golle_eg_clear (S + j);
    }
  }
  return err;
}

/* Get a random number in { 0, ..., n - 1 } */
static golle_error small_random (golle_num_t r,
				 size_t n,
				 BN_CTX *ctx)
{
  golle_error err = GOLLE_OK;
  
  /* Convert n to a BIGNUM */
  BN_CTX_start (ctx);
  BIGNUM *t = BN_CTX_get (ctx);
  if (!t) {
    err = GOLLE_EMEM;
    goto out;
  }

  if (!BN_set_word (t, n)) {
    err = GOLLE_EMEM;
    goto out;
  }

  err = golle_num_generate_rand (r, t);

 out:
  BN_CTX_end (ctx);
  return err;
}

/* Get a ciphertext as a buffer */
static golle_error eg_to_buffer (golle_bin_t *result,
				     const golle_eg_t *c) 
{
  golle_error err = GOLLE_OK;
  golle_bin_t b1 = { 0 }, b2 = { 0 };
  /* Get both numbers as buffers */
  err = golle_num_to_bin (c->a, &b1);
  if (err != GOLLE_OK) {
    goto out;
  }
  err = golle_num_to_bin (c->a, &b1);
  if (err != GOLLE_OK) {
    goto out;
  }
  /* Make result the correct size */
  err = golle_bin_resize (result, b1.size + b2.size);
  if (err != GOLLE_OK) {
    goto out;
  }

  /* Concatenate */
  memcpy (result->bin, b1.bin, b1.size);
  memcpy ((char *)result->bin + b1.size, b2.bin, b2.size);

 out:
  golle_bin_clear (&b1);
  golle_bin_clear (&b2);
  return err;
}

/* Get a commitment to the ciphertext */
static golle_commit_t *commit_to_cipher (const golle_eg_t *n) {
  /* Get ciphertext as a buffer */
  golle_bin_t b = { 0 };
  golle_error err = eg_to_buffer (&b, n);
  if (err != GOLLE_OK) {
    return NULL;
  }
  /* Get commitment to buffer */
  golle_commit_t *c = golle_commit_new (&b);
  golle_bin_clear (&b);
  return c;
}

/* Sum up selections to get the final choice */
static size_t reveal_selection (const golle_t *golle) {
  size_t s = 0;
  golle_res_t *r = golle->reserved;
  for (size_t i = 0; i < golle->num_peers; i++) {
    peer_data_t *p = r->peer_data + i;
    s = (s + p->r) % golle->num_items;
  }
  return s;
}

/* Validate an encryption */
static golle_error validate_encryption (const golle_key_t *key,
					const golle_eg_t *cipher,
					size_t m,
					golle_num_t rand)
{
  golle_error err = GOLLE_OK;
  BIGNUM *base, *e;
  BN_CTX *ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);
  BN_CTX_start (ctx);

  if (!(base = BN_CTX_get (ctx)) ||
      !(e = BN_CTX_get (ctx)))
    {
      err = GOLLE_EMEM;
      goto out;
    }


  if (!BN_set_word (base, m)) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!BN_mod_exp (e, key->g, base, key->q, ctx)) {
    err = GOLLE_EMEM;
    goto out;
  }

  golle_eg_t check = { 0 };
  err = golle_eg_encrypt (key, e, &check, &rand);
  if (err == GOLLE_OK) {
    if (golle_num_cmp (check.a, cipher->a) != 0 ||
	golle_num_cmp (check.b, cipher->b) != 0)
      {
	err = GOLLE_ECRYPTO;
      }
  }
  golle_eg_clear (&check);

 out:
  BN_CTX_free (ctx);
  return err;
}

/* Get r and rand values from each peer */
static golle_error get_randoms (golle_t *golle) {
  golle_error err = GOLLE_OK;
  golle_res_t *r = golle->reserved;
  for (size_t i = 0; i < golle->num_peers; i++) {    
    peer_data_t *p = r->peer_data + i;

    /* Accept from peer i */
    BN_init (&p->randomness);
    err = golle->accept_rand (golle, i, &p->r, &p->randomness);
    if (err != GOLLE_OK) {
      break;
    }

    /* Check that r is in range */
    if (p->r >= golle->num_items) {
      err = GOLLE_EOUTOFRANGE;
      break;
    }

    /* Check that the encryption is valid */
    err = validate_encryption (golle->key,
			       &p->cipher,
			       p->r,
			       &p->randomness);
    if (err != GOLLE_OK) {
      break;
    }
  }
  return err;
}

/* Get commitments from each peer */
static golle_error get_commitments (golle_t *golle) {
  golle_error err = GOLLE_OK;
  golle_bin_t rsend = { 0 }, hash = { 0 };

  golle_res_t *r = golle->reserved;
  for (size_t i = 0; i < golle->num_peers; i++) {
    peer_data_t *p = r->peer_data + i;

    /* Accept from peer i */
    err = golle->accept_commit (golle, i, &rsend, &hash);
    if (err != GOLLE_OK) break;

    /* Copy into storage. */
    if (!(p->commitment.rsend = golle_bin_copy (&rsend)) ||
	!(p->commitment.hash = golle_bin_copy (&hash)))
      {
	err = GOLLE_EMEM;
      }

    /* Clean up */
    golle_bin_clear (&rsend);
    golle_bin_clear (&hash);
    if (err != GOLLE_OK) {
      break;
    }
  }
  return err;
}

/* Get the revealed commitments from each peer */
static golle_error get_ciphertexts (golle_t *golle) {
  golle_error err = GOLLE_OK;;
  golle_bin_t rkeep = { 0 }, secret = { 0 };
  golle_eg_t cipher = { 0 };

  golle_res_t *r = golle->reserved;
  for (size_t i = 0; i < golle->num_peers; i++) {
    peer_data_t *p = r->peer_data + i;

    /* Accept ciphertext and rkeep from peer i */
    err = golle->accept_eg (golle, i, &cipher, &rkeep);
    if (err != GOLLE_OK) break;

    /* Convert cipher to a buffer */
    err = eg_to_buffer (&secret, &cipher);
    if (err != GOLLE_OK) break;

    /* Copy into storage. */
    if (!(p->commitment.rkeep = golle_bin_copy (&rkeep)) ||
	!(p->commitment.secret = golle_bin_copy (&secret))) 
      {
	err = GOLLE_EMEM;
      }
    if (!(p->cipher.a = golle_num_dup (cipher.a)) ||
	!(p->cipher.b = golle_num_dup (cipher.b)))
      {
	err = GOLLE_EMEM;
      }

    /* Clean up */
    golle_bin_clear (&secret);
    golle_bin_clear (&rkeep);
    golle_eg_clear (&cipher);
    if (err != GOLLE_OK) {
      break;
    }
  }
  return err;
}

/* Check all commitments */
static golle_error check_commitments (golle_t *golle) {
  golle_error err = GOLLE_OK;
  golle_res_t *r = golle->reserved;
  for (size_t i = 0; i < golle->num_peers; i++) {
    peer_data_t *p = r->peer_data + i;

    err = golle_commit_verify (&p->commitment);
    if (err != GOLLE_COMMIT_PASSED) {
      err = GOLLE_ENOCOMMIT;
      break;
    }
    err = GOLLE_OK;
  }
  return err;
}

/* Clear up the peer data */
static void clear_peer_data (golle_t *golle) {
  golle_res_t *r = golle->reserved;
  for (size_t i = 0; i < golle->num_peers; i++) {
    peer_data_t *p = r->peer_data + i;

    golle_commit_clear (&p->commitment);
    golle_eg_clear (&p->cipher);
    BN_clear_free (&p->randomness);
  }
  golle_eg_clear (&r->product);
}

/* Compute the product of all ciphertexts */
static golle_error prod_ciphers (golle_t *golle) {
  BIGNUM *a, *b;
  golle_error err = GOLLE_OK;
  golle_res_t *r = golle->reserved;
  BN_CTX *ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);
  
  BN_CTX_start (ctx);
  if (!(a = BN_CTX_get (ctx)) ||
      !(b = BN_CTX_get (ctx)) ||
      !BN_set_word (a, 1) ||
      !BN_set_word (b, 1))
    {
      err = GOLLE_EMEM;
      goto out;
    }

  for (size_t i = 0; i < golle->num_peers; i++) {
    peer_data_t *p = r->peer_data + i;
    if (!BN_mod_mul (a, a, p->cipher.a, golle->key->p, ctx) ||
	!BN_mod_mul (b, b, p->cipher.b, golle->key->p, ctx))
      {
	err = GOLLE_ECRYPTO;
	goto out;
      }
  }
  if (!(r->product.a = golle_num_dup (a)) ||
      !(r->product.b = golle_num_dup (b)))
    {
      err = GOLLE_EMEM;
      goto out;
    }

 out:
  BN_CTX_free (ctx);
  return err;
}

golle_error golle_initialise (golle_t *golle) {
  golle_error err = GOLLE_OK;
  GOLLE_ASSERT (golle, GOLLE_ERROR);
  GOLLE_ASSERT (golle->key, GOLLE_ERROR);
  GOLLE_ASSERT (golle->num_peers, GOLLE_ERROR);
  GOLLE_ASSERT (golle->num_items, GOLLE_ERROR);

  /* Allocate enough space for all of the private data */
  golle_res_t *priv = calloc (sizeof (golle_res_t), 1);
  GOLLE_ASSERT (priv, GOLLE_EMEM);

  if (!(priv->S = calloc (sizeof (golle_eg_t), golle->num_peers)) ||
      !(priv->items = calloc (sizeof (BIGNUM), golle->num_items)) ||
      !(priv->peer_data = calloc (sizeof(peer_data_t), golle->num_peers)))
    {
      err = GOLLE_EMEM;
      goto out;
    }

  /* Pre-compute the item set. */
  err = precompute_items (priv->items, 
			  golle->num_items, 
			  golle->key);
  if (err != GOLLE_OK) {
    goto out;
  }

  /* Pre-compute the S set. */
  err = precompute_S (priv->S, 
		      golle->num_peers, 
		      golle->num_items,  
		      golle->key);
  if (err != GOLLE_OK) {
    goto out;
  }
  /* Allocate the list */
  err = golle_list_new (&priv->selections);
  if (err != GOLLE_OK) {
    goto out;
  }
  golle->reserved = priv;

 out:
  if (err != GOLLE_OK) {
    golle_clear (golle);
  }
  return err;
}

void golle_clear (golle_t *golle) {
  if (golle && golle->reserved) {
    golle_res_t *r = golle->reserved;
    if (!r) {
      return;
    }

    if (r->S) {
      for (size_t i = 0; i < golle->num_peers; i++) {
	golle_eg_clear (r->S + i);
      }
      free (r->S);
    }
    if (r->items) {
      for (size_t i = 0; i < golle->num_items; i++) {
	BN_clear_free(r->items + i);
      }
      free (r->items);
    }
    if (r->peer_data) {
      clear_peer_data (golle);
      free (r->peer_data);
    }
    /* Clear the list */
    clear_selections (r->selections);
    golle_list_delete (r->selections);

    golle_eg_clear (&r->product);
    free (r);
  }
}

golle_error golle_generate (golle_t *golle, 
			    size_t round, 
			    size_t peer)
{
  /* This is the main function for the protocol.
   * In it, the crypto functions for (partially) selecting
   * an item are performed and most of the callbacks are invoked.
   */
  golle_eg_t C = { 0 };
  BIGNUM *r, *gr, *crand = NULL;
  golle_commit_t *commit = NULL;
  golle_error err = GOLLE_OK;
  GOLLE_ASSERT (golle, GOLLE_ERROR);
  GOLLE_ASSERT (peer < golle->num_peers || peer == SIZE_MAX, GOLLE_ERROR);
  GOLLE_ASSERT (golle->bcast_commit, GOLLE_ERROR);
  GOLLE_ASSERT (golle->bcast_secret, GOLLE_ERROR);
  GOLLE_ASSERT (golle->accept_commit, GOLLE_ERROR);
  GOLLE_ASSERT (golle->accept_eg, GOLLE_ERROR);
  GOLLE_ASSERT (golle->reveal_rand, GOLLE_ERROR);

  /* TODO: Allow more than one round.
   * To do this, an implementation of Millimix is required.
   */
  GOLLE_UNUSED (round);
  
  /* A context for random numbers and exponents */
  BN_CTX *ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);
  BN_CTX_start (ctx);

  /* Initialise temporaries */
  if (!(r = BN_CTX_get (ctx)) ||
      !(gr = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }

  /* Choose r in [0,num_items) */
  err = small_random (r, golle->num_items, ctx);
  if (err != GOLLE_OK) {
    goto out;
  }
  /* Get g^r */
  if (!gr) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!BN_mod_exp (gr, golle->key->g, r, golle->key->q, ctx)) {
    err = GOLLE_ECRYPTO;
    goto out;
  }

  /* Get ciphertext C = E(g^r) */
  err = golle_eg_encrypt (golle->key, gr, &C, (golle_num_t *)&crand);
  if (err != GOLLE_OK) {
    goto out;
  }

  /* Get a commitment to C */
  if (!(commit = commit_to_cipher (&C))) {
    err = GOLLE_EMEM;
    goto out;
  }

  /* Output the commitment */
  err = golle->bcast_commit (golle, commit->rsend, commit->hash);
  if (err != GOLLE_OK) {
    goto out;
  }

  /* Accept the commitment from each peer */
  err = get_commitments (golle);
  if (err != GOLLE_OK) {
    goto out;
  }

  /* Output the ciphertext and rkeep buffers */
  err = golle->bcast_secret (golle, &C, commit->rkeep);
  if (err != GOLLE_OK) {
    goto out;
  }

  /* Accept the ciphertext and rkeep buffers */
  err = get_ciphertexts (golle);
  if (err != GOLLE_OK) {
    goto out;
  }

  /* Check all commitments. */
  err = check_commitments (golle);
  if (err != GOLLE_OK) {
    goto out;
  }

  /* Compute the product of all of the ciphers */
  err = prod_ciphers (golle);
  if (err != GOLLE_OK) {
    goto out;
  }

  /* Send the selection and random value to the correct peer(s) */
  err = golle->reveal_rand (golle, peer, BN_get_word (r), crand);

 out:
  BN_CTX_end (ctx);
  BN_CTX_free (ctx);
  golle_eg_clear (&C);
  golle_commit_delete (commit);
  clear_peer_data (golle);
  golle_num_delete (crand);
  return err;
}

golle_error golle_reveal_selection (golle_t *golle,
				     size_t *selection)
{
  golle_error err = GOLLE_OK;
  GOLLE_ASSERT (golle, GOLLE_ERROR);
  GOLLE_ASSERT (selection, GOLLE_ERROR);
  
  /* Get all of the r and random values from other peers. */
  err = get_randoms (golle);
  if (err != GOLLE_OK) {
    goto out;
  }
  
  /* The selection is the sum of all r values */
  *selection = reveal_selection (golle);
 out:
  return err;
}
golle_error golle_reduce_selection (golle_t *golle,
				    size_t c,
				   size_t *collision)
{
  GOLLE_ASSERT (golle, GOLLE_ERROR);
  GOLLE_ASSERT (golle->bcast_crypt, GOLLE_ERROR);
  GOLLE_ASSERT (collision, GOLLE_ERROR);
  
  /* TODO: Output a proof that selection is in [0, num_items) and
   * has been decrypted properly.
   */

  /* Output E(g^c) and everyone tests for collision. */
  golle_error err = GOLLE_OK;
  golle_eg_t crypt = { 0 };
  golle_num_t i = golle_num_new_int (c);
  GOLLE_ASSERT (i, GOLLE_EMEM);
  err = golle_num_mod_exp (i, golle->key->g, i, golle->key->p);
  if (err != GOLLE_OK) {
    goto out;
  }

  err = golle_eg_encrypt (golle->key, i, &crypt, NULL);

  if (err == GOLLE_OK) {
    err = golle->bcast_crypt (golle, &crypt);
  }
  if (err == GOLLE_OK) {
    /* Check for collision locally */
    err = check_for_collisions (golle, &crypt, collision);
  }

 out:
  golle_num_delete (i);
  golle_eg_clear (&crypt);
  return err;
}
golle_error golle_check_selection (golle_t *golle,
				   size_t peer,
				   size_t *collision)
{
  GOLLE_ASSERT (golle, GOLLE_ERROR);
  GOLLE_ASSERT (golle->accept_crypt, GOLLE_ERROR);
  GOLLE_ASSERT (collision, GOLLE_ERROR);
  
  /* TODO: Accept and verify proof of subset membership/correct decryption
     from peer */
  
  /* Accept E(c) and test for collision. */
  golle_eg_t crypt = { 0 };
  golle_error err = golle->accept_crypt (golle, &crypt, peer);
  if (err == GOLLE_OK) {
    err = check_for_collisions (golle, &crypt, collision);
  }
  golle_eg_clear (&crypt);
  return err;
}
