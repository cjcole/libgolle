/*
 * Copyright (C) Anthony Arnold 2014
 */
#include <golle/golle.h>
#include <golle/config.h>
#include <golle/numbers.h>
#include <golle/elgamal.h>
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <openssl/bn.h>

/* The reserved data */
typedef struct golle_res_t {
  /* The set S = { E(g^(ni) } for n = num_items and i in [0, num_peers) */
  golle_eg_t *S;
  /* The index of the items, raised to the num_items power. */
  BIGNUM *items;
} golle_res_t;

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
    else if (!BN_mod_exp (t, key->g, t, key->p, ctx)) {
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
				 

golle_error golle_initialise (golle_t *golle) {
  GOLLE_ASSERT (golle, GOLLE_ERROR);
  GOLLE_ASSERT (golle->key, GOLLE_ERROR);
  GOLLE_ASSERT (golle->num_peers, GOLLE_ERROR);
  GOLLE_ASSERT (golle->num_items, GOLLE_ERROR);

  /* Allocate enough space for all of the private data */
  size_t size = sizeof (BIGNUM) * golle->num_items;
  size += sizeof (golle_eg_t) * golle->num_peers;
  size += sizeof (golle_res_t);
  golle_res_t *priv = calloc (size, 1);
  GOLLE_ASSERT (priv, GOLLE_EMEM);

  /* Point each array at the right location. */
  priv->S = (golle_eg_t*)((char *)priv) + sizeof (*priv);
  priv->items = (BIGNUM*)(priv->S + golle->num_peers);

  /* Pre-compute the item set. */
  golle_error err = precompute_items (priv->items, 
				      golle->num_items, 
				      golle->key);
  if (err != GOLLE_OK) {
    free (priv);
    return err;
  }

  /* Pre-compute the S set. */
  err = precompute_S (priv->S, 
			  golle->num_peers, 
			  golle->num_items,  
			  golle->key);
  if (err != GOLLE_OK) {
    free (priv);
    return err;
  }

  return err;
}

void golle_clear (golle_t *golle) {
  if (golle && golle->reserved) {
    golle_res_t *r = golle->reserved;

    for (size_t i = 0; i < golle->num_peers; i++) {
      golle_eg_clear (r->S + i);
    }
    for (size_t i = 0; i < golle->num_items; i++) {
      BN_clear(r->items + i);
    }
    free (r);
  }
}
