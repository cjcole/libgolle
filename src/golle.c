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

/* Represents data sent by a peer */
typedef struct peer_data_t {
  golle_commit_t commitment;
  golle_eg_t cipher;
  BIGNUM randomness;
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
static golle_error cipher_to_buffer (golle_bin_t *result,
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
  golle_error err = cipher_to_buffer (&b, n);
  if (err != GOLLE_OK) {
    return NULL;
  }
  /* Get commitment to buffe r*/
  golle_commit_t *c = golle_commit_new (&b);
  golle_bin_clear (&b);
  return c;
}

/* Get commitments from each peer */
static golle_error get_commitments (golle_t *golle) {
  golle_error err = GOLLE_OK;
  golle_bin_t rsend = { 0 }, hash = { 0 };

  golle_res_t *r = golle->reserved;
  for (size_t i = 0; i < golle->num_peers; i++) {
    peer_data_t *p = r->peer_data + i;

    /* Accept from peer i */
    err = golle->accept_commit (i, &rsend, &hash);
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
    err = golle->accept_eg (i, &cipher, &rkeep);
    if (err != GOLLE_OK) break;

    /* Convert cipher to a buffer */
    err = cipher_to_buffer (&secret, &cipher);
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
    BN_clear (&p->randomness);
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
  GOLLE_ASSERT (golle, GOLLE_ERROR);
  GOLLE_ASSERT (golle->key, GOLLE_ERROR);
  GOLLE_ASSERT (golle->num_peers, GOLLE_ERROR);
  GOLLE_ASSERT (golle->num_items, GOLLE_ERROR);

  /* Allocate enough space for all of the private data */
  size_t size = sizeof (BIGNUM) * golle->num_items;
  size += sizeof (golle_eg_t) * golle->num_peers;
  size += sizeof (peer_data_t) * golle->num_peers;
  size += sizeof (golle_res_t);
  golle_res_t *priv = calloc (size, 1);
  GOLLE_ASSERT (priv, GOLLE_EMEM);

  /* Point each array at the right location. */
  priv->S = (golle_eg_t*)((char *)priv) + sizeof (*priv);
  priv->items = (BIGNUM*)(priv->S + golle->num_peers);
  priv->peer_data = (peer_data_t *)(priv->items + golle->num_items);

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
    golle_eg_clear (&r->product);
    clear_peer_data (golle);
    free (r);
  }
}

golle_error golle_generate (golle_t *golle, 
			    size_t round, 
			    size_t peer)
{
  golle_eg_t C = { 0 };
  BIGNUM *r, *gr, *crand = NULL;
  golle_commit_t *commit = NULL;
  golle_error err = GOLLE_OK;
  GOLLE_ASSERT (golle, GOLLE_ERROR);
  GOLLE_ASSERT (peer < golle->num_peers, GOLLE_ERROR);
  GOLLE_ASSERT (golle->bcast, GOLLE_ERROR);
  GOLLE_ASSERT (golle->accept_commit, GOLLE_ERROR);
  GOLLE_ASSERT (golle->accept_eg, GOLLE_ERROR);
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
  if (!BN_mod_exp (gr, golle->key->g, r, golle->key->p, ctx)) {
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
  err = golle->bcast (commit);
  if (err != GOLLE_OK) {
    goto out;
  }

  /* Accept the commitment from each peer */
  err = get_commitments (golle);
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

  /* Ready to reduce the card */
  err = GOLLE_OK;
  
 out:
  BN_CTX_end (ctx);
  BN_CTX_free (ctx);
  golle_eg_clear (&C);
  golle_commit_delete (commit);
  clear_peer_data (golle);
  return err;
}
