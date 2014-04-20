/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/select.h>
#include <golle/set.h>
#include <golle/elgamal.h>
#include <openssl/bn.h>
#include <assert.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif

struct golle_select_t {
  /* Number of objects in the set */
  size_t n;
  /* Stor n as a big number */
  golle_num_t bn_n;
  /* Objects g^0 .. g^(n-1) */
  golle_num_t *exp;
  /* The number of peers */
  size_t k;
  /* E(g^(ni)) for i = 0, ..., k-1 */
  golle_num_t *S;
  /* Just keep a copy of the key. */
  golle_key_t *key;
  /* Already selected items. */
  golle_set_t *selected;
};

/* Compare two numbers, set-style */
static int num_cmp (const golle_bin_t *b1, const golle_bin_t *b2) {
  assert (b1);
  assert (b2);

  golle_num_t n1 = (golle_num_t)b1->bin;
  assert (n1);
  golle_num_t n2 = (golle_num_t)b2->bin;
  assert (n2);
  return golle_num_cmp (n1, n2);
}

/* Encrypt g^r mod q */
static golle_error enc_gr (golle_eg_t *cipher,
			   const BIGNUM *r,
			   golle_key_t *key,
			   golle_num_t rand,
			   BN_CTX *ctx)
{
  golle_error err;
  BIGNUM *e;

  BN_CTX_start (ctx);
  if (!(e = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }

  if (!BN_mod_exp (e, key->g, r, key->q, ctx)) {
    err = GOLLE_EMEM;
    goto out;
  }

  err = golle_eg_encrypt (key, e, cipher, rand);
 out:
  BN_CTX_end (ctx);
  return err;
}

/* Delete every number in an array safely */
static void delete_num_array (golle_num_t *nums, size_t n) {
  if (nums) {
    for (size_t i = 0; i < n; i++) {
      golle_num_delete (nums[i]);
    }
  }
}

/* Calculate and store g^(mi) for i in {0, .., n - 1} */
static golle_error precalc_exp (golle_key_t *key, 
				golle_num_t *nums, 
				size_t m, 
				size_t n) 
{
  BN_CTX *ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);
  BN_CTX_start (ctx);

  BIGNUM *e = BN_CTX_get (ctx);
  if (!e) {
    BN_CTX_free (ctx);
    return GOLLE_EMEM;
  }

  golle_error err = GOLLE_OK;
  for (size_t i = 0; i < n; i++) {
    /* e = m * i */
    if (!BN_set_word (e, i * m)) {
      err = GOLLE_EMEM;
      break;
    }

    BIGNUM* exp = BN_new ();
    if (!exp) {
      err = GOLLE_EMEM;
      break;
    }
    nums[i] = exp;

    /* exp = g ^ e mod q */
    if (!BN_mod_exp (exp, key->g, e, key->q, ctx)) {
      err = GOLLE_EMEM;
      break;
    }
  }
  BN_CTX_end (ctx);
  BN_CTX_free (ctx);
  return err;
}

/* Get an ElGamal ciphertext as one binary blob */
static golle_error eg_to_bin (const golle_eg_t *enc,
			      golle_bin_t *bin)
{
  golle_bin_t b = { 0 };
  golle_error err = golle_num_to_bin (enc->a, bin);
  if (err != GOLLE_OK) {
    return err;
  }
  err = golle_num_to_bin (enc->b, &b);
  if (err != GOLLE_OK) {
    golle_bin_release (bin);
    return err;
  }
  size_t old_size = bin->size;
  err = golle_bin_resize (bin, bin->size + b.size);
  if (err != GOLLE_OK) {
    golle_bin_release (bin);
    golle_bin_release (&b);
    return err;
  }

  memcpy ((char*)bin->bin + old_size, b.bin, b.size);
  golle_bin_release (&b);
  return GOLLE_OK;
}

/* Commit to the number r */
static golle_error commit_to_enc (const golle_eg_t *enc,
				  const golle_select_t *select,
				  golle_select_callback_t commit,
				  golle_select_callback_t verify)
{
  /* Merge the ciphertext into one binary blob */
  golle_bin_t a = { 0 };
  golle_error err = eg_to_bin (enc, &a);
  GOLLE_ASSERT (err == GOLLE_OK, err);

  golle_commit_t *cmt = golle_commit_new (&a);
  golle_bin_release (&a);
  GOLLE_ASSERT (cmt, GOLLE_EMEM);

  /* Commit to the ciphertext */
  err = commit (select, cmt->rsend, cmt->hash);
  if (err != GOLLE_OK) {
    err = GOLLE_EABORT;
    goto out;
  }

  /* Verify the ciphertext */
  err = verify (select, cmt->rkeep, cmt->secret);
  if (err != GOLLE_OK) {
    err = GOLLE_EABORT;
    goto out;
  }

 out:
  golle_commit_delete (cmt);
  return err;
}

/* Send the chosen value and the randomness */
static golle_error reveal_selection (const golle_num_t r,
				     const golle_num_t rand,
				     const golle_select_t *select,
				     golle_select_callback_t reveal)
{
  golle_error err;
  golle_bin_t rbin = { 0 }, randbin = { 0 };
  /* Both numbers to buffers */
  err = golle_num_to_bin (r, &rbin);
  if (err != GOLLE_OK) {
    goto out;
  }
  err = golle_num_to_bin (rand, &randbin);
  if (err != GOLLE_OK) {
    goto out;
  }

  /* Send them */
  err = reveal (select, &rbin, &randbin);
  if (err != GOLLE_OK) {
    err = GOLLE_EABORT;
  }

 out:
  golle_bin_release (&rbin);
  golle_bin_release (&randbin);
  return err;
}

/* Create empty arrays */
static golle_error create_empty_arrays (golle_select_t *s,
					size_t n,
					size_t k)
{
  s->exp = calloc (sizeof (golle_num_t), n);
  GOLLE_ASSERT (s->exp, GOLLE_EMEM);
  s->n = n;

  s->S = calloc (sizeof (golle_num_t), k);
  GOLLE_ASSERT (s->S, GOLLE_EMEM);
  s->k = k;

  return GOLLE_OK;
}

/* Assign the big number. */
static golle_error assign_numeric (golle_select_t *s,
				   size_t n)
{
  s->bn_n = golle_num_new_int (n);
  GOLLE_ASSERT (s->bn_n, GOLLE_EMEM);
  return GOLLE_OK;
}

/* Assign values to the select structure */
static golle_error select_assign (golle_select_t *s,
				  size_t n,
				  size_t k,
				  golle_key_t *key)
{
  golle_error err;
  /* Make an empty set of numbers */
  err = golle_set_new (&s->selected, &num_cmp);
  GOLLE_ASSERT (err == GOLLE_OK, err);

  /* Create arrays of all-empty numbers */
  err = create_empty_arrays (s, n, k);
  GOLLE_ASSERT (err == GOLLE_OK, err);

  /* Percompute some values */
  err = assign_numeric (s, n);
  GOLLE_ASSERT (err == GOLLE_OK, err);

  err = precalc_exp (key, s->exp, 1, n);
  GOLLE_ASSERT (err == GOLLE_OK, err);

  err = precalc_exp (key, s->S, n, k);
  GOLLE_ASSERT (err == GOLLE_OK, err);

  s->key = key;
  return GOLLE_OK;
}

golle_error golle_select_new (golle_select_t **select,
			      golle_peer_set_t *peers,
			      size_t n)
{
  golle_error err = GOLLE_OK;
  size_t k;
  golle_key_t *key;
  golle_select_t *s;

  GOLLE_ASSERT (select, GOLLE_ERROR);
  GOLLE_ASSERT (peers, GOLLE_ERROR);
  GOLLE_ASSERT (n, GOLLE_EEMPTY);

  /* Must have at least one peer */
  k = golle_peers_size (peers);
  GOLLE_ASSERT (k, GOLLE_EEMPTY);

  /* Key must be valid */
  GOLLE_ASSERT (golle_peers_get_state (peers) == GOLLE_KEY_READY, 
		GOLLE_EINVALID);
  key = golle_peers_get_key (peers);
  GOLLE_ASSERT (key, GOLLE_EINVALID);

  /* Make a new object first */
  s = malloc (sizeof (*s));
  GOLLE_ASSERT (s, GOLLE_EMEM);
  memset (s, 0, sizeof (*s));

  /* Make an empty set of numbers */
  err = select_assign (s, n, k, key);
 
  if (err != GOLLE_OK) {
    golle_select_delete (s);
  }
  else {
    *select = s;
  }
  return err;
}

void golle_select_delete (golle_select_t *select) {
  if (select) {
    /* Free each number. */
    delete_num_array (select->exp, select->n);
    delete_num_array (select->S, select->k);
    golle_set_delete (select->selected);
    golle_num_delete (select->bn_n);
    free (select);
  }
}

golle_error golle_select_object (golle_select_t *select,
				 golle_select_callback_t commit,
				 golle_select_callback_t verify,
				 golle_select_callback_t reveal)
{
  golle_error err;
  golle_eg_t eg;
  BIGNUM *r, *rand = NULL;
  BN_CTX *ctx;
  GOLLE_ASSERT (select, GOLLE_ERROR);
  GOLLE_ASSERT (commit, GOLLE_ERROR);
  GOLLE_ASSERT (verify, GOLLE_ERROR);
  GOLLE_ASSERT (reveal, GOLLE_ERROR);

  ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);
  BN_CTX_start (ctx);

  /* Select a random r in [0, n) */
  if (!(r = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!BN_rand_range (r, select->bn_n)) {
    err = GOLLE_ECRYPTO;
    goto out;
  }

  /* Compute E(g^r) */
  err = enc_gr (&eg, r, select->key, rand, ctx);

  /* Commit and verify the encryption */
  err = commit_to_enc (&eg, select, commit, verify);
  if (err != GOLLE_OK) {
    goto out;
  }

  /* Reveal the selection via callback */
  err = reveal_selection (r, rand, select, reveal);

 out:
  BN_CTX_end (ctx);
  BN_CTX_free (ctx);
  return err;
}
