/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/select.h>
#include <golle/set.h>
#include <openssl/bn.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif

struct golle_select_t {
  /* Number of objects in the set */
  size_t n;
  /* Objects g^0 .. g^(n-1) */
  golle_num_t *exp;
  /* The number of peers */
  size_t k;
  /* E(g^(ni)) for i = 0, ..., k-1 */
  golle_num_t *S;
  /* Just keep a copy of the key. */
  golle_key_t *key;
};

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
    if (!BN_set_word (e, i * m)) {
      err = GOLLE_EMEM;
      break;
    }

    BIGNUM* exp = BN_new ();
    if (!exp) {
      err = GOLLE_EMEM;
      break;
    }
    /* exp = g ^ e mod q */
    if (!BN_mod_exp (exp, key->g, e, key->q, ctx)) {
      err = GOLLE_EMEM;
      break;
    }
    nums[i] = exp;
  }
  BN_CTX_end (ctx);
  BN_CTX_free (ctx);
  return err;
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

  /* Create arrays of all-empty numbers */
  s->exp = calloc (sizeof (golle_num_t), n);
  if (!s->exp) {
    err = GOLLE_EMEM;
    goto out;
  }
  s->S = calloc (sizeof (golle_num_t), k);
  if (!s->S) {
    err = GOLLE_EMEM;
    goto out;
  }
  s->n = n;
  s->k = k;

  /* Percompute some values */
  err = precalc_exp (key, s->exp, 1, n);
  if (err != GOLLE_OK) {
    goto out;
  }
  err = precalc_exp (key, s->S, n, k);
  if (err != GOLLE_OK) {
    goto out;
  }
  s->key = key;
 
 out:
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
    free (select);
  }
}
