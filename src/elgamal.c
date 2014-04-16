/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/bin.h>
#include <golle/numbers.h>
#include <golle/distribute.h>
#include <golle/errors.h>
#include <openssl/bn.h>
#include <golle/random.h>

#define TOBN(g) ((BIGNUM*)(g))

golle_error golle_eg_encrypt (golle_key_t *key,
			      golle_bin_t *msg,
			      golle_bin_t *c1,
			      golle_bin_t *c2)
{
  golle_error err = GOLLE_OK;
  BIGNUM *m, *r, *gr, *mh, *mhr;
  BN_CTX *ctx;
  GOLLE_ASSERT (key, GOLLE_ERROR);
  GOLLE_ASSERT (msg, GOLLE_ERROR);
  GOLLE_ASSERT (c1, GOLLE_ERROR);
  GOLLE_ASSERT (c2, GOLLE_ERROR);
  GOLLE_ASSERT (key->q, GOLLE_ERROR);
  GOLLE_ASSERT (key->h_product, GOLLE_ERROR);
  GOLLE_ASSERT (msg->bin, GOLLE_ERROR);
  GOLLE_ASSERT (msg->size, GOLLE_ERROR);

  ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);

  BN_CTX_start (ctx);

  if (!(m = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  
  /* Get msg as a number */
  err = golle_bin_to_num (msg, m);
  if (err != GOLLE_OK) {
    goto out;
  }
  
  /* Cannot encrypt m if m > q */
  if (BN_cmp (TOBN(m), TOBN(key->q))) {
    err = GOLLE_EOUTOFRANGE;
    goto out;
  }

  /* Get random r in Z*q */
  err = golle_random_seed ();
  if (err != GOLLE_OK) {
    err = GOLLE_ECRYPTO;
    goto out;
  }

  if (!(r = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }

  do {
    if (!BN_rand_range (r, key->q)) {
      err = GOLLE_ECRYPTO;
      goto out;
    }
  } while (BN_is_zero (r));

  /* Calculate g^r */
  if (!(gr = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }

  if (!BN_mod_exp (gr, TOBN(key->g), r, TOBN(key->q), ctx)) {
    err = GOLLE_ECRYPTO;
    goto out;
  }

  /* Calculate mh^r */
  if (!(mh = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!(mhr = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }

  if (!BN_mod_mul(mh, m, TOBN(key->h_product), TOBN(key->q), ctx)) {
    err = GOLLE_ECRYPTO;
    goto out;
  }

  if (!BN_mod_exp(mhr, mh, r, TOBN(key->q), ctx)) {
    err = GOLLE_ECRYPTO;
    goto out;
  }

  /* Write gr to binary */
  err = golle_num_to_bin (gr, c1);
  if (err != GOLLE_OK) {
    goto out;
  }

  /* Write mhr to binary */
  err = golle_num_to_bin (mhr, c2);

 out:
  BN_CTX_end (ctx);
  BN_CTX_free (ctx);
  
  return err;
}

golle_error golle_eg_decrypt (golle_num_t *xi,
			      size_t len,
			      golle_bin_t *c1,
			      golle_bin_t *c2,
			      golle_bin_t *msg)
{
  return GOLLE_EINVALID;
}
