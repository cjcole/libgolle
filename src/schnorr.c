/*
 * Copyright (C) Anthony Arnold 2014
 */
#include "schnorr.h"

golle_error golle_schnorr_commit_impl (const golle_schnorr_t *key,
				       golle_num_t r,
				       golle_num_t t,
				       BN_CTX *ctx)
{
  GOLLE_ASSERT (key, GOLLE_ERROR);
  GOLLE_ASSERT (r, GOLLE_ERROR);
  GOLLE_ASSERT (t, GOLLE_ERROR);
  GOLLE_ASSERT (key->G, GOLLE_ERROR);
  GOLLE_ASSERT (key->p, GOLLE_ERROR);

  /* Always seed the RNG. */
  golle_error err = golle_num_generate_rand (r, key->q);
  GOLLE_ASSERT (err == GOLLE_OK, err);

  /* Get t = g^r */
  if (!BN_mod_exp (t, key->G, r, key->p, ctx)) {
    err = GOLLE_EMEM;
  }
  return err;
}

golle_error golle_schnorr_commit (const golle_schnorr_t *key,
				  golle_num_t r,
				  golle_num_t t)
{
  /* A context for exponents. */
  BN_CTX *ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);

  golle_error err = golle_schnorr_commit_impl (key, r, t, ctx);

  BN_CTX_free (ctx);
  return err;
}

golle_error golle_schnorr_prove (const golle_schnorr_t *key,
				 golle_num_t s,
				 const golle_num_t r,
				 const golle_num_t c)
{
  GOLLE_ASSERT (key, GOLLE_ERROR);
  GOLLE_ASSERT (key->q, GOLLE_ERROR);
  GOLLE_ASSERT (r, GOLLE_ERROR);
  GOLLE_ASSERT (s, GOLLE_ERROR);
  GOLLE_ASSERT (c, GOLLE_ERROR);

  /* A context for exponents. */
  BN_CTX *ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);
  BN_CTX_start (ctx);

  /* Get cx */
  golle_error err = GOLLE_OK;
  BIGNUM *cx;
  if (!(cx = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
  }
  else if (!BN_mod_mul (cx, key->x, c, key->q, ctx)) {
    err = GOLLE_EMEM;
  }
  /* Calculate s = cx + r */
  else if (!BN_mod_add (s, cx, r, key->q, ctx)) {
    err = GOLLE_EMEM;
  }

  BN_CTX_end (ctx);
  BN_CTX_free (ctx);
  return err;
}

golle_error golle_schnorr_verify (const golle_schnorr_t *key,
				  const golle_num_t s,
				  const golle_num_t t,
				  const golle_num_t c)
{
  GOLLE_ASSERT (key, GOLLE_ERROR);
  GOLLE_ASSERT (key->p, GOLLE_ERROR);
  GOLLE_ASSERT (key->G, GOLLE_ERROR);
  GOLLE_ASSERT (key->Y, GOLLE_ERROR);
  GOLLE_ASSERT (s, GOLLE_ERROR);
  GOLLE_ASSERT (t, GOLLE_ERROR);
  GOLLE_ASSERT (c, GOLLE_ERROR);

  /* A context for exponents. */
  BN_CTX *ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);
  BN_CTX_start (ctx);

  /* Get ty^c */
  BIGNUM *tyc = NULL, *yc = NULL;
  golle_error err = GOLLE_OK;
  if (!(yc = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!(tyc = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!BN_mod_exp (yc, key->Y, c, key->p, ctx)) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!BN_mod_mul (tyc, yc, t, key->p, ctx)) {
    err = GOLLE_EMEM;
    goto out;
  }

  /* Get g^s */
  BIGNUM *gs = NULL;
  if (!(gs = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!BN_mod_exp (gs, key->G, s, key->p, ctx)) {
    err = GOLLE_EMEM;
    goto out;
  }

  /* Ensure equality */
  if (BN_cmp (gs, tyc) != 0) {
    err = GOLLE_ECRYPTO;
  }

 out:
  BN_CTX_free (ctx);
  return err;
}
