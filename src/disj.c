/*
 * Copyright (C) Anthony Arnold 2014
 */

#include "schnorr.h"
#include <golle/disj.h>
#include <golle/random.h>
#include <golle/bin.h>
#include <limits.h>

/*
 * Get the s1 value for proof.
 */
static golle_error get_s1 (const golle_schnorr_t *key,
			   const golle_num_t r,
			   const golle_num_t c1,
			   golle_num_t s1)
{
  BIGNUM *cx = NULL;
  BN_CTX *ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);
  BN_CTX_start (ctx);
  
  golle_error err = GOLLE_OK;
  /* Calculate c1 * x */
  if (!(cx = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!BN_mod_mul (cx, c1, key->x, key->q, ctx)) {
    err = GOLLE_EMEM;
    goto out;
  }

  /* Calculate the final value */
  if (!BN_mod_sub (s1, cx, r, key->q, ctx)) {
    err = GOLLE_EMEM;
    goto out;
  }
 out:
  BN_CTX_free (ctx);
  return err;
}

/*
 * Get the t2 value for commitment.
 */
static golle_error get_t2 (const golle_schnorr_t *key,
			   const golle_num_t s2,
			   const golle_num_t c2,
			   golle_num_t t2,
			   BN_CTX *ctx)
{
  BN_CTX_start (ctx);
  golle_error err = GOLLE_OK;
  
  BIGNUM *GS, *YC, *invS;
  if (!(GS = BN_CTX_get (ctx)) ||
      !(YC = BN_CTX_get (ctx)) ||
      !(invS = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  /* Get inverse of g */
  if (!BN_mod_inverse (invS, key->G, key->p, ctx)) {
    err = GOLLE_ECRYPTO;
  }

  /* GS = G^-s */
  if (!BN_mod_exp (GS, invS, s2, key->p, ctx)) {
    err = GOLLE_ECRYPTO;
    goto out;
  }
  /* YC = Y^c2 */
  if (!BN_mod_exp (YC, key->Y, c2, key->p, ctx)) {
    err = GOLLE_ECRYPTO;
    goto out;
  }

  /* Product */
  if (!BN_mod_mul (t2, GS, YC, key->p, ctx)) {
    err = GOLLE_ECRYPTO;
    goto out;
  }

 out:
  BN_CTX_end (ctx);
  return err;
}

/*
 * Allocate the five numbers required for commitment.
 */
static golle_error alloc_nums (BIGNUM **t1,
			       BIGNUM **t2,
			       BIGNUM **r1,
			       BIGNUM **s2,
			       BIGNUM **c2)
{
  GOLLE_ASSERT (*t1 = BN_new (), GOLLE_EMEM);
  GOLLE_ASSERT (*t2 = BN_new (), GOLLE_EMEM);
  GOLLE_ASSERT (*r1 = BN_new (), GOLLE_EMEM);
  GOLLE_ASSERT (*s2 = BN_new (), GOLLE_EMEM);
  GOLLE_ASSERT (*c2 = BN_new (), GOLLE_EMEM);
  return GOLLE_OK;
}

/*
 * Verify for a single key.
 * Y^c == G^s * t
 */
golle_error check_key (const golle_schnorr_t *key,
		       const golle_num_t s,
		       const golle_num_t t,
		       const golle_num_t c)
{
  golle_error err = GOLLE_OK;
  BIGNUM *yc = NULL, *gs = NULL, *gst = NULL;
  BN_CTX *ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);
  BN_CTX_start (ctx);

  /* Get y^c */
  if (!(yc = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!BN_mod_exp (yc, key->Y, c, key->p, ctx)) {
    err = GOLLE_EMEM;
    goto out;
  }
  /* Get G^s */
  if (!(gs = BN_CTX_get (ctx)) ||
      !(gst = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!BN_mod_exp (gs, key->G, s, key->p, ctx)) {
    err = GOLLE_EMEM;
    goto out;
  }
  /* Get G^s * t */
  if (!BN_mod_mul (gst, gs, t, key->p, ctx)) {
    err = GOLLE_EMEM;
    goto out;
  }

  /* Ensure they're equal */
  if (BN_cmp (gst, yc) != 0) {
    err = GOLLE_ECRYPTO;
  }
 out:
  BN_CTX_free (ctx);
  return err;
}

golle_error golle_disj_commit (const golle_schnorr_t *unknown,
			       const golle_schnorr_t *known,
			       golle_disj_t *d)
{
  GOLLE_ASSERT (known, GOLLE_ERROR);
  GOLLE_ASSERT (unknown, GOLLE_ERROR);
  GOLLE_ASSERT (d, GOLLE_ERROR);
  BIGNUM *r1 = NULL, *t1 = NULL, *s2 = NULL, *t2 = NULL, *c2 = NULL;

  /* Allocate all numbers. */
  golle_error err = alloc_nums (&t1, &t2, &r1, &s2, &c2);
  GOLLE_ASSERT (err == GOLLE_OK, err);

  /* Get a context. */
  BN_CTX *ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);

  /* Get the first schnorr values */
  err = golle_schnorr_commit_impl (known, r1, t1, ctx);
  if (err != GOLLE_OK) {
    goto out;
  }

  /* Choose random s2 in Zq */
  err = golle_num_generate_rand (s2, unknown->q);
  err = golle_num_generate_rand (c2, unknown->q);

  /* Calculate t2 = G2^s2 * Y2 ^c2 */
  err = get_t2 (unknown, s2, c2, t2, ctx);
  if (err != GOLLE_OK) {
    goto out;
  }

 out:
  if (err != GOLLE_OK) {
    golle_num_delete (t1);
    golle_num_delete (r1);
    golle_num_delete (s2);
    golle_num_delete (c2);
    golle_num_delete (t2);
  }
  else {
    d->t1 = t1;
    d->t2 = t2;
    d->s2 = s2;
    d->c2 = c2;
    d->r1 = r1;
  }
  BN_CTX_free (ctx);
  return err;
}

golle_error golle_disj_prove (const golle_schnorr_t *unknown,
			      const golle_schnorr_t *known,
			      const golle_num_t c,
			      golle_disj_t *d)
{
  GOLLE_ASSERT (unknown, GOLLE_ERROR);
  GOLLE_ASSERT (known, GOLLE_ERROR);
  GOLLE_ASSERT (c, GOLLE_ERROR);
  GOLLE_ASSERT (d, GOLLE_ERROR);
  GOLLE_ASSERT (d->c2, GOLLE_ERROR);
  GOLLE_ASSERT (d->s2, GOLLE_ERROR);
  BIGNUM *c1 = NULL, *s1 = NULL;
  golle_error err = GOLLE_OK;
  
  /* Compute c1 = c ^ c2 */
  if (!(c1 = BN_new ())) {
    err = GOLLE_EMEM;
    goto out;
  }
  err = golle_num_xor (c1, c, d->c2);
  if (err != GOLLE_OK) {
    goto out;
  }

  /* Compute s1 = r + c1 * x */
  if (!(s1 = BN_new ())) {
    err = GOLLE_EMEM;
    goto out;
  }
  err = get_s1 (known, d->r1, c1, s1);

 out:
  if (err != GOLLE_OK) {
    golle_num_delete (c1);
    golle_num_delete (s1);
  }
  else {
    d->c1 = c1;
    d->s1 = s1;
  }
  return err;
}

golle_error golle_disj_verify (const golle_schnorr_t *k1,
			       const golle_schnorr_t *k2,
			       const golle_disj_t *d)
{
  /* Show that G^s * t == Y^c for each key */
  golle_error err = check_key (k1, d->s1, d->t1, d->c1);
  if (err == GOLLE_OK) {
    err = check_key (k2, d->s2, d->t2, d->c2);
  }
  return err;
}
