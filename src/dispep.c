/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/dispep.h>
#include "numbers.h"
#if HAVE_STRING_H
#include <string.h>
#endif

/* Compute a Schnorr key (G,Y) = (a/a1,b/b1) */
static golle_error compute_key (const golle_eg_t *e1,
				const golle_eg_t *e2,
				golle_schnorr_t *k,
				const golle_key_t *key,
				BN_CTX *ctx)
{
  k->G = golle_num_new ();
  k->Y = golle_num_new ();
  golle_error err = golle_mod_div (k->G, e1->a, e2->a, key->p, ctx);
  if (err == GOLLE_OK) {
    err = golle_mod_div (k->Y, e1->b, e2->b, key->p, ctx);
  }
  return err;
}

/* Duplicate p, q, x */
static golle_error duplicate_key (const golle_key_t *key,
				  golle_schnorr_t *k)
{
  /* Make copies of p,q,x */
  if (!(k->p = BN_dup (key->p)) ||
      !(k->q = BN_dup (key->q)) ||
      !(k->x = BN_dup (key->x)))
    {
      return GOLLE_EMEM;
    }
  return GOLLE_OK;
}

golle_error golle_dispep_setup (const golle_eg_t *r,
				const golle_eg_t *e1,
				const golle_eg_t *e2,
				golle_schnorr_t *k1,
				golle_schnorr_t *k2,
				const golle_key_t *key)
{
  GOLLE_ASSERT (r, GOLLE_ERROR);
  GOLLE_ASSERT (e1, GOLLE_ERROR);
  GOLLE_ASSERT (e2, GOLLE_ERROR);
  GOLLE_ASSERT (k1, GOLLE_ERROR);
  GOLLE_ASSERT (k2, GOLLE_ERROR);
  GOLLE_ASSERT (key, GOLLE_ERROR);
  GOLLE_ASSERT (key->p, GOLLE_ERROR);

  golle_error err = GOLLE_OK;
  golle_schnorr_t t1 = { 0 }, t2 = { 0 };

  /* Number context for divisions. */
  BN_CTX *ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);

  /* Make copies of p,q,x */
  if ((err = duplicate_key (key, &t1)) != GOLLE_OK ||
      (err = duplicate_key (key, &t2)) != GOLLE_OK)
    {
      goto out;
    }

  /* Compute (Y1,G1) = (b/b1,a/a1) */
  err = compute_key (r, e1, &t1, key, ctx);
  if (err == GOLLE_OK) {
    err = compute_key (r, e2, &t2, key, ctx);
  }

 out:
  BN_CTX_free (ctx);

  if (err == GOLLE_OK) {
    memcpy (k1, &t1, sizeof (t1));
    memcpy (k2, &t2, sizeof (t2));
  }
  else {
    golle_schnorr_clear (&t1);
    golle_schnorr_clear (&t2);
  }
  return err;
}
