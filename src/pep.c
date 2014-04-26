/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/pep.h>
#include <golle/numbers.h>
#include <openssl/bn.h>

golle_error golle_pep_set (const golle_key_t *egKey,
			   const golle_eg_t *e1,
			   const golle_num_t r1,
			   const golle_eg_t *e2,
			   const golle_num_t r2,
			   golle_schnorr_t *key)
{
  GOLLE_ASSERT (egKey, GOLLE_ERROR);
  GOLLE_ASSERT (e1, GOLLE_ERROR);
  GOLLE_ASSERT (e2, GOLLE_ERROR);
  GOLLE_ASSERT (r1, GOLLE_ERROR);
  GOLLE_ASSERT (r2, GOLLE_ERROR);
  GOLLE_ASSERT (key, GOLLE_ERROR);

  /* Context required for div */
  BN_CTX *ctx = BN_CTX_new();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);
  BN_CTX_start (ctx);

  /* Divide the El Gamal ciphertexts */
  golle_error err = GOLLE_OK;
  golle_num_t Y = NULL, G = NULL, x = NULL, q = NULL;

  /* Allocate the parameters */
  if (!(Y = golle_num_new ()) ||
      !(G = golle_num_new ()) ||
      !(x = golle_num_new ())) {
    err = GOLLE_EMEM;
    goto out;
  }
  /* x = r2 - r1 */
  if (!BN_mod_sub (x, r2, r1, egKey->q, ctx)) {
    err = GOLLE_EMEM;
    goto out;
  }
  /* G = a1 / a2 = g^x */
  if (!BN_mod_exp (G, egKey->g, x, egKey->q, ctx)) {
  /*if (!BN_div (Y, NULL, e1->b, e2->b, ctx)) {*/
    err = GOLLE_EMEM;
    goto out;
  }
  /* Y = b1 / b2 = y^x */
  if (!BN_mod_exp (Y, egKey->h_product, x, egKey->q, ctx)) {
  /*if (!BN_div (G, NULL, e1->a, e2->a, ctx)) {*/
    err = GOLLE_EMEM;
    goto out;
  }
  /* Make the key */
  if (!(q = BN_dup (egKey->q))) {
    err = GOLLE_EMEM;
    goto out;
  }

 out:
  BN_CTX_end (ctx);
  BN_CTX_free (ctx);
  if (err != GOLLE_OK) {
    golle_num_delete (Y);
    golle_num_delete (G);
    golle_num_delete (x);
    golle_num_delete (q);
  }
  else {
    key->G = G;
    key->Y = Y;
    key->q = q;
    key->x = x;
  }
  return err;
}
