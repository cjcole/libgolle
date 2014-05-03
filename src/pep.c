/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/pep.h>
#include <golle/numbers.h>
#include <openssl/bn.h>
#if HAVE_STRING_H
#include <string.h>
#endif

/* Get N = a ^ x mod p */
static BIGNUM *mod_exp (const BIGNUM *a,
			const BIGNUM *x,
			const BIGNUM *p,
			BN_CTX *ctx)
{
  BIGNUM *n = BN_new ();
  GOLLE_ASSERT (n, NULL);

  if (!BN_mod_exp (n, a, x, p, ctx)) {
    BN_free (n);
    return NULL;
  }
  return n;
}

/* Calculate a/b mod p by inverse */
static golle_error a_div_b (golle_num_t out,
			    const golle_num_t a,
			    const golle_num_t b,
			    const golle_num_t p,
			    BN_CTX *ctx)
{
  golle_error err = GOLLE_OK;
  BIGNUM *bi;
  /* Get b inverse */
  BN_CTX_start (ctx);
  if (!(bi = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!BN_mod_inverse (bi, b, (const BIGNUM*)p, ctx)) {
    err = GOLLE_EMEM;
    goto out;
  }
  /* Multiply by a */
  if (!BN_mod_mul (out, a, bi, (const BIGNUM*)p, ctx)) {
    err = GOLLE_EMEM;
    goto out;
  }
 out:
  BN_CTX_end (ctx);
  return err;
}

/* Get G = y ^ z * g */
static golle_num_t get_g (const golle_key_t *key,
			  const golle_num_t z,
			  BN_CTX *ctx)
{
  golle_num_t G = mod_exp (key->h_product, z, key->p, ctx);
  GOLLE_ASSERT (G, NULL);
  if (!BN_mod_mul (G, G, key->g, key->p, ctx)) {
    BN_free (G);
    G = NULL;
  }
  return G;
}

/* Get Y = b^z*a*/
static golle_num_t get_y (const golle_key_t *key,
			  const golle_num_t a,
			  const golle_num_t b,
			  const golle_num_t z,
			  BN_CTX *ctx)
{
  golle_num_t Y = mod_exp (b, z, key->p, ctx);
  GOLLE_ASSERT (Y, NULL);
  if (!BN_mod_mul (Y, Y, a, key->p, ctx)) {
    BN_free (Y);
    Y = NULL;
  }
  return Y;
}

/*
 * Copy p and q of the ElGamal key.
 */
static golle_error copy_pq (const golle_key_t *src,
			    golle_schnorr_t *dest)
{
  GOLLE_ASSERT (dest->p = BN_dup (src->p), GOLLE_EMEM);
  GOLLE_ASSERT (dest->q = BN_dup (src->q), GOLLE_EMEM);
  return GOLLE_OK;
}

/*
 * We compute Y = G ^ x.
 * Thank you to Ari Juels (http://www.arijuels.com) for helping
 * me to understand the protocol. The structure of G can be ignored,
 * we do something sensible here and set it to g^x.
 */
golle_error golle_pep_prover (const golle_key_t *egKey,
			      const golle_num_t k,
			      const golle_num_t z,
			      golle_schnorr_t *key)
{
  GOLLE_ASSERT (egKey, GOLLE_ERROR);
  GOLLE_ASSERT (k, GOLLE_ERROR);
  GOLLE_ASSERT (key, GOLLE_ERROR);
  BN_CTX *ctx = NULL;
  golle_error err = GOLLE_OK;
  golle_schnorr_t sn = { 0 };
  BIGNUM *a, *b;

  /* Context required for exp */
  ctx = BN_CTX_new();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);
  BN_CTX_start (ctx);

  /*Get temporaries */
  if (!(a = BN_CTX_get (ctx)) ||
      !(b = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!BN_mod_exp (b, egKey->h_product, k, egKey->p, ctx) ||
      !BN_mod_exp (a, egKey->g, k, egKey->p, ctx)) {
    err = GOLLE_ECRYPTO;
    goto out;
  }

  /* G = y^z * g, Y = b^z * a */
  if (!(sn.G = get_g (egKey, z, ctx)) ||
      !(sn.Y = get_y (egKey, a, b, z, ctx))) {
    err = GOLLE_ECRYPTO;
    goto out;
  }

  /* Store the private key */
  if (!(sn.x = BN_dup (k))) {
    err = GOLLE_EMEM;
    goto out;
  }
  /* Make the key */
  err = copy_pq (egKey, &sn);

 out:
  BN_CTX_free (ctx);
  if (err != GOLLE_OK) {
    golle_schnorr_clear (&sn);
  }
  else {
    memcpy (key, &sn, sizeof (sn));
  }
  return err;
}

golle_error golle_pep_verifier (const golle_key_t *egKey,
				const golle_num_t z,
				const golle_eg_t *e1,
				const golle_eg_t *e2,
				golle_schnorr_t *key)
{
  GOLLE_ASSERT (egKey, GOLLE_ERROR);
  GOLLE_ASSERT (e1, GOLLE_ERROR);
  GOLLE_ASSERT (e2, GOLLE_ERROR);
  GOLLE_ASSERT (key, GOLLE_ERROR);
  BN_CTX *ctx = NULL;
  golle_error err = GOLLE_OK;
  golle_schnorr_t sn = { 0 };
  BIGNUM *a, *b;

  /* Context required for div */
  ctx = BN_CTX_new();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);
  BN_CTX_start (ctx);

  /*Get temporaries */
  if (!(a = BN_CTX_get (ctx)) ||
      !(b = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  if ((err = a_div_b (a, e2->a, e1->a, egKey->p, ctx)) != GOLLE_OK ||
      (err = a_div_b (b, e2->b, e1->b, egKey->p, ctx)) != GOLLE_OK) {
    goto out;
  }
  /* G = y^z * g, Y = b^z * a */
  if (!(sn.G = get_g (egKey, z, ctx)) ||
      !(sn.Y = get_y (egKey, a, b, z, ctx))) {
    err = GOLLE_ECRYPTO;
    goto out;
  }
  /* Make the key */
  err = copy_pq (egKey, &sn);

 out:
  BN_CTX_end (ctx);
  BN_CTX_free (ctx);
  if (err != GOLLE_OK) {
    golle_schnorr_clear (&sn);
  }
  else {
    memcpy (key, &sn, sizeof (sn));
  }
  return err;
}
