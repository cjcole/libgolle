/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/elgamal.h>
#include <openssl/bn.h>
#include <golle/random.h>
#include <limits.h>

#define TOCBN(g) ((const BIGNUM*)(g))
#define TOBN(g) ((BIGNUM*)(g))

/*
 * Make a copy of a BIGNUM object.
 */
static golle_error copy_num (golle_num_t *num,
			     const golle_num_t cpy) 
{
  /* Always check for NULL and make a new
   * value if required.
   */
  if (!(*num)) {
    *num = golle_num_new ();
    if (!*num) {
      return GOLLE_EMEM;
    }
  }
  if (!BN_copy (TOBN(*num), TOBN(cpy))) {
    return GOLLE_EMEM;
  }
  return GOLLE_OK;
}

/* Calculate a * b ^ c mod p */
static golle_error mod_mul_exp (golle_num_t res,
				const golle_num_t a,
				const golle_num_t b,
				const golle_num_t c,
				const golle_num_t p,
				BN_CTX *ctx)
{
  BIGNUM *t;
  golle_error err = GOLLE_OK;
  BN_CTX_start (ctx);

  if (!(t = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  /* Get t = b ^ c */
  if (!BN_mod_exp (t, TOCBN (b), TOCBN (c), TOCBN (p), ctx)) {
    err = GOLLE_ECRYPTO;
    goto out;
  }
  /* res = t * a */
  if (!BN_mod_mul (TOBN (res), t, TOCBN (a), TOCBN (p), ctx)) {
    err = GOLLE_ECRYPTO;
    goto out;
  }

 out:
  BN_CTX_end (ctx);
  return err;
}

/* Calculate the sum of x mod p */
static golle_error mod_sum (golle_num_t r,
			    const golle_num_t *x,
			    size_t len,
			    const golle_num_t p,
			    BN_CTX *ctx)
{
  golle_error err = GOLLE_OK;
  GOLLE_ASSERT (BN_zero (r), GOLLE_ECRYPTO);

  /* Compute the sum. 
     TODO: Consider BN_mod_mul_reciprocal() for speed */
  for (size_t i = 0; i < len; i++) {
    /* Get the product */
    if (!BN_mod_add (TOBN (r), TOCBN (r), TOCBN (x[i]), TOCBN (p), ctx)) {
      err = GOLLE_ECRYPTO;
      break;
    }
  }
  return err;
}

/* Calculate product_i (a ^ x_i) mod p */
static golle_error mod_prod_exp (golle_num_t r,
				const golle_num_t a,
				const golle_num_t *xi,
				size_t len,
				const golle_num_t p,
				BN_CTX *ctx)
{
  BIGNUM *x;
  golle_error err = GOLLE_OK;
  BN_CTX_start (ctx);
  
  if (!(x = BN_CTX_get (ctx))) {
    BN_CTX_end (ctx);
    return GOLLE_EMEM;
  }
  /* Get the sum of the exponents */
  if ((err = mod_sum (x, xi, len, p, ctx)) == GOLLE_OK) {
    /* Exponentitate */
    if (!BN_mod_exp (r, a, x, TOCBN (p), ctx)) {
      err = GOLLE_ECRYPTO;
    }
  }
  BN_CTX_end (ctx);
  return err;
}

/* Get a random r in Zq */
static golle_num_t r_in_Zq (golle_num_t *rand,
			    const golle_num_t q)
{
  BIGNUM *r;
  if (!rand || !*rand) {
    r = golle_num_new ();
    GOLLE_ASSERT (r, NULL);

    do {
      golle_error err = golle_num_generate_rand (r, q);
      if (err != GOLLE_OK) {
	golle_num_delete (r);
	return NULL;
      }
      /* We don't want zero. */
    } while (BN_is_zero (TOCBN (r)));

    if (rand) {
      /* Return the chosen random number if required. */
      *rand = r;
    }
  }
  else {
    r = *rand;
  }

  return r;
}

golle_error golle_eg_encrypt (const golle_key_t *key,
			      const golle_num_t m,
			      golle_eg_t *cipher,
			      golle_num_t *rand)
{
  /*
   * To encrypt m in Gq, we generate a random value
   * r (or use r = rand if it's given to us).
   * Then the ciphertext is (a,b) where
   * a = g^r and b = mh^r.
   */
  golle_error err = GOLLE_OK;
  BIGNUM *r = NULL, *a, *b;
  BN_CTX *ctx;
  GOLLE_ASSERT (key, GOLLE_ERROR);
  GOLLE_ASSERT (m, GOLLE_ERROR);
  GOLLE_ASSERT (cipher, GOLLE_ERROR);
  GOLLE_ASSERT (key->q, GOLLE_ERROR);
  GOLLE_ASSERT (key->p, GOLLE_ERROR);
  GOLLE_ASSERT (key->h_product, GOLLE_ERROR);

  int rand_supplied = (rand && *rand);

  ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);

  BN_CTX_start (ctx);

  /* Cannot encrypt if m is not in Gq.
   This is hard to check so we just do what we
   can and assume the rest.
  */
  if (BN_cmp (TOBN(m), TOBN(key->q)) >= 0) {
    err = GOLLE_EOUTOFRANGE;
    goto out;
  }

  /* Get random r in Z*q */
  if (!(r = r_in_Zq (rand, key->q))) {
    err = GOLLE_EMEM;
    goto out;
  }

  /* Calculate g^r */
  if (!(a = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!BN_mod_exp (a, TOCBN (key->g), r, TOCBN (key->p), ctx)) {
    err = GOLLE_ECRYPTO;
    goto out;
  }

  /* Calculate mh^r */
  if (!(b = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  err = mod_mul_exp (b, m, key->h_product, r, key->p, ctx);
  if (err != GOLLE_OK) {
    goto out;
  }

  /* Store the results (a, b) in cipher.
   * (a, b) is the ciphertext */
  err = copy_num (&cipher->b, b);
  if (err == GOLLE_OK) {
    err = copy_num (&cipher->a, a);
  }
 out:
  if (err != GOLLE_OK) {
    if (!rand_supplied) {
      golle_num_delete (r);
      if (rand) {
	*rand = NULL;
      }
    }
    golle_eg_clear (cipher);
  }
  else if (!rand) {
    golle_num_delete (r);
  }
      
  BN_CTX_end (ctx);
  BN_CTX_free (ctx);
  
  return err;
}

golle_error golle_eg_reencrypt (const golle_key_t *key,
				const golle_eg_t *e1,
				golle_eg_t *e2,
				golle_num_t *rand)
{
  golle_error err = GOLLE_OK;
  BIGNUM *r = NULL, *a, *b;
  BN_CTX *ctx;
  GOLLE_ASSERT (key, GOLLE_ERROR);
  GOLLE_ASSERT (e1, GOLLE_ERROR);
  GOLLE_ASSERT (e2, GOLLE_ERROR);
  GOLLE_ASSERT (key->p, GOLLE_ERROR);
  GOLLE_ASSERT (key->q, GOLLE_ERROR);
  GOLLE_ASSERT (key->h_product, GOLLE_ERROR);
  
  int rand_supplied = (rand && *rand);

  ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);
  BN_CTX_start (ctx);

  /* Get random r in Z*q */
  if (!(r = r_in_Zq (rand, key->q))) {
    err = GOLLE_EMEM;
    goto out;
  }
  /* Allocate numbers */
  if (!(a = BN_CTX_get (ctx)) ||
      !(b = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }

  /* Calculate ag^r */
  err = mod_mul_exp (a, e1->a, key->g, r, key->p, ctx);
  if (err != GOLLE_OK) {
    goto out;
  }

  /* Calculate bh^r */
  err = mod_mul_exp (b, e1->b, key->h_product, r, key->p, ctx);
  if (err != GOLLE_OK) {
    goto out;
  }

  /* Store the results (a, b) in cipher.
   * (a, b) is the ciphertext */
  err = copy_num (&e2->b, b);
  if (err == GOLLE_OK) {
    err = copy_num (&e2->a, a);
  }
 out:
  if (err != GOLLE_OK) {
    if (!rand_supplied) {
      golle_num_delete (r);
      if (rand) {
	*rand = NULL;
      }
    }
    golle_eg_clear (e2);
  }
  
  BN_CTX_end (ctx);
  BN_CTX_free (ctx);
  
  return err; 
}

golle_error golle_eg_decrypt (const golle_key_t *key,
			      const golle_num_t *xi,
			      size_t len,
			      const golle_eg_t *cipher,
			      golle_num_t m)
{
  /*
   * To decrypt we find m =  b / (a^x).
   * Or alternatively, m = inverse(a^x) * b.
   * x must be constructed from the array of xi.
   * x is simply the product of xi mod q.
   */
  BN_CTX *ctx;
  BIGNUM *ax;
  golle_error err = GOLLE_OK;

  GOLLE_ASSERT (key, GOLLE_ERROR);
  GOLLE_ASSERT (xi, GOLLE_ERROR);
  GOLLE_ASSERT (len, GOLLE_ERROR);
  GOLLE_ASSERT (cipher, GOLLE_ERROR);
  GOLLE_ASSERT (cipher->b, GOLLE_ERROR);
  GOLLE_ASSERT (cipher->a, GOLLE_ERROR);
  GOLLE_ASSERT (m, GOLLE_ERROR);
  GOLLE_ASSERT (key->p, GOLLE_ERROR);
  GOLLE_ASSERT (key->q, GOLLE_ERROR);

  /* Get a context for temporaries. */
  ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);
  BN_CTX_start (ctx);

  /* Calculate a^x */
  if (!(ax = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }

  /* Get product of a ^ x for all x. */
  err = mod_prod_exp (ax, cipher->a, xi, len, key->p, ctx);
  if (err != GOLLE_OK) {
    goto out;
  }
  /* Invert a^x */
  if (!BN_mod_inverse (ax, ax, TOBN(key->p), ctx)) {
    err = GOLLE_ECRYPTO;
    goto out;
  }
  /* Multiply by b */
  if (!BN_mod_mul (m, ax, cipher->b, TOBN(key->p), ctx)) {
    err = GOLLE_ECRYPTO;
    goto out;
  }
  /* Now m is the plaintext */
 out:
  BN_CTX_end (ctx);
  BN_CTX_free (ctx);
  return err;
}
