/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/elgamal.h>
#include <openssl/bn.h>
#include <golle/random.h>
#include <limits.h>

#define TOBN(g) ((BIGNUM*)(g))

static golle_error copy_num (golle_num_t *num,
			     const golle_num_t cpy) {
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

golle_error golle_eg_encrypt (golle_key_t *key,
			      golle_num_t m,
			      golle_eg_t *cipher,
			      golle_num_t *rand)
{
  golle_error err = GOLLE_OK;
  BIGNUM *mh, *r = NULL, *rn = NULL, *a, *b;
  BN_CTX *ctx;
  GOLLE_ASSERT (key, GOLLE_ERROR);
  GOLLE_ASSERT (m, GOLLE_ERROR);
  GOLLE_ASSERT (cipher, GOLLE_ERROR);
  GOLLE_ASSERT (key->q, GOLLE_ERROR);
  GOLLE_ASSERT (key->h_product, GOLLE_ERROR);

  ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);

  BN_CTX_start (ctx);

  /* TODO: Cannot encrypt if m is not in Gq.
   This is hard to check so we just do what we
   can and assume the rest.
  */
  if (BN_cmp (TOBN(m), TOBN(key->q)) >= 0) {
    err = GOLLE_EOUTOFRANGE;
    goto out;
  }

  /* Get random r in Z*q */
  
  if (!rand || !*rand) {
    if (!(rn = golle_num_new ())) {
      err = GOLLE_EMEM;
      goto out;
    }
    r = rn;

    err = golle_random_seed ();
    if (err != GOLLE_OK) {
      err = GOLLE_ECRYPTO;
      goto out;
    }

    do {
      if (!BN_rand_range (r, TOBN(key->q))) {
	err = GOLLE_ECRYPTO;
	goto out;
      }
    } while (BN_is_zero (r));

    if (rand) {
      *rand = r;
    }
  }
  else {
    r = *rand;
  }

  /* Calculate g^r */
  if (!(a = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!BN_mod_exp (a, TOBN (key->g), r, TOBN (key->q), ctx)) {
    err = GOLLE_ECRYPTO;
    goto out;
  }

  /* Calculate mh^r */
  if (!(mh = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!(b = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }

  if (!BN_mod_exp(mh, (key->h_product), r, TOBN (key->q), ctx)) {
    err = GOLLE_ECRYPTO;
    goto out;
  }
  if (!BN_mod_mul(b, mh, m, TOBN (key->q), ctx)) {
    err = GOLLE_ECRYPTO;
    goto out;
  }

  err = copy_num (&cipher->b, b);
  if (err == GOLLE_OK) {
    err = copy_num (&cipher->a, a);
  }
 out:
  if (err != GOLLE_OK) {
    if (r) {
      BN_free (r);
      if (rand) {
	*rand = NULL;
      }
    }
    if (cipher->a) {
      golle_num_delete (cipher->a);
      cipher->a = NULL;
    }
    if (cipher->b) {
      golle_num_delete (cipher->b);
    }
  }
      
  BN_CTX_end (ctx);
  BN_CTX_free (ctx);
  
  return err;
}

golle_error golle_eg_decrypt (golle_key_t *key,
			      golle_num_t *xi,
			      size_t len,
			      const golle_eg_t *cipher,
			      golle_num_t m)
{
  BN_CTX *ctx;
  BIGNUM *x, *ax;
  golle_error err = GOLLE_OK;

  GOLLE_ASSERT (key, GOLLE_ERROR);
  GOLLE_ASSERT (xi, GOLLE_ERROR);
  GOLLE_ASSERT (len, GOLLE_ERROR);
  GOLLE_ASSERT (cipher, GOLLE_ERROR);
  GOLLE_ASSERT (cipher->b, GOLLE_ERROR);
  GOLLE_ASSERT (cipher->a, GOLLE_ERROR);
  GOLLE_ASSERT (m, GOLLE_ERROR);
  GOLLE_ASSERT (key->q, GOLLE_ERROR);

  /* Get a context for temporaries. */
  ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);
  BN_CTX_start (ctx);

  /* Calculate a^x */
  if (!(x = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!(ax = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!BN_one (ax)) {
    err = GOLLE_EMEM;
    goto out;
  }

  /* TODO: Montgomery multiplication */
  for (size_t i = 0; i < len; i++) {
    if (!BN_mod_exp (x, cipher->a, TOBN (xi[i]), TOBN(key->q), ctx)) {
      err = GOLLE_ECRYPTO;
      goto out;
    }
    if (!BN_mod_mul (ax, ax, x, TOBN(key->q), ctx)) {
      err = GOLLE_ECRYPTO;
      goto out;
    }
  }

  /* Invert a^x */
  if (!BN_mod_inverse (ax, ax, TOBN(key->q), ctx)) {
    err = GOLLE_ECRYPTO;
    goto out;
  }

  /* Multiply by b */
  if (!BN_mod_mul (m, ax, cipher->b, TOBN(key->q), ctx)) {
    err = GOLLE_ECRYPTO;
    goto out;
  }

 out:
  BN_CTX_end (ctx);
  BN_CTX_free (ctx);
  return err;
}
