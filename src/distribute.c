/*
 * Copyright (C) Anthony Arnold 2014
 */


#include <golle/distribute.h>
#include <openssl/bn.h>
#include <golle/random.h>

enum {
  /* Number of bits in q */
  QBITS = 160,
  /* Number of bits in p */
  PBITS = 1024
};

/* Return the right error based on a primality check. */
#define CHECK_PRIME(E) do {\
  switch (err) {\
  case GOLLE_PROBABLY_PRIME:\
    break;\
  case GOLLE_NOT_PRIME:\
    return GOLLE_ENOTPRIME;\
  default:\
    return err;\
  } } while (0)


/* Get h = g^x */
static golle_num_t get_h (const golle_num_t g,
			  const golle_num_t x)
{

  BN_CTX *ctx = BN_CTX_new ();
  if (!ctx) {
    return NULL;
  }
   
  BIGNUM *h = BN_new ();
  if (h) {
    if (!BN_exp (h, g, x, ctx)) {
      BN_free (h);
      h = NULL;
    }
  }
  
  BN_CTX_free (ctx);
  return h;
}


golle_error golle_key_gen_public (golle_key_t *key) {
  GOLLE_ASSERT (key, GOLLE_ERROR);
  golle_key_cleanup (key);

  golle_error err = GOLLE_OK;

  key->q = golle_generate_prime (QBITS, 0, NULL);
  if (!key->q) {
    err = GOLLE_ECRYPTO;
    goto error;
  }

  key->p = golle_generate_prime (PBITS, 0, key->q);
  if (!key->p) {
    err = GOLLE_ECRYPTO;
    goto error;
  }

  /* Find generator */
  key->g = golle_find_generator (key->q, key->p);
  if (!key->g) {
    err = GOLLE_ECRYPTO;
    goto error;
  }

  return GOLLE_OK;

 error:
  golle_key_cleanup (key);
  return err;
}

golle_error golle_key_set_public (golle_key_t *key,
				  const golle_num_t p,
				  const golle_num_t q,
				  const golle_num_t g)
{
  GOLLE_ASSERT (key, GOLLE_ERROR);
  GOLLE_ASSERT (p, GOLLE_ERROR);
  GOLLE_ASSERT (q, GOLLE_ERROR);
  GOLLE_ASSERT (g, GOLLE_ERROR);
  golle_key_cleanup (key);

  /* Check p is prime. */
  golle_error err = golle_test_prime (p);
  CHECK_PRIME (err);

  /* Check q is prime. */
  err = golle_test_prime (q);
  CHECK_PRIME (err);



  BN_CTX *ctx = BN_CTX_new ();
  if (!ctx) {
    return GOLLE_EMEM;
  }

  /* Check g is a generator */
  err = golle_test_generator (g, p, q, ctx);
  if (err != GOLLE_PROBABLY_GENERATOR) {
    BN_CTX_free (ctx);
    return GOLLE_ECRYPTO;
  }


  /* Check q divides p - 1 */
  BN_CTX_start (ctx);

  err = GOLLE_OK;
  BIGNUM *num = BN_CTX_get (ctx);
  if (!num) {
    err = GOLLE_EMEM;
  }
  else if (!BN_mod (num, p, q, ctx)) {
    err = GOLLE_ECRYPTO;
  }
  else if (!BN_is_one (num)) {
    /* Doesn't pass. */
    err = GOLLE_ECRYPTO;
  }

  BN_CTX_end (ctx);
  BN_CTX_free (ctx);

  if (err == GOLLE_OK) {
    if (!(key->p = BN_dup (p))) {
      err = GOLLE_EMEM;
    }
    else if (!(key->q = BN_dup (q))) {
      err = GOLLE_EMEM;
    }
    else if (!(key->g = BN_dup (g))) {
      err = GOLLE_EMEM;
    }
  }

  if (err != GOLLE_OK) {
    golle_key_cleanup (key);
  }
  return err;
}



golle_error golle_key_gen_private (golle_key_t *key) {
  GOLLE_ASSERT (key, GOLLE_ERROR);
  GOLLE_ASSERT (key->q, GOLLE_ERROR);
  GOLLE_ASSERT (key->g, GOLLE_ERROR);

  golle_error err = golle_random_seed ();
  GOLLE_ASSERT (err == GOLLE_OK, err);

  BIGNUM* r = BN_new ();
  GOLLE_ASSERT (r, GOLLE_EMEM);

  err = GOLLE_OK;
  if (!BN_rand_range (r, key->q)) {
    err = GOLLE_EMEM;
  }

  /* Calculate h */
  BIGNUM *h;
  if (err == GOLLE_OK) {
    h = get_h (key->g, r);
    if (!h) {
      err = GOLLE_EMEM;
    }
  }

  if (err == GOLLE_OK) {
    BIGNUM *hp = BN_dup (h);
    if (!hp) {
      err = GOLLE_EMEM;
    }
    else { 
      key->x = r;
      key->h = h;
      golle_num_delete (key->h_product);
      key->h_product = hp;
    }
  }

  if (err != GOLLE_OK) {
    BN_free (r);
  }

  return err;
}


golle_error golle_key_accum_h (golle_key_t *key,
			       const golle_num_t h)
{
  GOLLE_ASSERT (key, GOLLE_ERROR);
  GOLLE_ASSERT (h, GOLLE_ERROR);
  GOLLE_ASSERT (key->h_product, GOLLE_ERROR);

  BN_CTX *ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);

  golle_error err = GOLLE_OK;
  if (!BN_mul (key->h_product, key->h_product, h, ctx)) {
    err = GOLLE_EMEM;
  }

  BN_CTX_free (ctx);
  return err;
}
