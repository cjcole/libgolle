/*
 * Copyright (C) Anthony Arnold 2014
 */


#include <golle/distribute.h>
#include <openssl/bn.h>
#include <golle/random.h>

enum {
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
static golle_num_t get_h (const golle_num_t x,
			  const golle_num_t p,
			  const golle_num_t g)
{
  BIGNUM *h;
  BN_CTX *ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, NULL);

  if (!(h = BN_new ())) {
    goto out;
  }
  

  if (!BN_mod_exp (h, g, x, p, ctx)) {
    BN_free (h);
    h = NULL;
  }

  
 out:
  BN_CTX_free (ctx);
  return h;
}

/* Get q = (p - 1) / 2 */
static golle_num_t get_q (const golle_num_t p) 
{
  BIGNUM *q = BN_new ();
  if (q) {
    if (!BN_sub (q, p, BN_value_one ())) {
      BN_free (q);
      q = NULL;
    }
    else if (!BN_rshift1 (q, q)) {
      BN_free (q);
      q = NULL;
    }
  }

  return q;
}


golle_error golle_key_gen_public (golle_key_t *key,
				  int bits,
				  int n) 
{
  GOLLE_ASSERT (key, GOLLE_ERROR);
  golle_key_cleanup (key);

  golle_error err = GOLLE_OK;

  /* Get a safe prime ((p - 1) / 2) = q */
  if (bits <= 0) {
    bits = PBITS;
  }
  key->p = golle_generate_prime (bits, 1, 0);
  if (!key->p) {
    err = GOLLE_ECRYPTO;
    goto error;
  }

  key->q = get_q (key->p);
  if (!key->q) {
    err = GOLLE_EMEM;
    goto error;
  }

  /* Get a generator for g */
  key->g = BN_new ();
  if (!key->g) {
    err = GOLLE_EMEM;
    goto error;
  }
  err = golle_find_generator (key->g, key->p, key->q, n);
  if (err != GOLLE_OK) {
    goto error;
  }

  return GOLLE_OK;

 error:
  golle_key_cleanup (key);
  return err;
}

golle_error golle_key_set_public (golle_key_t *key,
				  const golle_num_t p,
				  const golle_num_t g)
{
  GOLLE_ASSERT (key, GOLLE_ERROR);
  GOLLE_ASSERT (p, GOLLE_ERROR);
  GOLLE_ASSERT (g, GOLLE_ERROR);
  golle_key_cleanup (key);

  /* Check p is prime. */
  golle_error err = golle_test_prime (p);
  CHECK_PRIME (err);


  /* Check q = (p-1)/2 is prime*/
  key->q = get_q (p);

  if (!key->q) {
    err = GOLLE_EMEM;
  }
  else {
    err = golle_test_prime (key->q);

    if (err != GOLLE_PROBABLY_PRIME) {
      err = GOLLE_ECRYPTO;
    } else {
      err = GOLLE_OK;
    }
  }

  /* Check that g is probably a good generator */
  if (BN_is_one ((BIGNUM*)g)) {
    err = GOLLE_ECRYPTO;
  }
  

  if (err == GOLLE_OK) {
    if (!(key->p = BN_dup (p))) {
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


  golle_error err = golle_random_seed ();
  GOLLE_ASSERT (err == GOLLE_OK, err);
  

  BIGNUM* r = BN_new ();
  GOLLE_ASSERT (r, GOLLE_EMEM);

  err = GOLLE_OK;
  if (!BN_rand_range (r, key->q)) {
    err = GOLLE_EMEM;
  }

  /* Calculate h = g^x mod p*/
  BIGNUM *h;
  if (err == GOLLE_OK) {
    h = get_h (r, key->p, key->g);
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
