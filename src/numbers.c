/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <openssl/bn.h>
#include <golle/numbers.h>
#include <golle/random.h>

/*
 * Shorthand for goto error;
 */
#define ERR_ASSERT(E) do { if (!(E)) { goto error; } } while (0)

/*
 * Convert a golle_num_t to a BIGNUM*
 */
#define AS_BN(gn) ((BIGNUM*)(gn))

/*
 * Convert a BIGNUM* to a golle_num_t
 */
#define AS_GN(bn) ((golle_num_t)(bn))

/*
 * Maximum search field
 */
enum {
  GENERATOR_CAP = 1000
};

void golle_num_delete (golle_num_t n) {
  if (n) {
    BN_free (AS_BN (n));
  }
}

golle_num_t golle_generate_prime (int bits, 
				  int safe, 
				  golle_num_t div)
{
  BIGNUM* num = BN_new ();
  GOLLE_ASSERT (num, NULL);

  golle_error err = golle_random_seed ();
  GOLLE_ASSERT (err == GOLLE_OK, NULL);

  if (!BN_generate_prime_ex (num, bits, safe, AS_BN(div), NULL, NULL)) {
    BN_free (num);
    return NULL;
  }

  return AS_GN (num);
}

golle_error golle_test_prime (golle_num_t p) {
  GOLLE_ASSERT (p, GOLLE_ERROR);

  BN_CTX *ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);

  golle_error err;
  if (BN_is_prime_ex (AS_BN (p), BN_prime_checks, ctx, NULL)) {
    err = GOLLE_PROBABLY_PRIME;
  }
  else {
    err = GOLLE_NOT_PRIME;
  }

  BN_CTX_free (ctx);
  return err;
}

golle_error golle_test_generator (const golle_num_t g,
				  const golle_num_t q,
				  const golle_num_t p,
				  void *ctx)
{
  int free_ctx;
  BIGNUM *t;
  golle_error err;
  
  GOLLE_ASSERT (g, GOLLE_ERROR);
  GOLLE_ASSERT (p, GOLLE_ERROR);
  GOLLE_ASSERT (q, GOLLE_ERROR);
  
  if (!ctx) {
    ctx = BN_CTX_new ();
    GOLLE_ASSERT (ctx, GOLLE_EMEM);
    free_ctx = 1;
  }
  else {
    free_ctx = 0;
  }
  BN_CTX_start (ctx);

  err = GOLLE_PROBABLY_NOT_GENERATOR;
  if (!(t = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  
  if (!BN_mod_exp (t, g, q, p, ctx)) {
    err = GOLLE_EMEM;
    goto out;
  }
  
  if (BN_is_one (t)) {
#if 0
    /* We have found a likely generator for Gq */
    if (!BN_sqr (t, g, ctx)) {
      err = GOLLE_EMEM;
    }
    else if (!BN_is_one (t)) {
      /* We have found a likely generator for Gq
	 that IS NOT of order 1 or 2. */
      err = GOLLE_PROBABLY_GENERATOR;
    }
#endif
    err = GOLLE_PROBABLY_GENERATOR;
  }

 out:
  BN_CTX_end (ctx);
  if (free_ctx) {
    BN_CTX_free (ctx);
  }

  return err;
}

golle_num_t golle_find_generator (const golle_num_t p, const golle_num_t q) {
  BN_CTX *ctx = NULL;
  BIGNUM* g = NULL;

  
  ERR_ASSERT (ctx = BN_CTX_new ());
  BN_CTX_start (ctx);

  ERR_ASSERT (g = BN_CTX_get (ctx));

  /* Start at two. */
  ERR_ASSERT(BN_set_word (g, 2));

  while (1) {
    ERR_ASSERT (!BN_is_word (g, GENERATOR_CAP));
    golle_error err = golle_test_generator (g, p, q, ctx);

    if (err == GOLLE_PROBABLY_GENERATOR) {
      break;
    }
    if (err != GOLLE_PROBABLY_NOT_GENERATOR) {
      goto error;
    }
 

    ERR_ASSERT (BN_add (g, g, BN_value_one ()));
  }

  goto out;
  
 error:
  if (g) {
    BN_free (g);
    g = NULL;
  }

 out:
  if (ctx) {
    BN_CTX_end (ctx);
    BN_CTX_free (ctx);
  }

  return AS_GN(g);
}
