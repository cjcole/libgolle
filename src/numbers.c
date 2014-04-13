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
  GENERATOR_CAP = 1000000
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
