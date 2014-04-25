/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <openssl/bn.h>
#include <golle/numbers.h>
#include <golle/random.h>
#include <golle/types.h>

#if HAVE_STRING_H
#include <string.h>
#endif

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

golle_num_t golle_num_new (void) {
  return BN_new ();
}

void golle_num_delete (golle_num_t n) {
  if (n) {
    BN_free (AS_BN (n));
  }
}

golle_num_t golle_num_new_int (size_t i) {
  golle_num_t n = golle_num_new ();
  if (n) {
    if (!BN_set_word (AS_BN (n), i)) {
      golle_num_delete (n);
      n = NULL;
    }
  }
  return n;
}

golle_error golle_num_generate_rand (golle_num_t r, 
				     const golle_num_t n)
{
  GOLLE_ASSERT (r, GOLLE_ERROR);
  GOLLE_ASSERT (n, GOLLE_ERROR);

  /* Always seed the RNG. */
  golle_error err = golle_random_seed ();
  GOLLE_ASSERT (err == GOLLE_OK, err);

  /* A random number */
  if (!BN_rand_range (r, n)) {
    return GOLLE_EMEM;
  }
  return GOLLE_OK;
}

golle_num_t golle_num_rand (const golle_num_t n) {
  /* Get a new number r */
  golle_num_t r = golle_num_new ();

  /* A random number */
  if (r) {
    golle_error err = golle_num_generate_rand (r, n);
    if (err != GOLLE_OK) {
      golle_num_delete (r);
      r = NULL;
    }
  }
  return r;
}

int golle_num_cmp (const golle_num_t n1, const golle_num_t n2) {
  return BN_cmp (n1, n2);
}

golle_num_t golle_generate_prime (int bits, 
				  int safe, 
				  golle_num_t div)
{
  BIGNUM* num = BN_new ();
  GOLLE_ASSERT (num, NULL);

  /* Always seed the RNG. */
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

golle_error golle_find_generator (golle_num_t g,
				  const golle_num_t p,
				  const golle_num_t q,
				  int n)
{
  BIGNUM *h, *i, *j, *test;
  golle_error err = GOLLE_OK;


  BN_CTX *ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);

  BN_CTX_start (ctx);

  /* Make temporary g */
  if (!(test = BN_CTX_get (ctx))) {
      err = GOLLE_EMEM;
  }

  /* Make random */
  if (err == GOLLE_OK && !(h = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
  }

  /* Get p - 1 */
  if (err == GOLLE_OK) {
    if (!(i = BN_CTX_get (ctx))) {
      err = GOLLE_EMEM;
    }
    else if (!BN_copy (i, p)) {
      err = GOLLE_EMEM;
    }
    else if (!BN_sub_word (i, 1)) {
      err = GOLLE_EMEM;
    }
  }

  /* Get (p - 1) / q */
  if (err == GOLLE_OK) {
    if (!(j = BN_CTX_get (ctx))) {
      err = GOLLE_EMEM;
    }
    else if (!BN_div (j, NULL, i, q, ctx)) {
      err = GOLLE_EMEM;
    }
  }

  /* Just keep looking until we find one. */
  while (err == GOLLE_OK && 
	 (n-- > 0))
   {
     err = golle_random_seed ();
     if (err != GOLLE_OK) {
       err = GOLLE_ECRYPTO;
       break;
     }
     
     if (!BN_rand_range (h, p)) {
       err = GOLLE_ECRYPTO;
       break;
     }

     /* Set g = h^((p-1)/q) */
     if (!BN_mod_exp (test, h, j, q, ctx)) {
       err = GOLLE_EMEM;
       break;
     }

     if (!BN_is_one (test)) {
       /* We don't want 1 */
       break;
     }
   }

  if (!n) {
    err = GOLLE_ENOTFOUND;
  }

  if (err == GOLLE_OK && g != NULL) {
    if (!BN_copy (g, test)) {
      err = GOLLE_EMEM;
    }
  }

  BN_CTX_end (ctx);
  BN_CTX_free (ctx);
  return err;
}

golle_error golle_num_to_bin (const golle_num_t n, golle_bin_t *bin) {
  GOLLE_ASSERT (n, GOLLE_ERROR);
  GOLLE_ASSERT (bin, GOLLE_ERROR);
  
  memset (bin->bin, 0, bin->size);

  size_t size = BN_num_bytes (AS_BN(n));

  if (size > bin->size) {
    golle_error err = golle_bin_resize (bin, size);
    GOLLE_ASSERT (err == GOLLE_OK, GOLLE_EMEM);
  }

  size_t copied = BN_bn2bin (AS_BN(n), (unsigned char *)bin->bin);
  GOLLE_ASSERT (copied > 0, GOLLE_EMEM);

  bin->size = copied;

  return GOLLE_OK;
}

golle_error golle_bin_to_num (const golle_bin_t *bin, golle_num_t n) {
  GOLLE_ASSERT (bin, GOLLE_ERROR);
  GOLLE_ASSERT (n, GOLLE_ERROR);
  GOLLE_ASSERT (bin->size, GOLLE_ERROR);
  GOLLE_ASSERT (bin->bin, GOLLE_ERROR);

  GOLLE_ASSERT (BN_bin2bn (bin->bin, (int)bin->size, AS_BN(n)), GOLLE_EMEM);
  return GOLLE_OK;
}

golle_error golle_num_mod_exp (golle_num_t out, 
			       const golle_num_t base, 
			       const golle_num_t exp, 
			       const golle_num_t mod)
{
  GOLLE_ASSERT (out, GOLLE_ERROR);
  GOLLE_ASSERT (base, GOLLE_ERROR);
  GOLLE_ASSERT (exp, GOLLE_ERROR);
  GOLLE_ASSERT (mod, GOLLE_ERROR);

  BN_CTX *ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);

  golle_error err = GOLLE_OK;
  if (!BN_mod_exp (out, base, exp, mod, ctx)) {
    err = GOLLE_ECRYPTO;
  }
  
  BN_CTX_free (ctx);
  return err;
}

golle_error golle_num_print (FILE *file, const golle_num_t num) {
  GOLLE_ASSERT (file, GOLLE_ERROR);
  GOLLE_ASSERT (num, GOLLE_ERROR);
  golle_error err = GOLLE_OK;

  golle_bin_t buff;
  if (golle_bin_init (&buff, BN_num_bytes (AS_BN(num))) != GOLLE_OK) {
    return GOLLE_EMEM;
  }
  err = golle_num_to_bin (num, &buff);
  if (err == GOLLE_OK) {
    for (size_t i = 0; i < buff.size; i++) {
      unsigned char c = ((unsigned char *)buff.bin)[i];
      fprintf (file, "%02x", c);
    }
  }

  golle_bin_release (&buff);
  return err;
}

golle_error golle_num_xor (golle_num_t out,
			   const golle_num_t x1,
			   const golle_num_t x2)
{
  GOLLE_ASSERT (out, GOLLE_ERROR);
  GOLLE_ASSERT (x1, GOLLE_ERROR);
  GOLLE_ASSERT (x2, GOLLE_ERROR);

  /* Hooking into the guts of BIGNUM */
  BIGNUM *a = AS_BN (x1), *b = AS_BN (x2);
  
  /* Find the biggest number, and the
     maximum number of words to xor. */
  BIGNUM *c = a;
  size_t max = b->top;
  if (b->top > a->top) {
    c = b;
    max = a->top;
  }
  if (!BN_copy (out, c)) {
    return GOLLE_EMEM;
  }

  /* XOR */
  for (int i = 0; i < max; i++) {
    c->d[i] = a->d[i] ^ b->d[i];
  }
  return GOLLE_OK;
}
