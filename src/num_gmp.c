/*
 * Copyright (C) Anthony Arnold 2014
 */

#include "num_gmp.h"


void golle_int_new (golle_int_t i) {
  mpz_init (i);
}

void golle_int_delete (golle_int_t i) {
  mpz_clear (i);
}

void golle_int_import (golle_int_t dest, size_t len, char *bytes) {
  mpz_import (dest, len, 1, 1, 0, 0, bytes);
}

void golle_int_set_ui (golle_int_t dest, unsigned long ui) {
  mpz_set_ui (dest, ui);
}

void golle_int_set_si (golle_int_t dest, signed long si) {
  mpz_set_si (dest, si);
}

void golle_int_set_hex (golle_int_t dest, const char *hex) {
  mpz_set_str (dest, hex, 16);
}

void golle_int_set_int (golle_int_t dest, const golle_int_t src) {
  mpz_set (dest, src);
}

void golle_int_add (golle_int_t dest, 
		    const golle_int_t lhs, 
		    const golle_int_t rhs)
{
  mpz_add (dest, lhs, rhs);
}

void golle_int_sub (golle_int_t dest, 
		    const golle_int_t lhs, 
		    const golle_int_t rhs)
{
  mpz_sub (dest, lhs, rhs);
}

void golle_int_pow (golle_int_t dest, 
		    const golle_int_t base, 
		    const golle_int_t exp,
		    const golle_int_t mod)
{
  mpz_powm (dest, base, exp, mod);
}

void golle_int_mul (golle_int_t dest, 
		    const golle_int_t lhs, 
		    const golle_int_t rhs)
{
  mpz_mul (dest, lhs, rhs);
}

void golle_int_mod (golle_int_t dest, 
		    const golle_int_t expr, 
		    const golle_int_t mod)
{
  mpz_mod (dest, expr, mod);
}

void golle_int_invert (golle_int_t dest, 
		       const golle_int_t expr, 
		       const golle_int_t mod) 
{
  mpz_invert (dest, expr, mod);
}

int golle_int_cmp (const golle_int_t lhs, const golle_int_t rhs) {
  return mpz_cmp (lhs, rhs);
}

void golle_int_divexact (golle_int_t dest, 
			 const golle_int_t num,
			 const golle_int_t den)
{
  mpz_divexact (dest, num, den);
}

void golle_int_gcd (golle_int_t dest,
		    const golle_int_t expr1,
		    const golle_int_t expr2)
{
  mpz_gcd (dest, expr1, expr2);
}

void golle_int_nextprime (golle_int_t dest, const golle_int_t from) {
  mpz_nextprime (dest, from);
}
