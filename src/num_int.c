/*
 * Copyright (C) Anthony Arnold 2014
 */

#include "num_int.h"
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <golle/errors.h>

enum {
  GOLLE_INT_BYTES = sizeof (golle_int_t)
};

static int is_prime (uintmax_t p) {
  uintmax_t a = 4, i = 5;
  while (1) {
    uintmax_t b = p / i;
    if (b < i) 
      return 1;

    if (p == b * i)
      return 0;

    a ^= 6;
    i += a;
  }
  return 1;
}

void golle_int_new (golle_int_t i) {
  if (i) {
    i[0] = 0;
  }
}

void golle_int_delete (golle_int_t i) {
  /* nop */
}

void golle_int_import (golle_int_t dest, size_t len, char *bytes) {
  if (dest) {
    dest[0] = 0;
    /* MSB first */
    char *end = bytes + len;
    for (size_t i = 0; i < len; i++) {
      dest[0] |= *bytes++;
      if (i + 1 < len) {
	dest[0] <<= 1;
      }
    }
  }
}

void golle_int_set_ui (golle_int_t dest, unsigned long ui) {
  if (dest) {
    dest[0] = ui;
  }
}


void golle_int_set_si (golle_int_t dest, signed long si) {
  if (dest) {
    dest[0] = (unsigned long long)si;
  }
}

void golle_int_set_hex (golle_int_t dest, const char *hex) {
  if (dest) {
    sscanf (hex, "%x", dest[0]);
  }
}

void golle_int_set_int (golle_int_t dest, const golle_int_t src) {
  if (dest && src) {
    dest[0] = src[0];
  }
}

void golle_int_add (golle_int_t dest, 
		    const golle_int_t lhs, 
		    const golle_int_t rhs)
{
  if (dest && lhs && rhs) {
    dest[0] = lhs[0] + rhs[0];
  }
}

void golle_int_sub (golle_int_t dest, 
		    const golle_int_t lhs, 
		    const golle_int_t rhs)
{
  if (dest && lhs && rhs) {
    dest[0] = lhs[0] - rhs[0];
  }
}


void golle_int_pow (golle_int_t dest, 
		    const golle_int_t base, 
		    const golle_int_t exp,
		    const golle_int_t mod) 
{
  if (dest && base && exp && mod) {
    dest[0] = (uintmax_t)pow (base[0], exp[0]) % mod[0];
  }
}

void golle_int_mul (golle_int_t dest, 
		    const golle_int_t lhs, 
		    const golle_int_t rhs)
{
  if (dest && lhs && rhs) {
    dest[0] = lhs[0] * rhs[0];
  }
}

void golle_int_mod (golle_int_t dest, 
		    const golle_int_t expr, 
		    const golle_int_t mod)
{
  if (dest && expr && mod) {
    dest[0] = expr[0] % mod[0];
  }
}

void golle_int_invert (golle_int_t dest, 
		       const golle_int_t expr, 
		       const golle_int_t mod)
{
  if (dest && expr && mod) {
    dest[0] = (uintmax_t)pow (expr[0], -1) % mod[0];
  }
}

int golle_int_cmp (const golle_int_t lhs, const golle_int_t rhs) {
  GOLLE_ASSERT(lhs && rhs, 0);
  return lhs[0] - rhs[0];
}

void golle_int_divexact (golle_int_t dest, 
			 const golle_int_t num,
			 const golle_int_t den)
{
  if (dest && num && den) {
    dest[0] = num[0] / den[0];
  }
}

void golle_int_gcd (golle_int_t dest,
		    const golle_int_t expr1,
		    const golle_int_t expr2)
{
  if (dest && expr1 && expr2) {
    uintmax_t a = expr1[0], b = expr2[0];

    while (a != b) {
      if (a > b) {
	a = a - b;
      }
      else {
	b = b - a;
      }
    }

    dest[0] = a;
  }
}


void golle_int_nextprime (golle_int_t dest, const golle_int_t from) {
  if (dest && from) {
    uintmax_t p = from[0];

    switch (p) {
    case 0:
    case 1:
    case 2:
      dest[0] = 2;
      return;
    case 3:
      dest[0] = 3;
      return;
    case 4:
    case 5:
      dest[0] = 5;
      return;
    }

    uintmax_t k = p / 6;
    uintmax_t i = p - 6 * k;
    uintmax_t a = i < 2 ? 1 : 5;
    p = 6 * k + a;
    for (i = (3 + a) / 2; !is_prime (p); p += i) {
      i ^= 6;
    }

    dest[0] = p;
  }
}
