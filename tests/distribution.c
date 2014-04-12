/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/distribute.h>
#include <openssl/bn.h>
#include <assert.h>

void produce_h (golle_key_t *target,
		golle_num_t h1,
		golle_num_t h2)
{
  assert (golle_key_accum_h (target, h1));
  assert (golle_key_accum_h (target, h2));
}

int main () {
  /* Three peers, A,B,C */
  golle_key_t
    a = { 0 },
    b = { 0 },
      c = { 0 };


  /* Excluding bit commitment steps. */

  /* A generates the public keys */
  assert (golle_key_gen_public (&a) == GOLLE_OK);

  /* A sends to B and B */
  assert (golle_key_set_public (&c,
				a.p,
				a.q,
				a.g) == GOLLE_OK);
  assert (golle_key_set_public (&b,
				a.p,
				a.q,
				a.g) == GOLLE_OK);


  /* All peers generate private keys */
  assert (golle_key_gen_private (&a) == GOLLE_OK);
  assert (golle_key_gen_private (&b) == GOLLE_OK);
  assert (golle_key_gen_private (&c) == GOLLE_OK);


  /* All peers distribute h to get H */
  produce_h (&a, b.h, c.h);
  produce_h (&b, a.h, c.h);
  produce_h (&c, a.h, b.h);

  /* All should have the same H */
  assert (BN_cmp (a.h_product, b.h_product) == 0);
  assert (BN_cmp (a.h_product, c.h_product) == 0);

  golle_key_cleanup (&a);
  golle_key_cleanup (&b);  
  golle_key_cleanup (&c);

  return 0;
}
