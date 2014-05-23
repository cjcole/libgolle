/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/elgamal.h>
#include <golle/random.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
/*
 * This sample program generates an ElGamal key.
 * It then creates a random element in the set Gq and encrypts it
 * using the associated key. Finally, the private key is used to
 * decrypt the ciphertext.
 */
enum {
  NUM_BITS = 100,
  NUM_TRIES = 3
};

#define STR(x) #x
#define PRINT_NUM(x,N)				\
  printf ("%s = ", STR(x));\
  golle_num_print(stdout, N);\
  printf ("\n")

/* Print an error and quit. */
void error_exit (int code, const char *msg, ...) {
  va_list args;
  va_start (args, msg);
  vfprintf(stderr, msg, args);
  va_end (args);
  exit (code);
}

int main (void) {
  /* Generate a key */
  golle_key_t key = { 0 };
  golle_error err = golle_key_gen_public (&key, NUM_BITS, NUM_TRIES);
  if (err != GOLLE_OK) {
    error_exit (err, "Error %d generating public key\n", err);
  }

  /* Print the public parts */
  printf ("Public key:\n");
  PRINT_NUM (p, key.p);
  PRINT_NUM (q, key.q);
  PRINT_NUM (generator, key.g);

  err = golle_key_gen_private (&key);
  if (err != GOLLE_OK) {
    error_exit (err, "Error %d generating private key\n", err);
  }

  /* Generate a random number in Gq */
  golle_num_t rand = golle_num_rand (key.q);
  if (!rand) {
    error_exit (1, "Error generating random number\n");
  }
  /* Get into Gq */
  err = golle_num_mod_exp (rand, key.g, rand, key.q);
  if (err != GOLLE_OK) {
    error_exit (err, "Error %d exponentiating number\n", err);
  }
  /* Print the number */
  printf ("Generated random number r in G_q\n");
  PRINT_NUM (r, rand);

  /* Encrypt */
  golle_eg_t cipher = { 0 };
  err = golle_eg_encrypt (&key, rand, &cipher, NULL);
  if (err != GOLLE_OK) {
    error_exit (err, "Error %d while encrypting\n", err);
  }
  
  printf ("Encrypted r:\n");
  PRINT_NUM (a, cipher.a);
  PRINT_NUM (b, cipher.b);

  /* Decrypt */
  golle_num_t plain = golle_num_new ();
  if (!plain) {
    error_exit (2, "Error creating new number\n");
  }
  err = golle_eg_decrypt (&key, &key.x, 1, &cipher, plain);
  if (err != GOLLE_OK) {
    error_exit (err, "Error %d while decrypting\n", err);
  }

  printf ("Decrypted:\n");
  PRINT_NUM (plaintext, plain);

  /* Clean up */
  golle_num_delete (plain);
  golle_num_delete (rand);
  golle_eg_clear (&cipher);
  golle_key_clear (&key);
  golle_random_clear ();

  return 0;
}
