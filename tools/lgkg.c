/*
 * Copyright (C) Anthony Arnold 2014
 */

/*
 * LibGolle Key Generator.
 * This tool generates a random safe prime p and generator g
 * of the multiplicative subgroup Gq of Z*p (where q|p).
 * The output is of the following format:
 *
 *   p<newline>g<newline>
 *
 * Where p is the hexadecimal value of the prime p, in big endian
 * format, <newline> is the ASCII line feed character, and
 * g is the hexadecimal value of the generator, in big endiand format.
 *
 * Parameters:
 *     -b, --bits=n    The number of bits that p should be. Default is 1024.
 */

#include <stdio.h>
#include <golle/distribute.h>
#include <golle/numbers.h>
#include <limits.h>
#include <string.h>

static const char *USAGE = "lgkg [-b n|--bits=n]";

static int bits = 1024;

static golle_key_t key = { 0 };

/* Write the generated public key parts p and g to
 * standard output in the correct format.
 */
static void print_key () {
  if (!key.p) {
    fprintf (stderr, "Error: prime not generated\n");
    exit (3);
  }

  if (!key.g) {
    fprintf (stderr, "Error: generator not set\n");
    exit (3);
  }

  golle_num_print (stdout, key.p);
  printf ("\n");
  golle_num_print (stdout, key.g);
  printf ("\n");
}

/* Generate a public key of bits length.
 * Check for errors; if any occur, print a message and exit.
 */
static void gen_key () {
  golle_error err = golle_key_gen_public (&key, bits, INT_MAX);
  if (err != GOLLE_OK) {
    fprintf (stderr, "Error: failed to generate public key. Error %u\n", err);
    exit (2);
  }
}


/* Attempt to extract the number of bits required out of
 * the provided argument. If a bit value > 0 can't be
 * found, the program prints an error and exits.
 */
static void read_bits (const char *arg) {
  bits = atoi (arg);
  if (!bits) {
    fprintf (stderr, "Invalid argument for bits, %s\n", arg);
    exit (1);
  }
}

/* 
 * Print the usage statement to the given file descriptor
 * and then exit with the given error code.
 */
static void print_usage (FILE *fp, int code) {
  fprintf (fp, "%s\n", USAGE);
  exit (code);
}

int main (int argc, char *argv[]) {

  if (argc > 3) {
    print_usage (stderr, 1);
  }

  for (int i = 1; i < argc; i++) {
    if (strcmp (argv[i], "-b") == 0) {
      if (i + 1 == argc) {
	print_usage (stderr, 1);
      }
      read_bits (argv[++i]);
    }
  

    else if (strstr (argv[i], "--bits=") == argv[i]) {
      read_bits (argv[i] + strlen ("--bits="));
    }

    else {
      fprintf (stderr, "Unrecognised option %s\n", argv[i]);
      exit (1);
    }
  }

  fprintf (stderr, "Generating key, please wait...\n");
  gen_key ();
  print_key ();

  return 0;
}





