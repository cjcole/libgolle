/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/numbers.h>
#include <golle/bin.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "globals.h"

static char hex_to_byte (const char *str) {
  char hex[3] = { *str, *(str + 1), 0 }; 
  return (char)strtol (hex, NULL, 16);
}

static int read_number (FILE *fp, 
			char *line, 
			golle_num_t num) 
{
  golle_bin_t *bin;
  int result = 0;
  golle_error err;

  if (!fgets (line, MAX_LINE_BYTES, fp)) {
    fprintf (stderr, "Unexpected EOF in %s\n", keyfile);
    return 1;
  }

  size_t len = strlen (line);
  bin = golle_bin_new (len / 2);
  assert (bin);

  /* Convert from hexadecimal big-endian into binary buffer */
  for (size_t i = 0; i < bin->size; i++) {
    size_t off = i * 2;
    *((char*)bin->bin + i) = hex_to_byte (line + off);
  }

  err = golle_bin_to_num (bin, num);
  if (err != GOLLE_OK) {
    fprintf (stderr, 
	     "Error %d converting to number in %s\n", 
	     (int)err,  
	     keyfile);
    result = 2;
  }

  golle_bin_delete (bin);
  return result;
}

/* Read key keyfile */
int read_key (void) {

  /* First line contains p, second contains g */
  char *line = NULL;
  golle_num_t p = 0, g = 0;
  int result = 0;
  FILE *fp = NULL;
  golle_error err;
  
  p = golle_num_new ();
  assert (p);
  g = golle_num_new ();
  assert (g);

  fp = fopen (keyfile, "r");
  if (!fp) {
    fprintf (stderr, "Failed to open keyfile %s\n", keyfile);
    result = 1;
    goto out;
  }
  line = malloc (MAX_LINE_BYTES + 1);
  
  if ((result = read_number (fp, line, p)) ||
      (result = read_number (fp, line, g))) {
    goto out;
  }

  err = golle_key_set_public (&key, p, g);
  if (err != GOLLE_OK) {
    fprintf (stderr, 
	     "Error %d. Invalid key in %s\n", 
	     (int)err,
	     keyfile);
    result = 6;
    goto out;
  }
 out:
  if (line) {
    free (line);
  }
  if (fp) {
    fclose (fp);
  }
  golle_num_delete (p);
  golle_num_delete (g);
  return result;
}
