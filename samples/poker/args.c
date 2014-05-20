/*
 * Copyright (C) Anthony Arnold 2014
 */
#include <stdio.h>
#include <string.h>
#include "globals.h"

void print_usage (FILE *fd) {
  fprintf (fd, "Usage: golle_poker name keyfile port [remote]\n");
}


static int read_port (const char *in, char *out) {
  int port = atoi (in);
  if (port < 1024 || port > 65535) {
    fprintf (stderr, 
	     "Invalid port number %s. Must be > 1023 and < 65536.\n",
	     in);
    return 1;
  }
  strncpy (out, in, MAX_PORT);
  return 0;
}

/* Parse the arguments. Return non-zero on error. */
int parse_arguments (int argc, char *argv[]) {
  if (argc < 4 || argc > 5) {
    print_usage (stderr);
    return 1;
  }

  strncpy (my_name, argv[1], MAX_NAME);
  strncpy (keyfile, argv[2], MAX_KEYFILE_PATH);

  if (read_port (argv[3], local_port) != 0) {
    return 2;
  }

  if (argc > 4) {
    char *colon = strchr(argv[4], ':');
    if (!colon || (colon - argv[4] > MAX_REMOTE_NAME)) {
      fprintf (stderr, "Invalid remote host name.\n");
      return 3;
    }

    *colon = 0;
    strncpy(remote_host, argv[4], MAX_REMOTE_NAME);

    if (read_port (colon + 1, remote_port) != 0) {
      return 4;
    }
  }
  else {
    remote_port[0] = 0;
    remote_host[0] = 0;
  }

  return 0;
}
