/*
 * Copyright (C) Anthony Arnold 2014
 */
#include <stdio.h>
#include <string.h>
#include "globals.h"

void print_usage (FILE *fd) {
  fprintf (fd, "Usage: golle_poker keyfile port [remote]\n");
}

/* Parse the arguments. Return non-zero on error. */
int parse_arguments (int argc, char *argv[]) {
  if (argc < 3 || argc > 4) {
    print_usage (stderr);
    return 1;
  }

  strncpy (keyfile, argv[1], MAX_KEYFILE_PATH);

  local_port = atoi (argv[2]);
  if (local_port < 1024 || local_port > 65535) {
    fprintf (stderr, 
	     "Invalid local port number %d. Must be > 1023 and < 65536.\n",
	     local_port);
    return 2;
  }

  if (argc > 3) {
    char *colon = strchr(argv[3], ':');
    if (!colon || (colon - argv[3] > MAX_REMOTE_NAME)) {
      fprintf (stderr, "Invalid remote host name.\n");
      return 3;
    }

    *colon = 0;
    strncpy(remote_host, argv[3], MAX_REMOTE_NAME);

    int port = atoi (colon + 1);
    if (port < 1024 || port > 65535) {
      fprintf (stderr, 
	       "Invalid remote port number %d. Must be > 1023 and < 65536.\n",
	       local_port);
      return 4;
    }
    strncpy (remote_port, colon, MAX_REMOTE_PORT);
  }
  else {
    remote_port[0] = 0;
    remote_host[0] = 0;
  }

  return 0;
}
