/*
 * Copyright (C) Anthony Arnold 2014
 */
#include "globals.h"
#include "socklib.h"
#include <string.h>

int connect_remote (const char *host, const char *port) {
  int status;
  struct addrinfo hints;
  struct addrinfo *servinfo;

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  status = getaddrinfo (host, port, &hints, &servinfo);
  if (status != 0) {
    fprintf (stderr, "Failed to get address info for %s %s error %d\n", 
	     host,
	     port,
	     status);
    return 1;
  }

  SOCKET sock = socket (servinfo->ai_family, 
			servinfo->ai_socktype, 
			servinfo->ai_protocol);
  if (sock == -1) {
    fprintf (stderr, "Failed to get socket.\n");
    return 2;
  }

  if (connect (sock, servinfo->ai_addr, servinfo->ai_addrlen) == -1) {
    fprintf (stderr, "Failed to connect to %s %s\n", host, port);
    return 3;
  }

  printf ("Connected to %s:%s\n", host, port);
  players[connected_players++] = sock;

  freeaddrinfo (servinfo);
  return 0;
}
