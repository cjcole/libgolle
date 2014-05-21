#include "socklib.h"
#include "globals.h"
#include <stdio.h>
#include <string.h>

static SOCKET listener;

static int save_socket (SOCKET sock) {
  int id = connected_players++;
  players[id] = sock;
  return 0;
}

static int run_accept (void) {
  struct sockaddr_storage rem_addr;
  socklen_t addr_size = sizeof (rem_addr);
 
  printf ("Accepting incoming connections.\n");
  SOCKET sock = accept (listener,
			(struct sockaddr *)&rem_addr,
			&addr_size);
  
  if (sock == -1) {
    return 1;
  }
  
  
  printf ("Player connected.\n");
  
  /* Save the socket */
  if (save_socket (sock) != 0) {
    shutdown (sock, 2);
    return 1;
  }
  return 0;
}

static void close_conns(void) {
  for (int i = 0; i < connected_players; i++) {
    shutdown (players[i], 2);
  }
}

#if GOLLE_WINDOWS
int intialise_sockets (void) {
  WSADATA wsaData;
  connected_players = 0;
  return WSAStartup (MAKEWORD (2,2), &wsaData);
}
void finalise_sockets (void) {
  close_conns();
  WSACleanup ();
}
#else
int initialise_sockets (void) {
  connected_players = 0;
  return 0;
}
void finalise_sockets (void) {
  close_conns();
}
#endif

int start_listening (const char *port) {
  int status;
  struct addrinfo hints;
  struct addrinfo *servinfo;

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  status = getaddrinfo (NULL, port, &hints, &servinfo);
  if (status != 0) {
    perror ("socklib");
    return 1;
  }

  listener = socket (servinfo->ai_family, 
		     servinfo->ai_socktype, 
		     servinfo->ai_protocol);
  if (listener == INVALID_SOCKET) {
    perror ("socklib");
    return 2;
  }

  int yes = 1;
  if (setsockopt (listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
    perror ("socklib");
    return 3;
  }

  if (bind (listener, servinfo->ai_addr, servinfo->ai_addrlen) == -1) {
    perror ("socklib");
    return 4;
  }

  if (listen (listener, MAX_PLAYERS) == -1) {
    perror ("socklib");
    return 5;
  }

  printf ("Opened listener on port %s\n", port);
  freeaddrinfo (servinfo);

  /* Kick off thread to accept clients */
  if (run_accept() != 0) {
    fprintf (stderr, "Had trouble accepting opponent.\n");
    return 1;
  }

  return 0;
}

int stop_listening (void) {
  shutdown (listener, 2);
  return 0;
}
