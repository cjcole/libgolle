#include "socklib.h"
#include "globals.h"
#include <stdio.h>
#include <pthread.h>
#include <string.h>

static SOCKET listener;
static pthread_t listen_thread;

static void *acceptor_thread (void *data) {
  GOLLE_UNUSED (data);
  struct sockaddr_storage rem_addr;
  socklen_t addr_size = sizeof (rem_addr);
 
  fprintf (stderr, "Accepting incoming connections.\n");
  while (connected_players < MAX_PLAYERS) {
    SOCKET sock = accept (listener,
			  (struct sockaddr *)&rem_addr,
			  &addr_size);

    if (sock == -1) {
      break;
    }


    printf ("Player connected.\n");
    players[connected_players++] = sock;
  }
  fprintf (stderr, "Stopped accepting.\n");
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
    fprintf (stderr, "Failed to get address info error %d\n", status);
    return 1;
  }

  listener = socket (servinfo->ai_family, 
		     servinfo->ai_socktype, 
		     servinfo->ai_protocol);
  if (listener == INVALID_SOCKET) {
    fprintf (stderr, "Failed to get socket\n");
    return 2;
  }

  int yes = 1;
  if (setsockopt (listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
    fprintf (stderr, "Failed to set socket option.");
    return 3;
  }

  if (bind (listener, servinfo->ai_addr, servinfo->ai_addrlen) == -1) {
    fprintf (stderr, "Failed to bind.\n");
    return 4;
  }

  if (listen (listener, MAX_PLAYERS) == -1) {
    fprintf (stderr, "Failed to listen.\n");
    return 5;
  }

  printf ("Opened listener on port %s\n", port);

  /* Kick off thread to accept clients */
  pthread_create (&listen_thread, NULL, &acceptor_thread, NULL);

  freeaddrinfo (servinfo);
  return 0;
}

int stop_listening (void) {
  shutdown (listener, 2);
  pthread_join (listen_thread, NULL);
  return 0;
}
