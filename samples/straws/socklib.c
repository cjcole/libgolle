#include "socklib.h"
#include "globals.h"
#include <stdio.h>
#include <string.h>

static SOCKET listener;

int recv_buffer (SOCKET sock, golle_bin_t *bin) {
  uint32_t size;
  if (recv (sock, &size, 4, 0) != 4) {
    perror ("draw");
    return 1;
  }
  size = ntohl (size);
  /* Sanity check the size */
  if (size > 1 << 15) {
    fprintf (stderr, "Buffer size %d too large.\n", size);
    return -1;
  }

  golle_error err = golle_bin_resize (bin, size);
  if (err != GOLLE_OK) {
    fprintf (stderr, "Buffer resize fail\n");
    return err;
  }

  int recvd = 0;
  char *buff = (char *)bin->bin;
  while (recvd < (int)size) {
    int r = recv (sock, buff + recvd, (int)size - recvd, 0);
    if (r == -1) {
      perror ("draw");
      return 2;
    }
    recvd += r;
  }
  return 0;
}

int send_buffer (SOCKET sock, golle_bin_t *bin) {
  uint32_t size = bin->size;
  size = htonl (size);
  if (send (sock, &size, 4, 0) != 4) {
    perror ("draw");
    return 1;
  }

  int sent = 0;
  char *buff = (char *)bin->bin;

  while (sent < (int)bin->size) {
    int s = send (sock, buff + sent, (int)bin->size - sent, 0);
    if (s == -1) {
      perror ("draw");
      return 2;
    }
    sent += s;
  }
  return 0;
}

int recv_num (SOCKET sock, golle_num_t num) {
  golle_bin_t bin = { 0 };
  if (recv_buffer (sock, &bin) != 0) {
    return 1;
  }

  golle_error err = golle_bin_to_num (&bin, num);
  golle_bin_clear (&bin);
  if (err != GOLLE_OK) {
    fprintf (stderr, "Error %d bin2num\n", err);
    return err;
  }
  return 0;
}

int send_num (SOCKET sock, golle_num_t num) {

  golle_bin_t bin = { 0 };
  golle_error err = golle_num_to_bin (num, &bin);
  if (err != GOLLE_OK) {
    fprintf (stderr, "Error %d num2bin\n", err);
    return err;
  }
  
  int res = send_buffer (sock, &bin);
  golle_bin_clear (&bin);
  return res;
}

int recv_eg (SOCKET sock, golle_eg_t *eg) {
  if (recv_num (sock, eg->a) == 0 &&
      recv_num (sock, eg->b) == 0)
    {
      return 0;
    }
  return 1;
}

int send_eg (SOCKET sock, golle_eg_t *eg) {
  if (send_num (sock, eg->a) == 0 &&
      send_num (sock, eg->b) == 0)
    {
      return 0;
    }
  return 1;
}

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
