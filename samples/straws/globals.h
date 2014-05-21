/*
 * Copyright (C) Anthony Arnold 2014
 */
#ifndef LIBGOLLE_SAMPLES_POKER_GLOBALS_H
#define LIBGOLLE_SAMPLES_POKER_GLOBALS_H

#include <golle/platform.h>
#include <golle/distribute.h>

#if GOLLE_WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#define SOCKET int
#define INVALID_SOCKET -1
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#ifndef LIBGOLLE_SAMPLES_POKER_GLOBALS_C
#define EXTERN extern
#else
#define EXTERN
#endif


enum {
  /* Maximum length of the remote host name */
  MAX_REMOTE_NAME = 256,
  /* Maximum length of the keyfile path */
  MAX_KEYFILE_PATH = 256,
  /* Maximum remote port number */
  MAX_PORT = 5,
  /* Maximum number of bytes we're prepared to read in one line. */
  MAX_LINE_BYTES = 4096,
  /* Maximum number of opponents */
  MAX_PLAYERS = 1,
  /* Maximum name length */
  MAX_NAME = 255,
  /* Maximum length of a remote enpoint */
  MAX_REMOTE_ENDPOINT = MAX_REMOTE_NAME + MAX_PORT
};

/* Global data */
EXTERN char keyfile[MAX_KEYFILE_PATH + 1];
EXTERN char local_port[MAX_PORT + 1];
EXTERN char remote_port[MAX_PORT + 1];
EXTERN char remote_host[MAX_REMOTE_NAME + 1];
EXTERN golle_key_t key;
EXTERN SOCKET players[MAX_PLAYERS];
EXTERN char player_endpoints[MAX_PLAYERS][MAX_REMOTE_ENDPOINT + 1];
EXTERN char player_names[MAX_PLAYERS][MAX_NAME + 1];
EXTERN int connected_players;
EXTERN char my_name[MAX_NAME+1];


/* Connect to remote client. */
int connect_remote (const char *host, const char *port);

/* Read from the key file */
int read_key (void);

/* Parse the arguments. Return non-zero on error. */
int parse_arguments (int argc, char *argv[]);

/* Print the usage statement. */
void print_usage (FILE *fd);

/* Do pedersen key distribution */
int distribute_key (void);

/* Parse a remote name into host and port */
int read_remote_name (const char *in, char *addr, char *port);

#endif

