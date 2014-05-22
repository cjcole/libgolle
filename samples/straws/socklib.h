/*
 * Copyright (C) Anthony Arnold 2014
 */
#ifndef LIBGOLLE_SAMPLES_POKER_SOCKLIB_H
#define LIBGOLLE_SAMPLES_POKER_SOCKLIB_H

#include "globals.h"
#include <golle/bin.h>
#include <golle/numbers.h>
#include <golle/elgamal.h>

/* Set up socket library. Return non-zero on error. */
int initialise_sockets (void);
/* Clean up the socket library. */
void finalise_sockets (void);

/* Set up the listener socket. Return non-zero on error. */
int start_listening (const char *port);

/* Stop the listener socket */
int stop_listening (void);


int recv_buffer (SOCKET sock, golle_bin_t *bin);

int send_buffer (SOCKET sock, const golle_bin_t *bin);

int recv_num (SOCKET sock, golle_num_t num);

int send_num (SOCKET sock, const golle_num_t num);

int recv_eg (SOCKET sock, golle_eg_t *eg);

int send_eg (SOCKET sock, const golle_eg_t *eg);


#endif
