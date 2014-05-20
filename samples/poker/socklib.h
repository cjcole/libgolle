/*
 * Copyright (C) Anthony Arnold 2014
 */
#ifndef LIBGOLLE_SAMPLES_POKER_SOCKLIB_H
#define LIBGOLLE_SAMPLES_POKER_SOCKLIB_H

/* Set up socket library. Return non-zero on error. */
int initialise_sockets (void);
/* Clean up the socket library. */
void finalise_sockets (void);

/* Set up the listener socket. Return non-zero on error. */
int start_listening (const char *port);

/* Stop the listener socket */
int stop_listening (void);

#endif
