/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle.h>
#include <stdio.h>
#include <string.h>
#include <golle/random.h>
#include "globals.h"
#include "socklib.h"

/*
 * A sample program to show how to use LibGolle.
 * This program allows two clients to connect and player a game
 * of "draw straws". The player with the largest number between 0 and 99
 * wins.
 *
 * Usage: golle_poker name keyfile [port|remote]
 *
 * The name is the username. It must be unique and < 255 characters.
 * 
 * The keyfile is a file containing the output of `lgkg`.
 * All players must use the same keyfile.
 *
 * The port is the local TCP port that the client should attempt to
 * bind to. Must have 1023 < port < 65536. If port is specified,
 * the client will listen for the opponent.
 *
 * If remote is specified, it must be an endpoint of another
 * client in the format host:port where host is a hostname or
 * IP address and port is the port number.
 *
 */

/* The main function */
int main (int argc, char *argv[]) {
  /* Parse arguments */
  int result = parse_arguments (argc, argv);
  if (result) {
    return result;
  }

  /* Populate the public key */
  memset (&key, 0, sizeof key);
  result = read_key ();
  if (result) {
    return result;
  }
  
  /* Initialise the socket library if necessary */
  result = initialise_sockets ();
  if (result) {
    fprintf (stderr, "Failed to initialise socket library.");
    return result;
  }
  
  /* Connect to remote if required */
  if (!is_listener) {
    result = connect_remote (remote_host, remote_port);
    if (result) {
      return result;
    }
  }
  else {
    /* Open listener */
    fprintf (stdout, "Waiting for opponent.\n");
    result = start_listening (local_port);
    if (result) {
      return result;
    }
    
    /* Wait for everyone to be ready */
    result = stop_listening ();
    if (result) {
      return result;
    }
    
    
    if (opponent == INVALID_SOCKET) {
      fprintf (stderr, "No peers.\n");
      return 0;
    }
  }

  /* Do key distribution. */
  result = distribute_key ();
  if (result) {
    return result;
  }
  
  
  /* Deal straws */
  int my_straw, their_straw;
  if (draw_straws (&my_straw, &their_straw) != 0) {
    return result;
  }

  /* Pick winner */
  printf ("======================\n");
  printf ("Your straw is %02d\n", my_straw);
  printf ("Opponent's straw is %02d\n", their_straw);

  if (my_straw > their_straw) {
    printf ("You win!\n");
  }
  else {
    printf ("You lose.\n");
  }
  printf ("======================\n");

  finalise_sockets ();
  golle_random_clear();
  return result;
}
