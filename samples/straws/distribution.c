/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle.h>
#include "globals.h"
#include "socklib.h"
#include <string.h>
#include <stdlib.h>
#include "hex2byte.h"

static golle_bin_t hbin = { 0 };

/* Send a buffer */
int send_buff (SOCKET sock, char *buff, int size) {
  int sent = 0;
  while (sent < size) {
    int s = send (sock, buff + sent, size - sent, 0);
    if (s == -1) {
      return 1;
    }
    sent += s;
  }
  return 0;
}

/* Get the h number as a hex string. */
int h_to_bin (golle_num_t num) {
  golle_error err = golle_num_to_bin (num, &hbin);
  if (err != GOLLE_OK) {
    fprintf (stderr, "Error %d converting h to binary\n", err);
    return 1;
  }
  return 0;
}

/* Send name to socket */
int send_name (SOCKET sock) {
  /* First send byte indicating length. */
  char len = (char)strlen (my_name);
  
  if (send (sock, &len, 1, 0) != 1) {
    fprintf (stderr, "Failed to send name length\n");
    return 1;
  }

  /* Now send the name */
  if (send_buff (sock, my_name, len) != 0) {
    fprintf (stderr, "Failed to send name\n");
    return 2;
  }

  return 0;
}


/* Send part of the h product */
int send_h (SOCKET sock) {
  if (send_buffer (sock, &hbin) != 0) {
    fprintf (stderr, "Failed to send the h part\n");
    return 1;
  }
  return 0;
}

/* Receive a socket's name */
int recv_name (SOCKET sock, char *out) {
  char len;
  /* Receive the length */
  if (recv (sock, &len, 1, 0) != 1) {
    fprintf (stderr, "Failed to recv name length\n");
    return 1;
  }

  int pedantic = len;
  if (pedantic > MAX_NAME) {
    fprintf (stderr, "Name length %d too large\n", (int)len);
    return 2;
  }

  int recvd = 0;
  while (recvd < len) {
    int r = recv (sock, out + recvd, len - recvd, 0);
    if (r == -1) {
      fprintf (stderr, "Failed to read name\n");
      return 3;
    }
    recvd += r;
  }

  return 0;
}

/* Receive the h value */
int recv_h (SOCKET sock, golle_num_t out) {
  golle_bin_t bin = { 0 };
  if (recv_buffer (sock, &bin) != 0) {
    return 4;
  }

  golle_error err = golle_bin_to_num (&bin, out);
  if (err != GOLLE_OK) {
    fprintf (stderr, "Failed to convert hex to number.\n");
  }
  golle_bin_clear (&bin);
  return (int)err;
}

/* Distribute keys */
int distribute_key (void) {
  int result;
  golle_num_t temp = golle_num_new ();
  if (!temp) {
    fprintf (stderr, "Memory error\n");
    return 1;
  }

  result = h_to_bin (key.h);
  if (result != 0) {
    return result;
  }

  /* Send name to opponent */
  result = send_name (opponent);
  if (result != 0) {
    return result;
  }
  

  /* Receive name from opponent */
  result = recv_name (opponent, opponent_name);
  if (result != 0) {
    return result;
  }
  printf ("Opponent's name is '%s'\n", opponent_name);
  
  
  /* Send h to opponent */
  result = send_h (opponent);
  if (result != 0) {
    return result;
  }

  /* Receive h from opponent */
  result = recv_h (opponent, temp);
  if (result != 0) {
    return result;
  }
  printf ("Received h from %s\n", opponent_name);

  golle_error err = golle_key_accum_h (&key, temp);
  if (err != GOLLE_OK) {
    result = (int)err;
    fprintf (stderr, "H value accumulation failed.\n");
  }
  

  golle_bin_clear (&hbin);
  golle_num_delete (temp);
  printf ("Key is distributed.\n");
  return result;
}
