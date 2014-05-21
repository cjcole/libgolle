/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle.h>
#include "globals.h"
#include "socklib.h"
#include <string.h>
#include <stdlib.h>
#include "hex2byte.h"

static char *h_as_hex;
static int hex_size;

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
int h_to_hex (golle_num_t num) {
  golle_bin_t bin = { 0 };
  golle_error err = golle_num_to_bin (num, &bin);
  if (err != GOLLE_OK) {
    fprintf (stderr, "Error %d converting h to binary\n", err);
    return 1;
  }

  hex_size = (int)bin.size * 2;
  h_as_hex = malloc (hex_size);
  if (!h_as_hex) {
    fprintf (stderr, "Memory failure.\n");
    return 2;
  }

  for (size_t i = 0; i < bin.size; i++) {
    char c = *((char*)bin.bin + i);
    sprintf (h_as_hex + (i*2), "%02x", (int)c);
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
  if (send_buff (sock, h_as_hex, hex_size) != 0) {
    fprintf (stderr, "Failed to send the h part\n");
    return 1;
  }
  /* Send 0 as delimiter */
  char zero = 0;
  if (send (sock, &zero, 1, 0) != 1) {
    fprintf (stderr, "Failed to send delimiter\n");
    return 2;
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
  /* Read until 0 */
  char *hex = 0;
  size_t size = 0;
  while (size < MAX_LINE_BYTES) {
    char buff[256];
    int read = recv (sock, buff, 255, 0);
    if (read == -1) {
      fprintf (stderr, "Failed to read h\n");
      return 1;
    }

    if (size + read > MAX_LINE_BYTES) {
      fprintf (stderr, "Received h value too long.\n");
      return 2;
    }

    hex = realloc (hex, size + read);
    if (!hex) {
      fprintf (stderr, "Memory error\n");
      return 3;
    }
    memcpy (hex + size, buff, read);
    size += read;

    if (buff[read - 1] == 0) {
      break;
    }
  }
  printf ("Received hex: %s\n", hex);

  size--;
  golle_bin_t *bin = golle_bin_new (size / 2);
  if (!bin) {
    fprintf (stderr, "Memory error.\n");
    return 4;
  }
  for (size_t i = 0; i < bin->size; i++) {
    char byte = hex_to_byte (hex + (i*2));
    char *loc = (char *)bin->bin + i;
    *loc = byte;
  }
  free (hex);

  golle_error err = golle_bin_to_num (bin, out);
  if (err != GOLLE_OK) {
    fprintf (stderr, "Failed to convert hex to number.\n");
  }
  golle_bin_delete (bin);
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

  result = h_to_hex (key.h);
  if (result != 0) {
    return result;
  }

  /* Send name to each peer */
  for (int i = 0; i < connected_players; i++) {
    result = send_name (players[i]);
    if (result != 0) {
      return result;
    }
  }

  /* Receive name from each player */
  for (int i = 0; i < connected_players; i++) {
    result = recv_name (players[i], player_names[i]);
    if (result != 0) {
      return result;
    }
    printf ("Received name '%s' from peer\n", player_names[i]);
  }

  /* Send h to each player */
  for (int i = 0; i < connected_players; i++) {
    result = send_h (players[i]);
    if (result != 0) {
      return result;
    }
  }

  /* Receive h from each player */
  for (int i = 0; i < connected_players; i++) {
    result = recv_h (players[i], temp);
    if (result != 0) {
      return result;
    }
    printf ("Received h from %s\n", player_names[i]);

    golle_error err = golle_key_accum_h (&key, temp);
    if (err != GOLLE_OK) {
      result = (int)err;
      fprintf (stderr, "H value accumulation failed.\n");
      break;
    }
  }

  golle_num_delete (temp);
  printf ("Key is distributed.\n");
  return result;
}
