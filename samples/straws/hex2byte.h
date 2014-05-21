/*
 * Copyright (C) Anthony Arnold 2014
 */
#ifndef LIBGOLLE_SAMPLES_POKER_HEX2BYTE_H
#define LIBGOLLE_SAMPLES_POKER_HEX2BYTE_H
#include <golle/platform.h>
#include <string.h>

GOLLE_INLINE char hex_to_byte (const char *str) {
  char hex[3] = { *str, *(str + 1), 0 }; 
  return (char)strtol (hex, NULL, 16);
}

#endif
