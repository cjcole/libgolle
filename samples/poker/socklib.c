#include "socklib.h"
#include "globals.h"
#include <golle/errors.h>


#if GOLLE_WINDOWS
int intialise_sockets (void) {
  WSADATA wsaData;
  return WSAStartup (MAKEWORD (2,2), &wsaData);
}
void finalise_sockets (void) {
  WSACleanup ();
}
#else
int initialise_sockets (void) {
  return 0;
}
void finalise_sockets (void) {
  /* nop */
}
#endif

int start_listening (int port) {
  GOLLE_UNUSED (port);
  return 0;
}

int stop_listening (void) {
  return 0;
}
