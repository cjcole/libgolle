/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/bin.h>
#include <golle/errors.h>
#include <golle/platform.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <golle/config.h>

#if HAVE_SSL
#include <openssl/engine.h>
#include <openssl/crypto.h>


static ENGINE *reng = NULL;
static int rand_loaded = 0;

static void unload_hardware_engine () {
  if (!reng)
    return;

  ENGINE_finish (reng);
  ENGINE_free (reng);
  ENGINE_cleanup ();
  reng = NULL;
  rand_loaded = 0;
}

static void load_hardware_engine () {
  if (rand_loaded)
    return;

  OPENSSL_cpuid_setup ();
  ENGINE_load_rdrand ();

  reng = ENGINE_by_id ("rdrand");
  ERR_get_error ();

  if (!reng)
    return;

  int rc = ENGINE_set_default (reng, ENGINE_METHOD_RAND);
  ERR_get_error ();

  if (!rc) {
    unload_hardware_engine ();
  }

  rand_loaded = 1;
}

#define LOAD_HARDWARE_ENGINE load_hardware_engine ();
#define UNLOAD_HARDWARE_ENGINE unload_hardware_engine ();

#else
#define LOAD_HARDWARE_ENGINE
#define UNLOAD_HARDWARE_ENGINE
#endif


golle_error golle_random_seed () {
  RAND_poll ();
  return GOLLE_OK;
}

golle_error golle_random_generate (golle_bin_t *buffer) {
  GOLLE_ASSERT (buffer, GOLLE_ERROR);

  LOAD_HARDWARE_ENGINE

  if (!RAND_status ()) {
    golle_error err = golle_random_seed ();
    GOLLE_ASSERT (err == GOLLE_OK, err);
  }

  
  int rc = RAND_bytes (buffer->bin, buffer->size);
  ERR_get_error ();

  if (rc != 1) {
    return GOLLE_ERROR;
  }
  return GOLLE_OK;
}

golle_error golle_random_clear () {
  UNLOAD_HARDWARE_ENGINE
  RAND_cleanup ();
  return GOLLE_OK;
}

