/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/golle.h>
#include <golle/set.h>
#include <golle/distribute.h>
#include <golle/bin.h>
#include <golle/commit.h>
#include <golle/errors.h>
#include <golle/config.h>
#include <golle/elgamal.h>
#include <openssl/bn.h>
#include <limits.h>
#include <assert.h>

#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif

/* Free state flags */
typedef enum FREE_TYPE {
  KEY,
  COPY,
  ELEMENTS,
  EXPONENTS,
  PEERS,
  CIPHERS,
  STATE,
} FREE_TYPE;

#define FREE_FLAG(f) (1 << (f))
#define FREE_ALL (unsigned)-1

typedef struct peer_t {
  int id;
  golle_commit_t key_commit;
} peer_t;

typedef struct elem_t {
  golle_bin_t data;
  size_t index;
  golle_num_t g_exp;
  int selected;
} elem_t;

typedef struct golle_t {
  golle_key_t key;
  elem_t *copy;
  size_t len;
  golle_eg_t *ciphers;
  golle_set_t *elements;
  golle_set_t *exponents;
  golle_set_t *peers;
  int next_id;
  int in_round;
} golle_t;

/*
 * Check to see if all of the public parts of the
 * key are set.
 */
static int pub_key_set (golle_t *state) {
  GOLLE_ASSERT (state, 0);
  GOLLE_ASSERT (state->key.p, 0);
  GOLLE_ASSERT (state->key.q, 0);
  GOLLE_ASSERT (state->key.g, 0);
  GOLLE_ASSERT (state->key.h_product, 0);
  return 1;
}

/*
 * Compare two peer structs. Strict week ordering.
 */
static int compare_peers (const golle_bin_t *peer1, const golle_bin_t *peer2) {
  assert (peer1);
  assert (peer2);
  return ((peer_t *)peer1)->id - ((peer_t*)peer2)->id;
}

/*
 * Compare two element structs. Strict week ordering.
 */
static int compare_elements (const golle_bin_t *elem1, 
			     const golle_bin_t *elem2) {
  assert (elem1);
  assert (elem2);
  return (long int)((elem_t*)elem1)->index - (long int)((elem_t*)elem2)->index;
}

/*
 * Safely release all copied buffers.
 */
static void free_copy (elem_t *elems, size_t len) {
  for (size_t i = 0; i < len; i++) {
    golle_bin_release (&elems[i].data);
    golle_num_delete (elems[i].g_exp);
  }
  free (elems);
}

/*
 * Safely clean up memory for a state.
 */
static void free_state (golle_t *state, int flags) {
  if (state) {
    if (flags & FREE_FLAG (CIPHERS)) {
      if (state->ciphers) {
	for (size_t i = 0; i < state->len; i++) {
	  golle_eg_clear (&state->ciphers[i]);
	}
	free (state->ciphers);
	state->ciphers = NULL;
      }
    }
    if (flags & FREE_FLAG (KEY)) {
      golle_key_cleanup (&state->key);
    }
    if (flags & FREE_FLAG (ELEMENTS)) {
      if (state->elements) {
	golle_set_delete (state->elements);
	state->elements = NULL;
      }
    }
    if (flags & FREE_FLAG (EXPONENTS)) {
      if (state->exponents) {
	golle_set_delete (state->exponents);
	state->exponents = NULL;
      }
    }
    if (flags & FREE_FLAG (PEERS)) {
      if (state->peers) {
	golle_set_delete (state->peers);
	state->peers = NULL;
      }
    }
    if (flags & FREE_FLAG(COPY)) {
      if (state->copy) {
	free_copy (state->copy, state->len);
	state->copy = NULL;
	state->len = 0;
      }
    }
    if (flags & FREE_FLAG (STATE)) {
      free (state);
    }
  }
}

/*
 * Store a copy of the elements.
 */
static golle_error copy_elements (golle_t *state,
				  const void **array,
				  size_t len,
				  size_t size)
{
  free_state (state, FREE_FLAG(COPY));

  elem_t *elems = calloc (sizeof (elem_t), len);
  GOLLE_ASSERT (elems, GOLLE_EMEM);

  /* Copy each element */
  golle_error err = GOLLE_OK;
  size_t i;
  for (i = 0; i < len; i++) {
    elems[i].index = i;
    err = golle_bin_init (&elems[i].data, size);
    if (err != GOLLE_OK) {
      break;
    }
    memcpy (elems[i].data.bin, array[i], len);
  }
  if (err != GOLLE_OK) {
    free_copy (elems, i);
  }
  else {
    state->copy = elems;
    state->len = len;
  }

  return err;
}			 

/*
 * Compute g^i for each element's index i.
 */
static golle_error exp_elems (golle_t *state) {
  BIGNUM *temp;

  BN_CTX *ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);
  BN_CTX_start (ctx);


  golle_error err = GOLLE_OK;
  if (!(temp = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
  }

  size_t i;
  for (i = 0; err == GOLLE_OK && i < state->len; i++) {
    elem_t *elem = &state->copy[i];

    /* Get g^ index of element mod q */
    if (!BN_set_word (temp, elem->index)) {
      err = GOLLE_EMEM;
      break;
    }

    golle_num_t m = golle_num_new ();
    if (!m) {
      err = GOLLE_EMEM;
      break;
    }

    golle_error err = BN_mod_exp (m,
				  state->key.g,
				  temp,
				  state->key.q,
				  ctx);
    if (err != GOLLE_OK) {
      golle_num_delete (m);
      break;
    }

    elem->g_exp = m;
  }

  if (err != GOLLE_OK) {
    for (size_t j = 0; j < i; j++) {
      elem_t *elem = &state->copy[j];
      golle_num_delete (elem->g_exp);
      elem->g_exp = NULL;
    }
  }

  BN_CTX_end (ctx);
  BN_CTX_free (ctx);

  return err;
}

static golle_error encrypt_idx (golle_t *state) {
  size_t i = 0;
  BIGNUM *m, *e, *ilen, *idx;
  BN_CTX *ctx;
  golle_error err = GOLLE_OK;

  golle_eg_t *ciphers = calloc (sizeof (golle_eg_t), state->len);
  GOLLE_ASSERT (ciphers, GOLLE_EMEM);

  ctx = BN_CTX_new ();
  if (!ctx) {
    err = GOLLE_EMEM;
    goto out;
  }
  BN_CTX_start (ctx);

  if (!(m = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!(e = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!(idx = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!(ilen = BN_CTX_get(ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!(BN_set_word (ilen, state->len))) {
    err = GOLLE_EMEM;
    goto out;
  }
 
  for (i = 0; i < state->len; i++) {
    elem_t *elem = &state->copy[i];
    if (!BN_set_word (idx, elem->index)) {
      err = GOLLE_EMEM;
      break;
    }
    if (!BN_mul (e, idx, ilen, ctx)) {
      err = GOLLE_EMEM;
      break;
    }
    if (!BN_mod_exp (m, state->key.g, e, state->key.q, ctx)) {
      err = GOLLE_EMEM;
      break;
    }
    err = golle_eg_encrypt (&state->key,
			    m,
			    &ciphers[i],
			    NULL);
    if (err != GOLLE_OK) {
      break;
    }
  }

  out:
  if (err == GOLLE_OK) {
    free_state (state, FREE_FLAG (CIPHERS));
    state->ciphers = ciphers;
  }
  else {
    for (size_t j = 0; j < i; j++) {
      golle_eg_clear (&ciphers[j]);
    }
    free (ciphers);
  }

  BN_CTX_end (ctx);
  BN_CTX_free (ctx);
  return err;
}

golle_error golle_new (golle_t **state) {
  GOLLE_ASSERT (state, GOLLE_ERROR);
  golle_error err = GOLLE_OK;

  golle_t *s = calloc (sizeof (*s), 1);
  GOLLE_ASSERT (s, GOLLE_EMEM);

  err = golle_set_new (&s->peers, &compare_peers);

  if (err == GOLLE_OK) {
    *state = s;
  }
  else {
    free_state (s, FREE_ALL);
  }
  
  return err;
}

void golle_delete (golle_t *state) {
  free_state (state, FREE_ALL);
}

golle_error golle_elements_set (golle_t *state,
				const void **array,
				size_t len,
				size_t size,
				golle_comp_t *comp)
{
  GOLLE_ASSERT (state, GOLLE_ERROR);
  GOLLE_ASSERT (array, GOLLE_ERROR);
  GOLLE_ASSERT (len, GOLLE_EEMPTY);
  GOLLE_ASSERT (size, GOLLE_ERROR);
  GOLLE_ASSERT (comp, GOLLE_ERROR);
  GOLLE_ASSERT (pub_key_set (state), GOLLE_EINVALID);
  GOLLE_ASSERT (!state->in_round, GOLLE_EINVALID);

  /* Copy the elements into the element array. */
  golle_error err = copy_elements (state, array, len, size);
  GOLLE_ASSERT (err == GOLLE_OK, err);

  /* Compute the exponential for each element. */
  err = exp_elems (state);
  if (err != GOLLE_OK) {
    goto out;
  }

  /* Calculate enc(g^(len * i)) for each peer i */
  err = encrypt_idx (state);
  if (err != GOLLE_OK) {
    goto out;
  }
  
  return GOLLE_OK;
 out:
    free_state (state, FREE_FLAG (COPY));
  
  return err;
}
