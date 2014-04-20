/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/config.h>
#include <golle/commit.h>
#include <golle/types.h>
#include <golle/random.h>
#include <openssl/evp.h>
#include <string.h>
#include <limits.h>

enum {
  RANDOM_BITS = (COMMIT_RANDOM_BITS + CHAR_BIT - 1) & ~(CHAR_BIT -1),
  RANDOM_BYTES = (RANDOM_BITS + CHAR_BIT - 1) / CHAR_BIT
};


#define ASSERT_FULL_COMMIT(commitment)\
  GOLLE_ASSERT (commitment, GOLLE_ERROR);\
  GOLLE_ASSERT (commitment->secret, GOLLE_ERROR);\
  GOLLE_ASSERT (commitment->rsend, GOLLE_ERROR);\
  GOLLE_ASSERT (commitment->rkeep, GOLLE_ERROR);\
  GOLLE_ASSERT (commitment->hash, GOLLE_ERROR);\
  GOLLE_ASSERT (commitment->secret->bin, GOLLE_ERROR);\
  GOLLE_ASSERT (commitment->rsend->bin, GOLLE_ERROR);\
  GOLLE_ASSERT (commitment->rkeep->bin, GOLLE_ERROR);\
  GOLLE_ASSERT (commitment->hash->bin, GOLLE_ERROR);


/*
 * Create a random buffer
 */
static golle_bin_t *random_buffer (void) {
  golle_bin_t *rand = golle_bin_new (RANDOM_BYTES);
  if (rand) {
    golle_error err = golle_random_generate (rand);
    if (err != GOLLE_OK) {
      golle_bin_delete (rand);
      rand = NULL;
    }
  }
  return rand;
}

/*
 * Create a hash. ALWAYS IN THE ORDER: rsend, rkeep, secret.
 */
static golle_bin_t *get_hash (const golle_bin_t *rsend,
		       const golle_bin_t *rkeep,
		       const golle_bin_t *secret)
{
  golle_bin_t *hash = NULL;

  EVP_MD_CTX *ctx = EVP_MD_CTX_create ();
  GOLLE_ASSERT (ctx, NULL);

  if (!EVP_DigestInit_ex (ctx, EVP_sha512(), NULL)) {
    goto out;
  }

  if (!EVP_DigestUpdate (ctx, rsend->bin, rsend->size)) {
    goto out;
  }

  if (!EVP_DigestUpdate (ctx, rkeep->bin, rkeep->size)) {
    goto out;
  }

  if (!EVP_DigestUpdate (ctx, secret->bin, secret->size)) {
    goto out;
  }

  hash = golle_bin_new ((size_t)EVP_MD_CTX_size (ctx));
  if (hash) {
    if (!EVP_DigestFinal_ex (ctx, hash->bin, NULL)) {
      golle_bin_delete (hash);
      hash = NULL;
    }
  }

 out:
    EVP_MD_CTX_destroy (ctx);
    return hash;
}


golle_commit_t *golle_commit_new (const golle_bin_t *secret) {
  GOLLE_ASSERT (secret, NULL);
  GOLLE_ASSERT (secret->bin, NULL);
  GOLLE_ASSERT (secret->size, NULL);

  golle_commit_t *commit = NULL;
  golle_bin_t
    *secret_copy = NULL,
    *rkeep = NULL,
    *rsend = NULL,
    *hash = NULL;

  /* Copy the secret. */
  secret_copy = golle_bin_copy (secret);
  if (!secret_copy) {
    goto error;
  }

  /* Generate the two random values */
  rsend = random_buffer ();
  if (!rsend) {
    goto error;
  }

  rkeep = random_buffer ();
  if (!rkeep) {
    goto error;
  }

  
  hash = get_hash (rsend, rkeep, secret_copy);
  if (!hash) {
    goto error;
  }

  commit = malloc (sizeof (*commit));
  if (!commit) {
    goto error;
  }


  commit->secret = secret_copy;
  commit->rsend = rsend;
  commit->rkeep = rkeep;
  commit->hash = hash;
  
  return commit;

  /* General error handling. */
 error:
  golle_bin_delete (secret_copy);
  golle_bin_delete (rsend);
  golle_bin_delete (rkeep);
  golle_bin_delete (hash);
  return NULL;
}

void golle_commit_delete (golle_commit_t *commitment) {
  if (commitment) {
    golle_bin_delete (commitment->secret);
    golle_bin_delete (commitment->rsend);
    golle_bin_delete (commitment->rkeep);
    golle_bin_delete (commitment->hash);
    free (commitment);
  }
}


golle_error golle_commit_verify (const golle_commit_t *commitment) {
  ASSERT_FULL_COMMIT (commitment);

  golle_bin_t *check = get_hash (commitment->rsend,
				 commitment->rkeep,
				 commitment->secret);

  GOLLE_ASSERT (check, GOLLE_ECRYPTO);

  golle_error err = GOLLE_COMMIT_PASSED;
  
  if (check->size != commitment->hash->size) {
    err = GOLLE_ECRYPTO;
  }
  else {
    int cmp = memcmp (check->bin, commitment->hash->bin, check->size);
    if (cmp) {
      /* Didn't hash to the same value. */
      err = GOLLE_COMMIT_FAILED;
    }
  }

  golle_bin_delete (check);
  return err;
}


golle_error golle_commit_copy (golle_commit_t *dest,
			       const golle_commit_t *src)
{
  GOLLE_ASSERT (dest, GOLLE_ERROR);
  GOLLE_ASSERT (src, GOLLE_ERROR);

  golle_bin_t 
    *rkeep = 0, 
    *rsend = 0, 
    *hash = 0, 
    *secret = 0;
  
  if (src->rkeep) {
    if (!(rkeep = golle_bin_copy (src->rkeep))) {
      goto error;
    }
  }
  if (src->rsend) {
    if (!(rsend = golle_bin_copy (src->rsend))) {
      goto error;
    }
  }
  if (src->hash) {
    if (!(hash = golle_bin_copy (src->hash))) {
      goto error;
    }
  }
  if (src->secret) {
    if (!(secret = golle_bin_copy (src->secret))) {
      goto error;
    }
  }

  dest->rkeep = rkeep;
  dest->rsend = rsend;
  dest->hash = hash;
  dest->secret = secret;

 error:
  golle_bin_delete (rkeep);
  golle_bin_delete (rsend);
  golle_bin_delete (hash);
  golle_bin_delete (secret);
  return GOLLE_EMEM;
}
