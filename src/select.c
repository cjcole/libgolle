/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/select.h>
#include <golle/set.h>
#include <golle/elgamal.h>
#include <openssl/bn.h>
#include <assert.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif

/* Defines an invalid number */
#define INVALID_NUMBER 0xffffffffL

struct golle_select_t {
  /* Number of objects in the set */
  size_t n;

  /* Stor n as a big number */
  golle_num_t bn_n;

  /* Objects g^0 .. g^(n-1) */
  golle_num_t *exp;

  /* The number of peers */
  size_t k;

  /* E(g^(ni)) for i = 0, ..., k-1 */
  golle_num_t *S;

  /* Already selected items. */
  golle_set_t *selected;

  /* Keep track of peer commitments */
  golle_set_t *commitments;

  /* Store the peer set */
  golle_peer_set_t *peers;

  /* Accumulate the product of encryptions. */
  golle_eg_t product;

  /* Accumulate the sum of plaintext to get the object. */
  size_t c;
};

/* Store a commitment against a peer */
typedef struct peer_t {
  golle_peer_t peer;
  golle_commit_t commit;
  golle_eg_t cipher;
  golle_num_t r;
} peer_t;

/* Compare two numbers, set-style */
static int num_cmp (const golle_bin_t *b1, const golle_bin_t *b2) {
  assert (b1);
  assert (b2);

  golle_num_t n1 = (golle_num_t)b1->bin;
  assert (n1);
  golle_num_t n2 = (golle_num_t)b2->bin;
  assert (n2);
  return golle_num_cmp (n1, n2);
}

/* Compare two peers */
static int peer_cmp (const golle_bin_t *b1, const golle_bin_t *b2) {
  assert (b1);
  assert (b2);

  golle_peer_t *n1 = (golle_num_t)b1->bin;
  assert (n1);
  golle_peer_t *n2 = (golle_num_t)b2->bin;
  assert (n2);
  return (int)*n1 - (int)*n2;
}

/* Encrypt g^r mod q */
static golle_error enc_gr (golle_eg_t *cipher,
			   const BIGNUM *r,
			   golle_key_t *key,
			   golle_num_t rand,
			   BN_CTX *ctx)
{
  golle_error err;
  BIGNUM *e;

  BN_CTX_start (ctx);
  if (!(e = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }

  if (!BN_mod_exp (e, key->g, r, key->q, ctx)) {
    err = GOLLE_EMEM;
    goto out;
  }

  err = golle_eg_encrypt (key, e, cipher, &rand);
 out:
  BN_CTX_end (ctx);
  return err;
}

/* Verify that the encryption is correct */
static golle_error verify_enc (const golle_eg_t *cipher,
			       const golle_num_t r,
			       const golle_num_t rand,
			       golle_key_t *key)
{
  /* A context is needed for the EG encryption. */
  BN_CTX *ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);

  golle_eg_t check = { 0 };
  golle_error err = enc_gr (&check, (const BIGNUM*)r, key, rand, ctx);
  if (err == GOLLE_OK &&
      (golle_num_cmp (check.a, cipher->a) != 0 ||
       golle_num_cmp (check.b, cipher->b) != 0))
    {
      /* Encryption doesn't match. */
      err = GOLLE_EABORT;
    }
  golle_eg_clear (&check);

  BN_CTX_free (ctx);
  return err;
}

/* Delete every number in an array safely */
static void delete_num_array (golle_num_t *nums, size_t n) {
  if (nums) {
    for (size_t i = 0; i < n; i++) {
      golle_num_delete (nums[i]);
    }
  }
}

/* Calculate and store g^(mi) for i in {0, .., n - 1} */
static golle_error precalc_exp (golle_key_t *key, 
				golle_num_t *nums, 
				size_t m, 
				size_t n) 
{
  BN_CTX *ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);
  BN_CTX_start (ctx);

  BIGNUM *e = BN_CTX_get (ctx);
  if (!e) {
    BN_CTX_free (ctx);
    return GOLLE_EMEM;
  }

  golle_error err = GOLLE_OK;
  for (size_t i = 0; i < n; i++) {
    /* e = m * i */
    if (!BN_set_word (e, i * m)) {
      err = GOLLE_EMEM;
      break;
    }

    BIGNUM* exp = BN_new ();
    if (!exp) {
      err = GOLLE_EMEM;
      break;
    }
    nums[i] = exp;

    /* exp = g ^ e mod q */
    if (!BN_mod_exp (exp, key->g, e, key->q, ctx)) {
      err = GOLLE_EMEM;
      break;
    }
  }
  BN_CTX_end (ctx);
  BN_CTX_free (ctx);
  return err;
}

/* Get an ElGamal ciphertext as one binary blob */
static golle_error eg_to_bin (const golle_eg_t *enc,
			      const golle_key_t *key,
			      golle_bin_t *bin)
{
  /* Both numbers a and b are mod q,
     so we pad them with leading zeroes up to
     BN_num_bytes(q). */
  const size_t q_bytes = BN_num_bytes (key->q);

  golle_bin_t b = { 0 };
  golle_error err = golle_num_to_bin (enc->a, bin);
  if (err != GOLLE_OK) {
    return err;
  }
  err = golle_num_to_bin (enc->b, &b);
  if (err != GOLLE_OK) {
    golle_bin_release (bin);
    return err;
  }

  /* Resize to 2 * bytes(q) */
  size_t old_size = bin->size;
  err = golle_bin_resize (bin, q_bytes * 2);
  if (err != GOLLE_OK) {
    golle_bin_release (bin);
    golle_bin_release (&b);
    return err;
  }

  /* Shift bytes along so than the first q bytes
     are a with leading zeroes */
  size_t move_by = q_bytes - old_size;
  memmove((char*)bin->bin + move_by, bin->bin, move_by);
  memset (bin->bin, 0, move_by);
  
  /* Copy b so that the second q bytes are b
     with leading zeroes. */
  move_by = q_bytes - b.size;
  memset ((char*)bin->bin + q_bytes, 0, move_by);
  memcpy ((char*)bin->bin + q_bytes + move_by, b.bin, b.size);
  golle_bin_release (&b);
  return GOLLE_OK;
}

/* Store an ElGamal encryption. */
static golle_error store_secret (peer_t *pc,
				 golle_bin_t *bin,
				 const golle_key_t *key)
{
  golle_num_t a = NULL, b = NULL;
  golle_error err = GOLLE_OK;

  /* bin is two numbers of the same size concatenated */
  size_t size = BN_num_bytes (key->q);
  GOLLE_ASSERT (bin->size == size, GOLLE_ERROR);

  golle_bin_t abin;
  abin.bin = bin->bin;
  abin.size = size;
  
  if (!(a = golle_num_new ())) {
    err = GOLLE_EMEM;
    goto out;
  }
  err = golle_bin_to_num (&abin, a);
  if (err != GOLLE_OK) {
    goto out;
  }

  /* Shift up and get the b value */
  abin.bin = (char *)bin->bin + size;
  if (!(b = golle_num_new())) {
    err = GOLLE_EMEM;
    goto out;
  }
  err = golle_bin_to_num (&abin, b);

 out:
  if (err != GOLLE_OK) {
    golle_num_delete (a);
    golle_num_delete (b);
  }
  else {
    pc->cipher.a = a;
    pc->cipher.b = b;
  }
  return err;
}

/* Accumulate ElGamal encryptions */
static golle_error accumulate_encryption (golle_eg_t *product,
					  const golle_eg_t *cipher,
					  const golle_key_t *key)
{
  BIGNUM *a = NULL, *b = NULL;
  golle_error err = GOLLE_OK;
  BN_CTX *ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);

  if (!(a = BN_new ())) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!(b = BN_new ())) {
    err = GOLLE_EMEM;
    goto out;
  }
  
  if (!BN_mod_mul (a, product->a, cipher->a, key->q, ctx)) {
    err = GOLLE_ECRYPTO;
    goto out;
  }

  if (!BN_mod_mul (b, product->b, cipher->b, key->q, ctx)) {
    err = GOLLE_ECRYPTO;
    goto out;
  }

 out:
  BN_CTX_free (ctx);

  if (err == GOLLE_OK) {
    golle_eg_clear (product);
    product->a = a;
    product->b = b;
  }
  else {
    golle_num_delete (a);
    golle_num_delete (b);
  }
  return err;
}				  

/* Commit to the number r */
static golle_error commit_to_enc (const golle_eg_t *enc,
				  const golle_select_t *select,
				  golle_select_callback_t commit,
				  golle_select_callback_t verify)
{
  golle_key_t *key = golle_peers_get_key (select->peers);
  GOLLE_ASSERT (key, GOLLE_ERROR);

  /* Merge the ciphertext into one binary blob */
  golle_bin_t a = { 0 };
  golle_error err = eg_to_bin (enc, key, &a);
  GOLLE_ASSERT (err == GOLLE_OK, err);

  golle_commit_t *cmt = golle_commit_new (&a);
  golle_bin_release (&a);
  GOLLE_ASSERT (cmt, GOLLE_EMEM);

  /* Commit to the ciphertext */
  err = commit (select, cmt->rsend, cmt->hash);
  if (err != GOLLE_OK) {
    err = GOLLE_EABORT;
    goto out;
  }

  /* Verify the ciphertext */
  err = verify (select, cmt->rkeep, cmt->secret);
  if (err != GOLLE_OK) {
    err = GOLLE_EABORT;
    goto out;
  }

 out:
  golle_commit_delete (cmt);
  return err;
}

/* Send the chosen value and the randomness */
static golle_error reveal_selection (const golle_num_t r,
				     const golle_num_t rand,
				     const golle_select_t *select,
				     golle_select_callback_t reveal)
{
  golle_error err;
  golle_bin_t rbin = { 0 }, randbin = { 0 };
  /* Both numbers to buffers */
  err = golle_num_to_bin (r, &rbin);
  if (err != GOLLE_OK) {
    goto out;
  }
  err = golle_num_to_bin (rand, &randbin);
  if (err != GOLLE_OK) {
    goto out;
  }

  /* Send them */
  err = reveal (select, &rbin, &randbin);
  if (err != GOLLE_OK) {
    err = GOLLE_EABORT;
  }

 out:
  golle_bin_release (&rbin);
  golle_bin_release (&randbin);
  return err;
}

/* Create empty arrays */
static golle_error create_empty_arrays (golle_select_t *s,
					size_t n,
					size_t k)
{
  s->exp = calloc (sizeof (golle_num_t), n);
  GOLLE_ASSERT (s->exp, GOLLE_EMEM);
  s->n = n;

  s->S = calloc (sizeof (golle_num_t), k);
  GOLLE_ASSERT (s->S, GOLLE_EMEM);
  s->k = k;

  return GOLLE_OK;
}

/* Assign the big number. */
static golle_error assign_numeric (golle_select_t *s,
				   size_t n)
{
  s->bn_n = golle_num_new_int (n);
  GOLLE_ASSERT (s->bn_n, GOLLE_EMEM);
  return GOLLE_OK;
}

/* Do an action for each item in the set */
static golle_error for_each_item (golle_set_t *set,
				  void *param,
				  void (*cb) (void *, const golle_bin_t *))
{
  
  golle_set_iterator_t *iter;
  golle_error err = golle_set_iterator (set, &iter);
  GOLLE_ASSERT (err == GOLLE_OK, err);

  do {
    const golle_bin_t *item;
    err = golle_set_iterator_next (iter, &item);
    if (err == GOLLE_OK) {
      cb (param, item);
    }
  } while (err == GOLLE_OK);

  golle_set_iterator_free (iter);

  GOLLE_ASSERT (err == GOLLE_END, err);

  return golle_set_clear (set);
}

/* Free all values from a set using a callback. */
static golle_error free_set_items (golle_set_t *set,
				   void (*cb) (const golle_bin_t *))
{

  
  golle_set_iterator_t *iter;
  golle_error err = golle_set_iterator (set, &iter);
  GOLLE_ASSERT (err == GOLLE_OK, err);

  do {
    const golle_bin_t *item;
    err = golle_set_iterator_next (iter, &item);
    if (err == GOLLE_OK) {
      cb (item);
    }
  } while (err == GOLLE_OK);

  golle_set_iterator_free (iter);

  GOLLE_ASSERT (err == GOLLE_END, err);

  return golle_set_clear (set);
}

/* Free a peer commitment */
static void free_peer_commitment (const golle_bin_t *item) {
  peer_t *commit = (peer_t*)item->bin;
  golle_commit_clear (&commit->commit);
  golle_eg_clear (&commit->cipher);
  golle_num_delete (commit->r);
}

/* Free the commit record for each peer. */
static golle_error free_peer_commitments (golle_set_t *set) {
  return free_set_items (set, &free_peer_commitment);
}

/* Free a number from a set */
static void free_selected_number (const golle_bin_t *item) {
  golle_num_t num = (golle_num_t)item->bin;
  golle_num_delete (num);
}

/* Free all of the selected numbers. */
static golle_error free_selected (golle_set_t *set) {
  return free_set_items (set, &free_selected_number);
}

/* Assign values to the select structure */
static golle_error select_assign (golle_select_t *s,
				  size_t n,
				  size_t k,
				  golle_peer_set_t *peers)
{
  golle_error err;
  golle_key_t *key = golle_peers_get_key (peers);
  GOLLE_ASSERT (key, GOLLE_EINVALID);

  /* Make an empty set of numbers */
  err = golle_set_new (&s->selected, &num_cmp);
  GOLLE_ASSERT (err == GOLLE_OK, err);

  /* Make an array for storing peer commitments. */
  err = golle_set_new (&s->commitments, &peer_cmp);
  GOLLE_ASSERT (err == GOLLE_OK, err);
  
  /* Create arrays of all-empty numbers */
  err = create_empty_arrays (s, n, k);
  GOLLE_ASSERT (err == GOLLE_OK, err);

  /* Percompute some values */
  err = assign_numeric (s, n);
  GOLLE_ASSERT (err == GOLLE_OK, err);

  err = precalc_exp (key, s->exp, 1, n);
  GOLLE_ASSERT (err == GOLLE_OK, err);

  err = precalc_exp (key, s->S, n, k);
  GOLLE_ASSERT (err == GOLLE_OK, err);

  s->peers = peers;
  return GOLLE_OK;
}

/* Find a commitment for a peer. */
static golle_error find_commitment (golle_select_t *select,
				    golle_peer_t peer,
				    peer_t **cmt)
{
  const golle_bin_t *bin;
  peer_t c;
  c.peer = peer;
  golle_error err = golle_set_find (select->commitments, &c, sizeof (c), &bin);
  if (err == GOLLE_OK) {
    *cmt = (peer_t*)bin->bin;
  }
  return err;
}

/* Increment if the peer has revealed r */
static void increment_if_revealed (void *param, const golle_bin_t *bin) {
  size_t *s = (size_t *)param;
  peer_t *p = (peer_t *)bin->bin;

  if (p->r) {
    (*s)++;
  }
}					  

/* Check that all peers have revealed their plaintext */
static golle_error check_all_revealed (golle_select_t *select) {
  size_t revealed = 0;
  golle_error err = for_each_item (select->commitments, 
				   &revealed,
				   &increment_if_revealed);

  if (err == GOLLE_OK) {
    if (revealed < select->k) {
      /* Not all have been revealed yet. */
      err = GOLLE_EEMPTY;
    }
  }
  return err;
}

golle_error golle_select_new (golle_select_t **select,
			      golle_peer_set_t *peers,
			      size_t n)
{
  golle_error err = GOLLE_OK;
  size_t k;
  golle_key_t *key;
  golle_select_t *s;

  GOLLE_ASSERT (select, GOLLE_ERROR);
  GOLLE_ASSERT (peers, GOLLE_ERROR);
  GOLLE_ASSERT (n, GOLLE_EEMPTY);

  /* Must have at least one peer */
  k = golle_peers_size (peers);
  GOLLE_ASSERT (k, GOLLE_EEMPTY);

  /* Key must be valid */
  GOLLE_ASSERT (golle_peers_get_state (peers) == GOLLE_KEY_READY, 
		GOLLE_EINVALID);
  key = golle_peers_get_key (peers);
  GOLLE_ASSERT (key, GOLLE_EINVALID);

  /* Make a new object first */
  s = malloc (sizeof (*s));
  GOLLE_ASSERT (s, GOLLE_EMEM);
  memset (s, 0, sizeof (*s));

  /* Assign values */
  err = select_assign (s, n, k, peers);

  if (err != GOLLE_OK) {
    golle_select_delete (s);
  }
  else {
    *select = s;
  }
  return err;
}

void golle_select_delete (golle_select_t *select) {
  if (select) {
    /* Free each member. */
    delete_num_array (select->exp, select->n);
    delete_num_array (select->S, select->k);
    golle_num_delete (select->bn_n);

    free_selected (select->selected);
    golle_set_delete (select->selected);

    free_peer_commitments (select->commitments);
    golle_set_delete (select->commitments);

    golle_eg_clear (&select->product);

    free (select);
  }
}

golle_error golle_select_object (golle_select_t *select,
				 golle_select_callback_t commit,
				 golle_select_callback_t verify,
				 golle_select_callback_t reveal)
{
  golle_error err;
  golle_eg_t eg;
  BIGNUM *r, *rand = NULL;
  BN_CTX *ctx;
  golle_key_t *key;

  GOLLE_ASSERT (select, GOLLE_ERROR);
  GOLLE_ASSERT (commit, GOLLE_ERROR);
  GOLLE_ASSERT (verify, GOLLE_ERROR);
  GOLLE_ASSERT (reveal, GOLLE_ERROR);

  key = golle_peers_get_key (select->peers);
  GOLLE_ASSERT (key, GOLLE_ERROR);

  ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);
  BN_CTX_start (ctx);

  /* Select a random r in [0, n) */
  if (!(r = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!BN_rand_range (r, select->bn_n)) {
    err = GOLLE_ECRYPTO;
    goto out;
  }

  /* Compute E(g^r) */
  err = enc_gr (&eg, r, key, rand, ctx);

  /* Commit and verify the encryption */
  err = commit_to_enc (&eg, select, commit, verify);
  if (err != GOLLE_OK) {
    goto out;
  }

  /* Reveal the selection via callback */
  err = reveal_selection (r, rand, select, reveal);

 out:
  BN_CTX_end (ctx);
  BN_CTX_free (ctx);
  return err;
}

golle_error golle_select_peer_commit (golle_select_t *select,
				      golle_peer_t peer,
				      golle_bin_t *rsend,
				      golle_bin_t *hash)
{
  GOLLE_ASSERT (select, GOLLE_ERROR);
  GOLLE_ASSERT (rsend, GOLLE_ERROR);
  GOLLE_ASSERT (hash, GOLLE_ERROR);

  /* Ensure that peer is a verified member of the set. */
  GOLLE_ASSERT (golle_peers_check_key (select->peers, peer), GOLLE_ENOTFOUND);

  /* Make a copy */
  golle_commit_t commit = { 0 };
  commit.hash = hash;
  commit.rsend = rsend;
  peer_t c = { 0 };
  golle_error err = golle_commit_copy (&c.commit, &commit);
  if (err != GOLLE_OK) {
    goto out;
  }
  c.peer = peer;

  /* Attempt to insert the commitment into the set. */
  /* Returns EEXISTS for us. */
  err = golle_set_insert (select->commitments, &c, sizeof(c));

 out:
  if (err != GOLLE_OK) {
    golle_commit_clear (&c.commit);
  }
  return err;
}

golle_error golle_select_peer_verify (golle_select_t *select,
				      golle_peer_t peer,
				      golle_bin_t *rkeep,
				      golle_bin_t *secret)
{
  GOLLE_ASSERT (select, GOLLE_ERROR);
  GOLLE_ASSERT (rkeep, GOLLE_ERROR);
  GOLLE_ASSERT (secret, GOLLE_ERROR);
  golle_key_t *key = golle_peers_get_key (select->peers);
  GOLLE_ASSERT (key, GOLLE_ERROR);

  /* Ensure that peer is a verified member of the set. */
  GOLLE_ASSERT (golle_peers_check_key (select->peers, peer), GOLLE_ENOTFOUND);

  /* Find the commitment. */
  peer_t *c;
  golle_error err = find_commitment (select, peer, &c);
  GOLLE_ASSERT (err == GOLLE_OK, err);
  GOLLE_ASSERT (c, GOLLE_ERROR);

  /* Ensure it hasn't been verified yet. */
  GOLLE_ASSERT (c->commit.secret == NULL, GOLLE_EEXISTS);
  GOLLE_ASSERT (c->commit.rkeep == NULL, GOLLE_EEXISTS);
  
  /* Set the values. */
  if (!(c->commit.secret = golle_bin_copy (secret))) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!(c->commit.rkeep = golle_bin_copy (rkeep))) {
    err = GOLLE_EMEM;
    goto out;
  }
  /* Verify the commitment */
  err = golle_commit_verify (&c->commit);
  if (err == GOLLE_COMMIT_PASSED) {
    /* Store the secret */
    err = store_secret (c, secret, key);
    if (err == GOLLE_OK) {
      err = accumulate_encryption (&select->product,
				   &c->cipher,
				   key);
    }
  }
  else {
    /* Commitment failed! */
    err = GOLLE_ENOCOMMIT;
  }

 out:
  if (err != GOLLE_OK) {
    golle_bin_delete(c->commit.rkeep); c->commit.rkeep = NULL;
    golle_bin_delete(c->commit.hash); c->commit.hash = NULL;
  }
  return err;
}

golle_error golle_select_reveal (golle_select_t *select,
				 golle_peer_t peer,
				 golle_bin_t *r,
				 golle_bin_t *rand)
{
  GOLLE_ASSERT (select, GOLLE_ERROR);
  GOLLE_ASSERT (r, GOLLE_ERROR);
  GOLLE_ASSERT (rand, GOLLE_ERROR);

  /* make sure the key's valid */
  golle_key_t *key = golle_peers_get_key (select->peers);
  GOLLE_ASSERT (key, GOLLE_ERROR);

  /* Ensure that peer is a verified member of the set. */
  GOLLE_ASSERT (golle_peers_check_key (select->peers, peer), GOLLE_ENOTFOUND);

  /* Find the commitment. */
  peer_t *c;
  golle_error err = find_commitment (select, peer, &c);
  GOLLE_ASSERT (err == GOLLE_OK, err);
  GOLLE_ASSERT (c, GOLLE_ERROR);

  /* Ensure it has been verified. */
  GOLLE_ASSERT (c->commit.secret, GOLLE_ENOTFOUND);
  GOLLE_ASSERT (c->commit.rkeep, GOLLE_ENOTFOUND);
  GOLLE_ASSERT (c->cipher.a, GOLLE_ENOTFOUND);
  GOLLE_ASSERT (c->cipher.b, GOLLE_ENOTFOUND);

  /* Ensure it hasn't set its value yet. */
  GOLLE_ASSERT (c->r == NULL, GOLLE_EEXISTS);

  /* Get r and rand as numbers */
  BIGNUM *nr = NULL, *nrand = NULL;
  if (!(nr = BN_new ())) {
    err = GOLLE_EMEM;
    goto out;
  }
  if (!(nrand = BN_new ())) {
    err = GOLLE_EMEM;
    goto out;
  }

  /* Ensure that r is in [0,n) */
  if (BN_is_negative (nr) ||
      BN_cmp (nr, select->bn_n) >= 0)
    {
      err = GOLLE_EOUTOFRANGE;
      goto out;
    }

  /* Verify that E(g^r) using rand is correct. */
  err = verify_enc (&c->cipher, nr, nrand, key);
  GOLLE_ASSERT (err == GOLLE_OK, err);
 
  /* Add to the sum of r */
  size_t rnative = BN_get_word (nr);
  if (rnative == INVALID_NUMBER) {
    err = GOLLE_EINVALID;
    goto out;
  }
  select->c += rnative;
 out:
  if (err != GOLLE_OK) {
    golle_num_delete (nr);
    golle_num_delete (nrand);
  }
  return err;
}

golle_error golle_extract_value (golle_select_t *select,
				 golle_eg_t *egc,
				 size_t *selection)
{
  GOLLE_ASSERT (select, GOLLE_ERROR);
  GOLLE_ASSERT (selection, GOLLE_ERROR);
  GOLLE_ASSERT (egc, GOLLE_ERROR);

  /* make sure the key's valid */
  golle_key_t *key = golle_peers_get_key (select->peers);
  GOLLE_ASSERT (key, GOLLE_ERROR);

  /* Check that all peers have revealed r */
  golle_error err = check_all_revealed (select);
  GOLLE_ASSERT (err == GOLLE_OK, err);
  
  /* Reduce the sum, module n */
  size_t mod = select->c % select->n;

  /* Calculate encryption of g^c */
  BN_CTX *ctx = BN_CTX_new ();
  GOLLE_ASSERT (ctx, GOLLE_EMEM);
  BN_CTX_start (ctx);

  BIGNUM *bnmod;
  if (!(bnmod = BN_CTX_get (ctx))) {
    err = GOLLE_EMEM;
  }
  else {
    if (!BN_set_word (bnmod, mod)) {
      err = GOLLE_EMEM;
    }
    else {
      err = enc_gr (egc, bnmod, key, NULL, ctx);
    }
  }

  /* Encryption complete. */
  if (err == GOLLE_OK) {
    /* Selection is the index */
    *selection = mod;
  }
  BN_CTX_end (ctx);
  BN_CTX_free (ctx);
  return err;
}

golle_error golle_select_next_round (golle_select_t *select) {
  GOLLE_ASSERT (select, GOLLE_ERROR);
  golle_eg_clear (&select->product);

  golle_error err = free_peer_commitments (select->commitments);
  if (err != GOLLE_OK) {
    golle_set_delete (select->commitments);
    err = golle_set_new (&select->commitments, &peer_cmp);
  }
  if (err == GOLLE_OK) {
    select->c = 0;
  }
  return err;
}

golle_error golle_select_reset (golle_select_t *select) {
  GOLLE_ASSERT (select, GOLLE_ERROR);
  golle_error err = golle_select_next_round (select);
  if (err == GOLLE_OK) {
    err = free_selected (select->selected);
    if (err != GOLLE_OK) {
      golle_set_delete (select->selected);
      err = golle_set_new (&select->selected, &num_cmp);
    }
  }
  return err;
}

