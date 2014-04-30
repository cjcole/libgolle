/*
 * Copyright (C) Anthony Arnold 2014
 */


#include "golle/set.h"
#include <assert.h>
#include <string.h>

enum {
  HIGH_ITEMS = 100,
  ITEM_SIZE = sizeof (int)
};

static int comp (const golle_bin_t *l, const golle_bin_t *r) {
  return *(int*)l->bin - *(int*)r->bin;
}

int main (void) {
  /* Create a set */
  golle_set_t *set;

  golle_error err = golle_set_new (&set, &comp);

  assert (err == GOLLE_OK);
  assert (set);
  assert (golle_set_size (set) == 0);
  

  /* Add lots of items */
  for (int i = 0; i < HIGH_ITEMS; i++) {
    err = golle_set_insert (set, &i, ITEM_SIZE);
    assert (err == GOLLE_OK);
    assert (golle_set_check (set) == GOLLE_OK);
  }
  assert (golle_set_size (set) == HIGH_ITEMS);

  /* Find each item */
  for (int i = 0; i < HIGH_ITEMS; i++) {
    const golle_bin_t *search;

    err = golle_set_find (set, &i, ITEM_SIZE, &search);
    assert (err == GOLLE_OK);
    assert (search);
    assert (*(int*)search->bin == i);
  }

  /* Clear all items. */
  err = golle_set_clear (set);
  assert (err == GOLLE_OK);
  assert (golle_set_check (set) == GOLLE_OK);
  assert (golle_set_size (set) == 0);

  /* Add them all back */
  for (int i = 0; i < HIGH_ITEMS; i++) {
    err = golle_set_insert (set, &i, ITEM_SIZE);
    assert (err == GOLLE_OK);
    assert (golle_set_check (set) == GOLLE_OK);
  }
  assert (golle_set_size (set) == HIGH_ITEMS);

  /* Delete every second one */
  for (int i = 0; i < HIGH_ITEMS; i += 2) {
    err = golle_set_erase (set, &i, ITEM_SIZE);
    assert (err == GOLLE_OK);
    assert (golle_set_check (set) == GOLLE_OK);
  }
  assert (golle_set_size (set) == HIGH_ITEMS / 2);

  /* Get an iterator */
  golle_set_iterator_t *it;
  err = golle_set_iterator (set, &it);
  assert (err == GOLLE_OK);
  assert (it);

  /* Check the order/existance of items. */
  const golle_bin_t *item;
  for (int i = 1; i < HIGH_ITEMS; i += 2) {
    err = golle_set_iterator_next (it, &item);
    assert (err == GOLLE_OK);
    assert (item);
    assert (*(int*)item->bin == i);
  }

  /* Check that the next call is the end. */
  assert (golle_set_iterator_next (it, &item) == GOLLE_END);

  golle_set_iterator_free (it);
  golle_set_delete (set);

  /* Errors */
  
  /* Passing NULL to allocator */
  err = golle_set_new (NULL, NULL);
  assert (err == GOLLE_ERROR);
  err = golle_set_new (&set, NULL);
  assert (err == GOLLE_ERROR);

  /* NULL to insert */
  assert (golle_set_insert (NULL, NULL, 0) == GOLLE_ERROR);
  
  /* Inserting an existing record. */
  assert (golle_set_new (&set, &comp) == GOLLE_OK);
  int i = 0;
  assert (golle_set_insert (set, &i, sizeof(i)) == GOLLE_OK);
  assert (golle_set_insert (set, &i, sizeof(i)) == GOLLE_EEXISTS);

  /* NULL to erase */
  assert (golle_set_erase (NULL, NULL, sizeof (i)) == GOLLE_ERROR);

  /* Deleting a non-existant item. */
  i = 1;
  assert (golle_set_erase (set, &i, sizeof (i)) == GOLLE_ENOTFOUND);

  /* NULL to find */
  assert (golle_set_find (NULL, NULL, 0, NULL) == GOLLE_ERROR);
  assert (golle_set_find (set, NULL, 0, NULL) == GOLLE_ERROR);

  /* NULL to clear */
  assert (golle_set_clear (NULL) == GOLLE_ERROR);

  /* Finding non-existant item. */
  const golle_bin_t *x;
  assert (golle_set_find (set, &i, sizeof (i), &x) == GOLLE_ENOTFOUND);

  /* NULL to an iterator */
  assert (golle_set_iterator (NULL, NULL) == GOLLE_ERROR);
  assert (golle_set_iterator (set, NULL) == GOLLE_ERROR);

  /* NULL to iterator next */
  assert (golle_set_iterator (set, &it) == GOLLE_OK);
  assert (golle_set_iterator_next (it, NULL) == GOLLE_ERROR);

  /* NULL to iterator reset */
  assert (golle_set_iterator_reset (NULL) == GOLLE_ERROR);

  golle_set_iterator_free (it);
  golle_set_delete (set);

  return 0;
}
