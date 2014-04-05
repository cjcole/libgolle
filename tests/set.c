/*
 * Copyright (C) Anthony Arnold 2014
 */


#include "golle/set.h"
#include <assert.h>
#include <string.h>

enum {
  HIGH_ITEMS = 10,
  ITEM_SIZE = sizeof (int)
};

static int comp (const void *l, const void *r) {
  return memcmp (l, r, ITEM_SIZE);
}

int main () {
  /* Create a set */
  golle_set_t *set;

  golle_error err = golle_set_new (&set, HIGH_ITEMS, ITEM_SIZE, &comp);

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
    int *search;

    err = golle_set_find (set, &i, (const void**)&search);
    assert (err == GOLLE_OK);
    assert (search);
    assert (*search == i);
  }

  /* Delete every second one */
  for (int i = 0; i < HIGH_ITEMS; i += 2) {
    err = golle_set_erase (set, &i);
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
  int *item;
  for (int i = 1; i < HIGH_ITEMS; i += 2) {
    err = golle_set_iterator_next (it, (const void**)&item);
    assert (err == GOLLE_OK);
    assert (item);
    assert (*item == i);
  }
  /* Check that the next call is the end. */
  assert (golle_set_iterator_next (it, (const void**)&item) == GOLLE_END);

  golle_set_iterator_free (it);
  golle_set_delete (set);

  /* Errors */
  
  /* Passing NULL to allocator */
  err = golle_set_new (NULL, 0,0, NULL);
  assert (err == GOLLE_ERROR);
  err = golle_set_new (&set, 0, 0, NULL);
  assert (err == GOLLE_ERROR);

  /* NULL to insert */
  assert (golle_set_insert (NULL, NULL, 0) == GOLLE_ERROR);
  
  /* Inserting an existing record. */
  assert (golle_set_new (&set, 0, 0, &comp) == GOLLE_OK);
  int i = 0;
  assert (golle_set_insert (set, &i, sizeof(i)) == GOLLE_OK);
  assert (golle_set_insert (set, &i, sizeof(i)) == GOLLE_EEXISTS);
  

  /* NULL to erase */
  assert (golle_set_erase (NULL, NULL) == GOLLE_ERROR);

  /* Deleting a non-existant item. */
  i = 1;
  assert (golle_set_erase (set, &i) == GOLLE_ENOTFOUND);

  /* NULL to find */
  assert (golle_set_find (NULL, NULL, NULL) == GOLLE_ERROR);
  assert (golle_set_find (set, NULL, NULL) == GOLLE_ERROR);

  /* Finding non-existant item. */
  int *x;
  assert (golle_set_find (set, &i, (const void**)&x) == GOLLE_ENOTFOUND);

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
