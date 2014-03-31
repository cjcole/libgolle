/*
 * Copyright (C) Anthony Arnold 2014
 */

#include "golle/list.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

#define ONE "1"
#define TWO "TWO"

enum {
  STRING_LENGTH = 15,
  ITEMS = 10000,
  INSERT_AT = 5
};

typedef struct entry {
  int id;
  char str[STRING_LENGTH + 1];
} entry;

int main (int argc, char *argv[]) {
  /* Make a list */
  golle_list_t *list;

  golle_error error = golle_list_new (&list);

  assert(error == GOLLE_OK);
  assert(list);
  assert(golle_list_size(list) == 0);

  /* Add an item. */
  entry e;
  e.id = 1;
  strcpy(e.str, ONE);

  error = golle_list_push(list, &e, sizeof(e));

  assert(error == GOLLE_OK);
  assert(golle_list_size(list) == 1);


  /* Check its value. */
  golle_list_iterator_t *it;
  error = golle_list_iterator (list, &it);
  
  assert(error == GOLLE_OK);
  
  entry *e2;
  error = golle_list_iterator_next (it, (void**)&e2);
  assert(error == GOLLE_OK);
  assert(e2->id == 1);
  assert(strcmp(e2->str, ONE) == 0);

  error = golle_list_iterator_next (it, (void**)&e2);
  assert(error == GOLLE_END);

  /* Reset the iterator. */
  error = golle_list_iterator_reset (it);
  assert(error == GOLLE_OK);
  error = golle_list_iterator_next (it, (void**)&e2);
  assert(error == GOLLE_OK);
  assert(e2->id == 1);
  
  golle_list_iterator_free (it);
  it = NULL;

  /* Remove the item. */
  error = golle_list_pop (list);
  assert(error == GOLLE_OK);
  assert(golle_list_size(list) == 0);

  /* Add a NULL item. */
  error = golle_list_push(list, NULL, sizeof(e));
  assert(error == GOLLE_OK);
  assert(golle_list_size(list) == 1);

  /* Check its value. */
  error = golle_list_iterator (list, &it);
  
  assert(error == GOLLE_OK);
  

  error = golle_list_iterator_next (it, (void**)&e2);
  assert(error == GOLLE_OK);
  assert(e2 == NULL);


  /* Remove using iterator. */
  error = golle_list_erase_at (it);
  assert(error == GOLLE_OK);
  assert(golle_list_size(list) == 0);
  assert(golle_list_iterator_next (it, (void**)&e2) == GOLLE_END);

  golle_list_iterator_free(it);


  /* Add lots of items. */
  error = golle_list_push_many (list, &e, sizeof(e), ITEMS);
  assert(error == GOLLE_OK);

  assert(golle_list_size(list) == ITEMS);

  /* Iterate to the 5th one. */
  assert(golle_list_iterator(list, &it) == GOLLE_OK);
  for (int i = 0; i < INSERT_AT; i++) {
    assert(golle_list_iterator_next(it, (void**)&e2) == GOLLE_OK);
  }
  
  /* Insert between 5th and 6th element. */
  e.id = 2;
  strcpy(e.str, TWO);
  error = golle_list_insert_at(it, &e, sizeof(e));

  /* Get the newly inserted one */
  assert(golle_list_iterator_next(it, (void**)&e2) == GOLLE_OK);
  assert(e2);
  assert(e2->id == 2);
  assert(strcmp(e2->str, TWO) == 0);

  golle_list_iterator_free(it);


  /* Remove all except the first. */
  error = golle_list_pop_many (list, ITEMS);
  assert(error == GOLLE_OK);
  assert(golle_list_size(list) == 1);

  /* Remove the rest. */
  /*assert(golle_list_push_many (list, &e, sizeof(e), ITEMS) == GOLLE_OK);*/
  error = golle_list_pop_all(list);
  assert(error == GOLLE_OK);
  assert(golle_list_size(list) == 0);

  /* Check that popping an empty list gives error code. */
  error = golle_list_pop (list);
  assert(error == GOLLE_EEMPTY);
  
  /* Delete a full list */
  assert(golle_list_push_many (list, &e, sizeof(e), ITEMS) == GOLLE_OK);
  golle_list_delete(list);

  return 0;
}
