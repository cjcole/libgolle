/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/list.h>
#include <string.h>
#include <stdlib.h>

#define INVALID_ITERATOR(l) ((void*)(l))

typedef struct golle_list_node_t golle_list_node_t;

struct golle_list_node_t {
  golle_list_node_t *next;
  void *data;
};

struct golle_list_t {
  golle_list_node_t *head;
  golle_list_node_t *tail;
  size_t count;
};

struct golle_list_iterator_t {
  golle_list_t *list;
  golle_list_node_t *current;
};


/*
 * Delete a chain of linked nodes
 */
static void free_linked_nodes (golle_list_node_t *head) {
  while (head) {
    golle_list_node_t *next = head->next;
    free (head);
    head = next;
  }
}

/*
 * Allocate a chain of linked nodes. Set data to NULL.
 * Returns the head of the list, and puts the tail in out_tail.
 */
static golle_list_node_t *alloc_linked_nodes (size_t size, 
					      size_t num,
					      golle_list_node_t **out_tail) 
{
  golle_list_node_t
    *head, *tail;

  head = NULL;
  tail = NULL;

  /* Allocate each node. If one fails, they all fail. */
  for (size_t i = 0; i < num; i++) {
    golle_list_node_t *node = malloc(size);
    if (!node) {
      free_linked_nodes (head);
      return NULL;
    }
    memset(node, 0, size);

    if (!head) {
      head = node;
    }
    if (tail) {
      tail->next = node;
    }
    tail = node;
  }

  if (out_tail) {
    *out_tail = tail;
  }
  return head;
}

/*
 * Create a chain of linked nodes and fill in their data.
 */
static golle_list_node_t *make_linked_list (const void *item,
					    size_t size,
					    size_t num,
					    golle_list_node_t **out_tail)
{
  if (!item) {
    size = 0;
  }

  size_t node_size = size + sizeof (golle_list_node_t);
  
  /* Get the head and tail of the new sublist. */
  golle_list_node_t
    *head = alloc_linked_nodes (node_size, num, out_tail);


  /* New copy of data into each node. */
  if (head && size) {
    golle_list_node_t *copy = head;
    while (copy) {
      copy->data = ((char *)copy) + sizeof (golle_list_node_t);
      memcpy (copy->data, item, size);
      copy = copy->next;
    }
  }

  return head;
}


golle_error golle_list_new (golle_list_t **list) {
  GOLLE_ASSERT (list, GOLLE_ERROR);

  golle_list_t *l = malloc (sizeof(golle_list_t));
  GOLLE_ASSERT (l, GOLLE_EMEM);
  memset (l, 0, sizeof(*l));

  *list = l;

  return GOLLE_OK;
}


void golle_list_delete (golle_list_t *list) {
  if (list) {
    golle_list_pop_all (list);
    free(list);
  }
}


size_t golle_list_size (const golle_list_t *list) {
  GOLLE_ASSERT (list, 0);
  return list->count;
}

golle_error golle_list_top (const golle_list_t *list,
			    void **item)
{
  GOLLE_ASSERT (list, GOLLE_ERROR);
  GOLLE_ASSERT (item, GOLLE_ERROR);

  GOLLE_ASSERT (list->count, GOLLE_EEMPTY);

  *item = list->head->data;
  return GOLLE_OK;
}

golle_error golle_list_push (golle_list_t *list,
			     const void *item,
			     size_t size) 
{  
  return golle_list_push_many (list, item, size, 1);
}

golle_error golle_list_push_many (golle_list_t *list,
				  const void *item,
				  size_t size,
				  size_t count) 
{
  GOLLE_ASSERT (list, GOLLE_ERROR);
  GOLLE_ASSERT (count, GOLLE_OK);

  golle_list_node_t
    *head, *tail;

  head = make_linked_list (item, size, count, &tail);
  GOLLE_ASSERT (head, GOLLE_EMEM);


  /* Append sublist to end of list */
  if (list->tail) {
    list->tail->next = head;
    list->tail = tail;
  } else {
    list->head = head;
    list->tail = tail;
  }

  list->count += count;
  return GOLLE_OK;
}


golle_error golle_list_pop (golle_list_t *list) {
  return golle_list_pop_many (list, 1);
}


golle_error golle_list_pop_many (golle_list_t *list, size_t count) {
  GOLLE_ASSERT(list, GOLLE_ERROR);
  GOLLE_ASSERT(count, GOLLE_OK);
  GOLLE_ASSERT(list->count >= count, GOLLE_EEMPTY);

  if (count == list->count) {
    free_linked_nodes (list->head);
    list->head = NULL;
    list->tail = NULL;
    list->count = 0;
    return GOLLE_OK;
  }

  golle_list_node_t *sub = list->head, *prev = NULL;
  size_t c = count;
  while (c--) {
    prev = sub;
    sub = sub->next;
  }
  golle_list_node_t *t = list->head;
  list->head = sub;
  prev->next = NULL;

  free_linked_nodes (t);
  list->head = sub;
  
  list->count -= count;


  return GOLLE_OK;
}


golle_error golle_list_pop_all (golle_list_t *list) {
  GOLLE_ASSERT(list, GOLLE_ERROR);

  free_linked_nodes (list->head);
  list->head = NULL;
  list->tail = NULL;
  list->count = 0;
  
  return GOLLE_OK;
}


golle_error golle_list_iterator (golle_list_t *list,
				 golle_list_iterator_t **iter)
{
  GOLLE_ASSERT (list, GOLLE_ERROR);
  GOLLE_ASSERT (iter, GOLLE_ERROR);

  golle_list_iterator_t *it = malloc(sizeof(*it));
  GOLLE_ASSERT (it, GOLLE_EMEM);


  it->list = list;
  it->current = INVALID_ITERATOR(list);

  *iter = it;
  return GOLLE_OK;
}

void golle_list_iterator_free (golle_list_iterator_t *iter) {
  if (iter) {
    free(iter);
  }
}

golle_error golle_list_iterator_next (golle_list_iterator_t *iter,
				      void **item)
{
  GOLLE_ASSERT (iter, GOLLE_ERROR);
  GOLLE_ASSERT (item, GOLLE_ERROR);

  /* Invalid pointer means START */
  if (iter->current == INVALID_ITERATOR(iter->list)) {
    iter->current = iter->list->head;
  }

  /* NULL pointer means END */
  else if (iter->current != NULL) {
    iter->current = iter->current->next;
  }
  
  if (iter->current == NULL) {
    return GOLLE_END;
  }

  *item = iter->current->data;

  return GOLLE_OK;
}

golle_error golle_list_iterator_reset (golle_list_iterator_t *iter) {
  GOLLE_ASSERT (iter, GOLLE_ERROR);

  iter->current = INVALID_ITERATOR(iter->list);
  return GOLLE_OK;
}


golle_error golle_list_insert_at (golle_list_iterator_t *iter, 
				  const void *item,
				  size_t size) 
{
  GOLLE_ASSERT (iter, GOLLE_ERROR);

  golle_list_t *list = iter->list;

  /* Create the new list node */
  golle_list_node_t *head = make_linked_list (item, size, 1, NULL);
  GOLLE_ASSERT (head, GOLLE_EMEM);

  
  if (iter->current == INVALID_ITERATOR(list)) {
    /* Initial state. Prepend. */
    head->next = list->head;

    if (list->head == list->tail) {
      list->tail = head;
    }
    list->head = head;
  }
  else if (iter->current == NULL) {
    /* End of list. Append. */
    if (list->tail) {
      iter->current = list->tail;
      list->tail->next = head;
    }
    else {
      iter->current = INVALID_ITERATOR(list);
      list->head = head;
    }
    list->tail = head;

  }
  else {
    /* Splice in between two nodes. */
    head->next = iter->current->next;
    iter->current->next = head;
  }

  list->count++;

  return GOLLE_OK;
}


golle_error golle_list_erase_at (golle_list_iterator_t *iter) {
  GOLLE_ASSERT (iter, GOLLE_ERROR);
  GOLLE_ASSERT (iter->current, GOLLE_ENOTFOUND);

  golle_list_t *list = iter->list;

  GOLLE_ASSERT (iter->current != INVALID_ITERATOR (list), GOLLE_ENOTFOUND);


  if (list->head == iter->current) {
    /* Easily remove the head node. */
    golle_error err = golle_list_pop (list);
    if (err == GOLLE_OK) {
      iter->current = list->head;
    }
    return err;
  }

  /* Need to find the preceding node. */
  golle_list_node_t *pre = iter->list->head;
  while (pre->next != iter->current) {
    pre = pre->next;
  }

  /* Unlink */
  pre->next = iter->current->next;
  iter->current->next = NULL;
  free_linked_nodes (iter->current);
  iter->current = pre->next;
  list->count--;

  return GOLLE_OK;
}
