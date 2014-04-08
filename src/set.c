/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/set.h>
#include <golle/list.h>
#include "align.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>


/*
 * Index into child array.
 */
enum {
  TREE_LEFT,
  TREE_RIGHT,
  TREE_CHILDREN
};

/*
 * Node colours.
 */
typedef enum NODE_COLOURS {
  NODE_BLACK = 0,
  NODE_RED = 1
} NODE_COLOURS;


/*
 * Magic reallocation multiplier.
 */
static const float REALLOC_MUL = 0.6f;


/*
 * A node in the set tree.
 */
typedef struct set_node_t set_node_t;

struct set_node_t {
  set_node_t *children[TREE_CHILDREN];
  set_node_t *parent;
  int colour;
  size_t buffer_size;
  void *data;
};


/*
 * A chunk of memory that can be split up enough to
 * hold set elements.
 */
typedef struct node_chunk_t {
  size_t num_elems;
  set_node_t nodes[];

} node_chunk_t;

struct golle_set_t {
  golle_set_comp_t comp;
  size_t count;
  size_t size_hint;
  
  golle_list_t *chunks;
  golle_list_t *free_nodes;

  set_node_t *root;
};

struct golle_set_iterator_t {
  const golle_set_t *set;
  set_node_t *next;
};

/*
 * Get the address of the node's local buffer.
 */
static void *node_local_data (const set_node_t *node) {
  GOLLE_ASSERT (node, NULL);

  return ((char*)node) + sizeof (set_node_t);
}

/*
 * Unlink a leaf from the tree and return it to the free list.
 */
static void set_leaf_unlink (golle_set_t *set, set_node_t *node) {
  if (!node) {
    return;
  }
	
  golle_error err = golle_list_push (set->free_nodes, &node, sizeof(node));
  assert (err == GOLLE_OK);
}

/*
 * Copy data to a node.
 */
static golle_error set_node_copy_data (set_node_t *node, 
				       const void *data, 
				       size_t size)
{
  GOLLE_ASSERT (node, GOLLE_ERROR);

  if (!data) {
    node->data = NULL;
    return GOLLE_OK;
  }

  if (size > node->buffer_size) {
    node->data = malloc (size);
    GOLLE_ASSERT (node->data, GOLLE_EMEM);
  }
  else {
    node->data = node_local_data (node);
  }
  
  memcpy (node->data, data, size);
  return GOLLE_OK;
}

/*
 * Free a node's data if required.
 */
static void set_node_free_data (set_node_t *node) {
  if (!node) {
    return;
  }

  if (node->data &&
      (char *)node->data != node_local_data (node))
    {
      /* Node data points to an independant buffer. */
      free (node->data);
    }
  node->data = NULL;
}

/*
 * Traverse a node's children and free their data.
 */
static void set_node_delete (set_node_t *node) {
  if (node) {
    set_node_delete (node->children[TREE_LEFT]);
    set_node_delete (node->children[TREE_RIGHT]);
    set_node_free_data (node);
  }
}

/*
 * Iterator over a list of chunks and free them.
 */
static void chunk_list_delete (golle_list_t *list) {
  if (!list) {
    return;
  }
  while (golle_list_size (list)) {
    void *ptr;
    assert (golle_list_top (list, &ptr) == GOLLE_OK);

    node_chunk_t *chunk = *(node_chunk_t **)ptr;
    free (chunk);

    assert (golle_list_pop (list) == GOLLE_OK);
  }
  golle_list_delete (list);
}

/*
 * Iterate over a list of node pointers and free their data.
 */
static void node_list_delete (golle_list_t *list) {
  if (!list) {
    return;
  }
  while (golle_list_size (list)) {
    void *ptr;
    assert (golle_list_top (list, &ptr) == GOLLE_OK);

    set_node_t *node = *(set_node_t **)ptr;
    set_node_free_data (node);

    assert (golle_list_pop (list) == GOLLE_OK);
  }
  golle_list_delete (list);
}

/*
 * Split a buffer of memory up into nodes with
 * a given data buffer size. Add them to the free node
 * list.
 */
static golle_error new_nodes (golle_set_t *set,
			      void *buffer,
			      size_t num_nodes,
			      size_t node_size)
{
  for (size_t i = 0; i < num_nodes; i++) {
    set_node_t *node = (set_node_t *)((char *)buffer + (node_size * i));
    golle_error err = golle_list_push (set->free_nodes, &node, sizeof (node));
    if (err != GOLLE_OK) {
      golle_list_pop_many (set->free_nodes, i + 1);
      return err;
    }

    node->buffer_size = node_size - sizeof (set_node_t);
    node->data = NULL;
  }

  return GOLLE_OK;
}

/*
 * Create a new chunk of nodes with a given
 * buffer size.
 */
static golle_error new_chunk (golle_set_t *set,
			      size_t num_items,
			      size_t item_size)
{
  GOLLE_ASSERT (set, GOLLE_ERROR);
  GOLLE_ASSERT (set->free_nodes, GOLLE_ERROR);
  GOLLE_ASSERT (set->chunks, GOLLE_ERROR);

  /* A node must be able to hold at least a pointer. */
  item_size = GOLLE_ALIGN (item_size);

  size_t node_size = sizeof (set_node_t) + item_size;
  node_size = GOLLE_ALIGN (node_size);

  size_t chunk_size = sizeof (node_chunk_t) + (node_size * num_items);
  node_chunk_t *chunk = malloc (chunk_size);
  memset (chunk, 0, chunk_size);

  GOLLE_ASSERT (chunk, GOLLE_EMEM);
  chunk->num_elems = num_items;
  
  golle_error err = golle_list_push (set->chunks, &chunk, sizeof (chunk));
  if (err != GOLLE_OK) {
    free (chunk);
    return err;
  }

  /* Add each node in the chunk to the free list. */
  err = new_nodes (set, chunk->nodes, num_items, node_size);
  if (err != GOLLE_OK) {
    golle_list_pop (set->chunks);
    free (chunk);
    return err;
  }

  return GOLLE_OK;
}

/*
 * Clear a node's connections.
 */
static void disconnect_node (set_node_t *node) {
  if (node) {
    node->children[TREE_LEFT] = NULL;
    node->children[TREE_RIGHT] = NULL;
    node->parent = NULL;
  }
}

/*
 * Get a free node to insert. Allocate new chunks if required.
 */
static set_node_t *alloc_node (golle_set_t *set) {
  golle_error err;

  if (golle_list_size (set->free_nodes) == 0) {
    size_t more = set->count * REALLOC_MUL;
    if (!more) {
      more = 4;
    }
    err = new_chunk (set, more, set->size_hint);
    GOLLE_ASSERT (err == GOLLE_OK, NULL);
    GOLLE_ASSERT (golle_list_size (set->free_nodes) > 0, NULL);
  }

  set_node_t **node;
  err = golle_list_top (set->free_nodes, (void **)&node);
  GOLLE_ASSERT (err == GOLLE_OK, NULL);
  GOLLE_ASSERT (node, NULL);

  err = golle_list_pop (set->free_nodes);
  GOLLE_ASSERT (err == GOLLE_OK, NULL);

  disconnect_node (*node);
  return *node;
}

/*
 * Get the colour of a node. NULL nodes are black.
 */
static NODE_COLOURS node_colour (set_node_t *node) {
  GOLLE_ASSERT (node, NODE_BLACK);
  return node->colour;
}

/*
 * Determine whether the node is the given colour.
 */
static int node_is (set_node_t *node, int c) {
  return node_colour (node) == c;
}

/*
 * Substitute a new node for an old one.
 */
static void node_replace (golle_set_t *set, 
			  set_node_t *old,
			  set_node_t *rep)
{
  if (old->parent == NULL) {
    set->root = rep;
  }
  else {
    if (old == old->parent->children[TREE_LEFT]) {
      old->parent->children[TREE_LEFT] = rep;
    }
    else {
      old->parent->children[TREE_RIGHT] = rep;
    }
  }

  if (rep) {
    rep->parent = old->parent;
  }
}


/*
 * Swap nodes.
 */
static void node_copy (set_node_t *n1, set_node_t *n2) {
  if (n2->data == node_local_data (n2))
    {
      if (n1->data != node_local_data (n1)) {
	free (n1->data);
      }
      
      if (n2->buffer_size <= n1->buffer_size) {
	n1->data = node_local_data (n1);
      }
      else {
	n1->data = malloc (n2->buffer_size);
	assert (n1->data);
      }

      memcpy (n1->data, n2->data, n2->buffer_size);
    }
  else {
    if (n1->data != node_local_data (n1)) {
      free (n1->data);
    }

    n1->data = n2->data;
    n2->data = NULL;
  }
}



/*
 * Retrieve the parent of a node's parent.
 */
static set_node_t *node_gparent (set_node_t *node) {
  assert (node);
  assert (node->parent);
  assert (node->parent->parent);

  return node->parent->parent;
}

/*
 * Retrive the sibling of this node.
 */
static set_node_t *node_sibling (set_node_t *node) {
  assert (node);
  assert (node->parent);

  if (node == node->parent->children[TREE_LEFT]) {
    return node->parent->children[TREE_RIGHT];
  }
  return node->parent->children[TREE_LEFT];
}

/*
 * Retrieve the sibling of this node's parent.
 */
static set_node_t *node_uncle (set_node_t *node) {
  assert (node);
  assert (node->parent);
  assert (node->parent->parent);
  return node_sibling (node->parent);
}


/*
 * Rotate the node in the given direction.
 */
static void node_rotate (golle_set_t *set, set_node_t *node, int dir) {
  set_node_t *pivot = node->children[!dir];
  node_replace (set, node, pivot);
  node->children[!dir] = pivot->children[dir];
  if (pivot->children[dir]) {
    pivot->children[dir]->parent = node;
  }
  pivot->children[dir] = node;
  node->parent = pivot;
}

/*
 * Delete case 1.
 */
static void golle_set_erase_a (golle_set_t *set, set_node_t *node);

/*
 * Delete case 2.
 */
static void golle_set_erase_b (golle_set_t *set, set_node_t *node);

/*
 * Delete case 3.
 */
static void golle_set_erase_c (golle_set_t *set, set_node_t *node);

/*
 * Delete case 4.
 */
static void golle_set_erase_d (golle_set_t *set, set_node_t *node);

/*
 * Delete case 5.
 */
static void golle_set_erase_e (golle_set_t *set, set_node_t *node);

/*
 * Delete case 6.
 */
static void golle_set_erase_f (golle_set_t *set, set_node_t *node);


static void golle_set_erase_a (golle_set_t *set, set_node_t *node) {
  if (!node->parent) {
    return;
  }

  golle_set_erase_b (set, node);
}

static void golle_set_erase_b (golle_set_t *set, set_node_t *node) {
  set_node_t *s = node_sibling (node);

  if (node_is (s, NODE_RED)) {
    node->parent->colour = NODE_RED;
    s->colour = NODE_BLACK;
    
    int dir = TREE_RIGHT;
    if (node == node->parent->children[TREE_LEFT]) {
      dir = TREE_LEFT;
    }

    node_rotate (set, node->parent, dir);
  }

  golle_set_erase_c (set, node);
}

static void golle_set_erase_c (golle_set_t *set, set_node_t *node) {
  set_node_t *s = node_sibling (node);

  if (node_is (node->parent, NODE_BLACK) &&
      node_is (s, NODE_BLACK) &&
      node_is (s->children[TREE_LEFT], NODE_BLACK) &&
      node_is (s->children[TREE_RIGHT], NODE_BLACK))
    {
      s->colour = NODE_RED;
      golle_set_erase_a (set, node->parent);
    }
  else {
    golle_set_erase_d (set, node);
  }
}

static void golle_set_erase_d (golle_set_t *set, set_node_t *node) {
  set_node_t *s = node_sibling (node);

  if (node_is (node->parent, NODE_RED) &&
      node_is (s, NODE_BLACK) &&
      node_is (s->children[TREE_LEFT], NODE_BLACK) &&
      node_is (s->children[TREE_RIGHT], NODE_BLACK))
    {
      s->colour = NODE_RED;
      node->parent->colour = NODE_BLACK;
    } 
  else {
    golle_set_erase_e (set, node);
  }
}


static void golle_set_erase_e (golle_set_t *set, set_node_t *node) {
  set_node_t *s = node_sibling (node);

  int dir = TREE_RIGHT;
  if (node == node->parent->children[TREE_LEFT]) {
    dir = TREE_LEFT;
  }

  if (node_is (s, NODE_BLACK) &&
      node_is (s->children[dir], NODE_RED) &&
      node_is (s->children[!dir], NODE_BLACK))
    {
      s->colour = NODE_RED;
      s->children[dir]->colour = NODE_BLACK;
      node_rotate (set, s, !dir);
    }
  golle_set_erase_f (set, node);
}

static void golle_set_erase_f (golle_set_t *set, set_node_t *node) {
  set_node_t *s = node_sibling (node);

  s->colour = node_colour (node->parent);
  node->parent->colour = NODE_BLACK;

  if (node == node->parent->children[TREE_LEFT]) {
    assert (node_is (s->children[TREE_RIGHT], NODE_RED));
    s->children[TREE_RIGHT]->colour = NODE_BLACK;
    node_rotate (set, node->parent, TREE_LEFT);
  }
  else {
    assert (node_is (s->children[TREE_LEFT], NODE_RED));
    s->children[TREE_LEFT]->colour = NODE_BLACK;
    node_rotate (set, node->parent, TREE_RIGHT);
  }

}

static void golle_set_erase_node (golle_set_t *set, set_node_t *node) {  
  if (node->children[TREE_LEFT] && node->children[TREE_RIGHT]) {
    /* Swap data with inorder predecessor or inorder successor.
       And delete the node swapped with.
    */
    set_node_t *swap = node->children[TREE_LEFT];
    while (swap->children[TREE_RIGHT]) {
	swap = swap->children[TREE_RIGHT];
    }

    node_copy (node, swap);
    node = swap;
  }
  assert (!node->children[TREE_LEFT] || 
	  !node->children[TREE_RIGHT]);

  set_node_t *child = node->children[TREE_RIGHT];
  if (!child) {
    child = node->children[TREE_LEFT];
  }

  if (node_is (node, NODE_BLACK)) {
    node->colour = node_colour (child);
    golle_set_erase_a (set, node);
  }

  node_replace (set, node, child);
  if (!node->parent && child) {
    child->colour = NODE_BLACK;
  }

  set_leaf_unlink (set, node);
}

/*
 * Insert case 1.
 */
static void golle_set_insert_a (golle_set_t *set, set_node_t *node);

/*
 * Insert case 2.
 */
static void golle_set_insert_b (golle_set_t *set, set_node_t *node);

/*
 * Insert case 3
 */
static void golle_set_insert_c (golle_set_t *set, set_node_t *node);

/*
 * Insert case 4
 */
static void golle_set_insert_d (golle_set_t *set, set_node_t *node);

/*
 * Insert case 5
 */
static void golle_set_insert_e (golle_set_t *set, set_node_t *node);



static void golle_set_insert_e (golle_set_t *set, set_node_t *node) {
  set_node_t *g = node_gparent (node);
  node->parent->colour = NODE_BLACK;
  g->colour = NODE_RED;
  if (node == node->parent->children[TREE_LEFT] &&
      node->parent == g->children[TREE_LEFT]) 
    {
      node_rotate (set, g, TREE_RIGHT);
    }
  else {
    assert (node == node->parent->children[TREE_RIGHT] &&
	    node->parent == g->children[TREE_RIGHT]);
    node_rotate (set, g, TREE_LEFT);
  }
}

static void golle_set_insert_d (golle_set_t *set, set_node_t *node) {
  set_node_t *g = node_gparent (node);

  if (node == node->parent->children[TREE_RIGHT] && 
      node->parent == g->children[TREE_LEFT]) 
    {
      node_rotate (set, node->parent, TREE_LEFT);
      node = node->children[TREE_LEFT];
    }

  else if (node == node->parent->children[TREE_LEFT] &&
	   node->parent == g->children[TREE_RIGHT])
    {
      node_rotate (set, node->parent, TREE_RIGHT);
      node = node->children[TREE_RIGHT];
    }

  golle_set_insert_e (set, node);
}


static void golle_set_insert_c (golle_set_t *set, set_node_t *node) {
  set_node_t *u = node_uncle (node);

  if (node_is (u, NODE_RED)) {
    node->parent->colour = NODE_BLACK;
    u->colour = NODE_BLACK;
    set_node_t *g = node_gparent (node);
    g->colour = NODE_RED;
    golle_set_insert_a (set, g);
  }
  else {
    golle_set_insert_d (set, node);
  }
}

static void golle_set_insert_b (golle_set_t *set, set_node_t *node) {
  if (node_colour (node->parent) == NODE_BLACK) {
    return;
  }
  else {
    golle_set_insert_c (set, node);
  }
}


static void golle_set_insert_a (golle_set_t *set, set_node_t *node) {
  if (!node->parent) {
    node->colour = NODE_BLACK;
  }
  else {
    golle_set_insert_b (set, node);
  }
}


/*
 * Given the data definition, find a matching node.
 */
static set_node_t *set_find_node (set_node_t *root, 
				  golle_set_comp_t comp,
				  const void *data) 
{
  GOLLE_ASSERT (root, NULL);

  int cmp = comp (data, root->data);
  if (cmp == 0) {
    return root;
  }

  if (cmp < 0) {
    cmp = TREE_LEFT;
  }
  else {
    cmp = TREE_RIGHT;
  }
    
  return set_find_node (root->children[cmp], comp, data);
}

/*
 * Insert a node into the tree the classic way.
 */
static golle_error golle_set_insert_recursive (golle_set_comp_t comp,
					       set_node_t *parent,
					       set_node_t *node) 
{
  GOLLE_ASSERT (node, GOLLE_ERROR);
  GOLLE_ASSERT (comp, GOLLE_ERROR);
  if (!parent) {
    return GOLLE_OK;
  }
  
  
  int c = comp (node->data, parent->data);
  if (c == 0) {
    return GOLLE_EEXISTS;
  }
  
  if (c < 0) {
    c = TREE_LEFT;
  }
  else {
    c = TREE_RIGHT;
  }

  set_node_t *child = parent->children[c];

  if (!child) {
    parent->children[c] = node;
    node->parent = parent;
    return GOLLE_OK;
  }

  return golle_set_insert_recursive (comp, child, node);
}

/*
 * Test property 1 of RB trees.
 * i.e. All nodes are red or black.
 */
static int test_prop_1 (set_node_t *node) {
  GOLLE_ASSERT (node_is (node, NODE_RED) || node_is (node, NODE_BLACK), 0);
  if (node) {
    GOLLE_ASSERT (test_prop_1 (node->children[TREE_LEFT]), 0);
    GOLLE_ASSERT (test_prop_1 (node->children[TREE_RIGHT]), 0);
  }
  return 1;
}

/*
 * Test property 2 of RB trees.
 * i.e. The root node is black.
 */
static int test_prop_2 (set_node_t *node) {
  GOLLE_ASSERT (node_is (node, NODE_BLACK), 0);
  return 1;
}

/*
 * Test property 4.
 * i.e. Every red node has two black children.
 */
static int test_prop_4 (set_node_t *node) {
  if (node_is (node, NODE_RED)) {
    GOLLE_ASSERT (node_is (node->children[TREE_LEFT], NODE_BLACK), 0);
    GOLLE_ASSERT (node_is (node->children[TREE_RIGHT], NODE_BLACK), 0);
    GOLLE_ASSERT (node_is (node->parent, NODE_BLACK), 0);
  }
  if (node) {
    GOLLE_ASSERT (test_prop_4 (node->children[TREE_LEFT]), 0);
    GOLLE_ASSERT (test_prop_4 (node->children[TREE_RIGHT]), 0);
  }
  return 1;
}

/*
 * Test property 5.
 * i.e. All paths from one node to leaf nodes contains the same number of 
 * black nodes.
 */
static int test_prop_5_impl (set_node_t *node, int black, int *black_path) {
  if (node_is (node, NODE_BLACK)) {
    black++;
  }

  if (!node) {
    if (*black_path == -1) {
      *black_path = black;
    }
    else {
      GOLLE_ASSERT (black == *black_path, 0);
    }
    return 1;
  }

  int r = test_prop_5_impl (node->children[TREE_LEFT], black, black_path);
  GOLLE_ASSERT (r, 0);

  r = test_prop_5_impl (node->children[TREE_RIGHT], black, black_path);
  GOLLE_ASSERT (r, 0);

  return 1;
}

static int test_prop_5 (set_node_t *node) {
  int path = -1;
  return test_prop_5_impl (node, 0, &path);
}

/*
 * Test a subtree for validity.
 */
static int tree_is_valid (set_node_t *root) {
  GOLLE_ASSERT (test_prop_1 (root), 0);
  GOLLE_ASSERT (test_prop_2 (root), 0);
  GOLLE_ASSERT (test_prop_4 (root), 0);
  GOLLE_ASSERT (test_prop_5 (root), 0);
  return 1;
}

/*
 * Get the left-most child.
 */
set_node_t *get_least (set_node_t *node) {
  GOLLE_ASSERT (node, NULL);

  while (node->children[TREE_LEFT]) {
    node = node->children[TREE_LEFT];
  }

  return node;
}

golle_error golle_set_new (golle_set_t **set,
			   size_t num_items,
			   size_t item_size,
			   golle_set_comp_t comp)
{
  golle_error err;

  GOLLE_ASSERT(set, GOLLE_ERROR);
  GOLLE_ASSERT(comp, GOLLE_ERROR);

  golle_set_t *s = malloc (sizeof (*s));
  GOLLE_ASSERT(s, GOLLE_EMEM);
  memset (s, 0, sizeof (*s));

  /* Initial values */
  s->comp = comp;

  /* List of free nodes */
  golle_list_t *f;
  err = golle_list_new (&f);
  if (err != GOLLE_OK) {
    golle_set_delete (s);
  }
  s->free_nodes = f;

  /* List of chunks */
  golle_list_t *c;
  err = golle_list_new (&c);
  if (err != GOLLE_OK) {
    golle_set_delete (s);
    return err;
  }
  s->chunks = c;

  /* Preallocate */
  if (num_items && item_size) {
    err = new_chunk (s, num_items, item_size);
    if (err != GOLLE_OK) {
      golle_set_delete (s);
      return err;
    }
  }
  s->size_hint = item_size;

  *set = s;
  return GOLLE_OK;
}

void golle_set_delete (golle_set_t *set) {
  if (!set) {
    return;
  }

  /* Remove all nodes. */
  node_list_delete (set->free_nodes);
  set_node_delete (set->root);
  
  /* Remove all chunks */
  chunk_list_delete (set->chunks);

  free (set);
}


size_t golle_set_size (const golle_set_t *set) {
  GOLLE_ASSERT (set, 0);
  return set->count;
}

golle_error golle_set_insert (golle_set_t *set, 
			      const void *item, 
			      size_t size)
{
  GOLLE_ASSERT (set, GOLLE_ERROR);

  set_node_t *node = alloc_node (set);
  GOLLE_ASSERT (node, GOLLE_EMEM);
  node->colour = NODE_RED;


  golle_error err;
  if (set->root) {
    node->data = (void *)item;
    err = golle_set_insert_recursive (set->comp, 
				      set->root, 
				      node);
    GOLLE_ASSERT (err == GOLLE_OK, err);
  }
  else {
    set->root = node;
  }

  /* Make a copy of the data before rebalancing.
   If it fails we can just unlink the node. */
  err = set_node_copy_data (node, item, size);
  if (err != GOLLE_OK) {
    set_leaf_unlink (set, node);
    return err;
  }
  
  golle_set_insert_a (set, node);

  set->count++;
  return GOLLE_OK;
}

golle_error golle_set_erase (golle_set_t *set,
			     const void *item)
{
  GOLLE_ASSERT (set, GOLLE_ERROR);
  
  set_node_t *found = set_find_node (set->root, set->comp, item);

  GOLLE_ASSERT (found, GOLLE_ENOTFOUND);

  golle_set_erase_node (set, found);
  if (--set->count == 0) {
    set->root = NULL;
  }
  return GOLLE_OK;
}

golle_error golle_set_find (const golle_set_t *set, 
			    const void *item,
			    const void  **found)
{
  GOLLE_ASSERT (set, GOLLE_ERROR);
  GOLLE_ASSERT (found, GOLLE_ERROR);
  
  set_node_t *node = set_find_node (set->root, set->comp, item);

  GOLLE_ASSERT (node, GOLLE_ENOTFOUND);

  *found = node->data;
  return GOLLE_OK;
}

golle_error golle_set_iterator (const golle_set_t *set, 
				golle_set_iterator_t **iter)
{
  GOLLE_ASSERT (set, GOLLE_ERROR);
  GOLLE_ASSERT (iter, GOLLE_ERROR);

  golle_set_iterator_t *it = malloc (sizeof(*it));
  GOLLE_ASSERT (it, GOLLE_EMEM);
  
  it->set = set;
  it->next = get_least (set->root);

  *iter = it;
  return GOLLE_OK;
}

golle_error golle_set_iterator_next (golle_set_iterator_t * iter,
				     const void **item)
{
  GOLLE_ASSERT (iter, GOLLE_ERROR);
  GOLLE_ASSERT (item, GOLLE_ERROR);



  set_node_t *n = iter->next;
  if (!n) {
    return GOLLE_END;
  }


  /* Walk right if we can. */
  if (n->children[TREE_RIGHT]) {
    n = n->children[TREE_RIGHT];
    n = get_least (n);
  }
  else {
    /* Otherwise, go up until we're a left subtree. */
    while (1) {
      if (!n->parent || n->parent->children[TREE_LEFT] == n) {
	n = n->parent;
	break;
      }
      n = n->parent;
    }
  }
   
  *item = iter->next->data;
  iter->next = n;
  return GOLLE_OK;
}

golle_error golle_set_iterator_reset (golle_set_iterator_t *iter) {
  GOLLE_ASSERT (iter, GOLLE_ERROR);
  iter->next = get_least (iter->set->root);
  return GOLLE_OK;
}

void golle_set_iterator_free (golle_set_iterator_t *iter) {
  if (iter) {
    free (iter);
  }
}



golle_error golle_set_check (golle_set_t *set) {
  GOLLE_ASSERT(tree_is_valid (set->root), GOLLE_ERROR);
  return GOLLE_OK;
}
