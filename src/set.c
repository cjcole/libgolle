/*
 * Copyright (C) Anthony Arnold 2014
 */

#include <golle/set.h>
#include <golle/types.h>
#include <string.h>
#include <assert.h>
#include <golle/bin.h>

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
 * A node in the set tree.
 */
typedef struct set_node_t set_node_t;

struct set_node_t {
  set_node_t *children[TREE_CHILDREN];
  set_node_t *parent;
  int colour;
  golle_bin_t buffer;
};

struct golle_set_t {
  golle_set_comp_t comp;
  size_t count;

  set_node_t *root;
};

struct golle_set_iterator_t {
  const golle_set_t *set;
  set_node_t *next;
};

/*
 * Unlink a leaf from the tree and free it.
 */
static void set_leaf_unlink (set_node_t *node) {
  if (!node) {
    return;
  }
  golle_bin_release (&node->buffer);
  free (node);
}

/*
 * Walk through a tree, returning each node to the free list.
 */
static void set_tree_unlink (set_node_t *node) {
  if (!node) {
    return;
  }
  /* Recursive unlink - children first */
  set_tree_unlink (node->children[TREE_LEFT]);
  set_tree_unlink (node->children[TREE_RIGHT]);
  set_leaf_unlink (node);
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
    return GOLLE_OK;
  }
  /* We know that the buffer has not been created with
   * golle_bin_new() so it's safe to init it.
   */
  golle_error err = golle_bin_init (&node->buffer, size);
  GOLLE_ASSERT (err == GOLLE_OK, err);
  memcpy (node->buffer.bin, data, size);
  return GOLLE_OK;
}

/*
 * Allocate a new node.
 */
static set_node_t *alloc_node (void) {
  /* It's generally safer to zero out memory
   * where we can.
   */
  set_node_t *node = malloc (sizeof (*node));
  if (node) {
    memset (node, 0, sizeof (*node));
  }
  return node;
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
  return (int)node_colour (node) == c;
}

/*
 * Determine whether the node is a left child.
 */
static int is_left (const set_node_t *node) {
  if (!node || !node->parent) {
    /* Not a child at all */
    return 0;
  }
  return node->parent->children[TREE_LEFT] == node;
}

/*
 * Substitute a new node for an old one.
 */
static void node_replace (golle_set_t *set, 
			  set_node_t *old,
			  set_node_t *rep)
{
  if (old->parent == NULL) {
    /* The old node was the root,
     * so the new root of the tree is th
     * replacement node.
     */
    set->root = rep;
  }
  else {
    /* The old node's parent should now refer
     * to the replacement node as its child.
     */
    if (is_left (old)) {
      old->parent->children[TREE_LEFT] = rep;
    }
    else {
      old->parent->children[TREE_RIGHT] = rep;
    }
  }

  /* The replacement node takes the old node's parent. */
  if (rep) {
    rep->parent = old->parent;
  }
}

/*
 * Move the memory of one node to another.
 * Node 1 takes node 2's buffer, and node 2
 * removes its reference to the buffer to
 * avoid freeing it. Node 1's original buffer
 * is freed.
 */
static void node_move (set_node_t *n1, set_node_t *n2) {
  golle_bin_release (&n1->buffer);
  n1->buffer.bin = n2->buffer.bin;
  n1->buffer.size = n2->buffer.size;
  n2->buffer.bin = NULL;
  n2->buffer.size = 0;
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

  if (is_left (node)) {
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
    if (is_left (node)) {
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
  if (is_left (node)) {
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

  if (is_left (node)) {
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

    node_move (node, swap);
    node = swap;
  }
  /* Node must be a leaf */
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

  set_leaf_unlink (node);
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
  if (is_left (node) && is_left (node->parent)) 
    {
      node_rotate (set, g, TREE_RIGHT);
    }
  else {
    assert (!is_left (node) && !is_left (node->parent));
    node_rotate (set, g, TREE_LEFT);
  }
}

static void golle_set_insert_d (golle_set_t *set, set_node_t *node) {
  if (!is_left (node) && is_left (node->parent)) 
    {
      node_rotate (set, node->parent, TREE_LEFT);
      node = node->children[TREE_LEFT];
    }

  else if (is_left (node) && !is_left (node->parent))
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
				  const void *data,
				  size_t size) 
{
  GOLLE_ASSERT (root, NULL);
  const golle_bin_t temp = { size, (void *)data };

  /* Use the comparison function given at creation */
  int cmp = comp (&temp, &root->buffer);
  if (cmp == 0) {
    return root;
  }

  if (cmp < 0) {
    cmp = TREE_LEFT;
  }
  else {
    cmp = TREE_RIGHT;
  }
    
  return set_find_node (root->children[cmp], comp, data, size);
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
  
  int c = comp (&node->buffer, &parent->buffer);
  if (c == 0) {
    /* Duplicates are not allowed. */
    return GOLLE_EEXISTS;
  }
  
  /* Walk left or right depending on comparison. */
  if (c < 0) {
    c = TREE_LEFT;
  }
  else {
    c = TREE_RIGHT;
  }

  set_node_t *child = parent->children[c];
  if (!child) {
    /* Found the leaf. Add the new node
     * as a new leaf. */
    parent->children[c] = node;
    node->parent = parent;
    return GOLLE_OK;
  }

  /* Descend and try again. */
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
static set_node_t *get_least (set_node_t *node) {
  GOLLE_ASSERT (node, NULL);

  while (node->children[TREE_LEFT]) {
    set_node_t *n  = node->children[TREE_LEFT];
    node = n;
  }

  return node;
}

golle_error golle_set_new (golle_set_t **set,
			   golle_set_comp_t comp)
{
  GOLLE_ASSERT(set, GOLLE_ERROR);
  GOLLE_ASSERT(comp, GOLLE_ERROR);

  golle_set_t *s = malloc (sizeof (*s));
  GOLLE_ASSERT(s, GOLLE_EMEM);
  memset (s, 0, sizeof (*s));

  /* Initial values */
  s->comp = comp;

  *set = s;
  return GOLLE_OK;
}

void golle_set_delete (golle_set_t *set) {
  if (!set) {
    return;
  }

  /* Remove all nodes. */
  set_tree_unlink (set->root);
  
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

  set_node_t *node = alloc_node ();
  GOLLE_ASSERT (node, GOLLE_EMEM);
  node->colour = NODE_RED;


  golle_error err;
  if (set->root) {
    /* Temporarily assign user values for comparison. */
    node->buffer.bin = (void *)item;
    node->buffer.size = size;
    err = golle_set_insert_recursive (set->comp, 
				      set->root, 
				      node);
    if (err != GOLLE_OK) {
      /* Clean up memory, but don't clean up the user's value. */
      memset (node, 0, sizeof (*node));
      set_leaf_unlink (node);
      return err;
    }
  }
  else {
    set->root = node;
  }

  /* Make a copy of the data before rebalancing.
   If it fails we can just unlink the node. */
  err = set_node_copy_data (node, item, size);
  if (err != GOLLE_OK) {
    set_leaf_unlink (node);
    return err;
  }
  
  golle_set_insert_a (set, node);

  set->count++;
  return GOLLE_OK;
}

golle_error golle_set_erase (golle_set_t *set,
			     const void *item,
			     size_t size)
{
  GOLLE_ASSERT (set, GOLLE_ERROR);
  
  /* Make sure the node exists. */
  set_node_t *found = set_find_node (set->root, set->comp, item, size);
  GOLLE_ASSERT (found, GOLLE_ENOTFOUND);

  /* Remove the node from the tree. */
  golle_set_erase_node (set, found);
  if (--set->count == 0) {
    set->root = NULL;
  }
  return GOLLE_OK;
}

golle_error golle_set_clear (golle_set_t *set) {
  GOLLE_ASSERT (set, GOLLE_ERROR);
  /* Remove all nodes recursively */
  set_tree_unlink (set->root);
  set->root = NULL;
  set->count = 0;
  return GOLLE_OK;
}

golle_error golle_set_find (const golle_set_t *set, 
			    const void *item,
			    size_t size,
			    const golle_bin_t **found)
{
  GOLLE_ASSERT (set, GOLLE_ERROR);
  GOLLE_ASSERT (found, GOLLE_ERROR);
  
  set_node_t *node = set_find_node (set->root, set->comp, item, size);
  GOLLE_ASSERT (node, GOLLE_ENOTFOUND);

  *found = &node->buffer;
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
				     const golle_bin_t **item)
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
   
  *item = &iter->next->buffer;
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
