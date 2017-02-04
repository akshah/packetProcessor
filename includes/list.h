/*
 * Definitions for a doubly linked list.
 */

#include "patricia.h"
#include <stdlib.h>

#ifndef __LIST_H__
#define __LIST_H__

/* List node structure*/
struct list_node
{
    struct list_node *next;
    struct list_node *prev;
    patricia_node_t *patricia_node;
};

typedef struct list_node list_node_t;

/* Function prototypes */
list_node_t *new_node();
patricia_node_t *get_first_node(list_node_t *);
list_node_t *insert(list_node_t *, patricia_node_t *);
patricia_node_t *pop(list_node_t *);
void remove_first_node(list_node_t *);

#endif
