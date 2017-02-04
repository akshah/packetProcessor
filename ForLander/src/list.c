/*
 * Definitions for linked list functions.
 */

#include "../includes/list.h"

/* Create a new list node.
 * Input: None
 * Returns: Address of new list node.
 */
list_node_t *new_node()
{
    list_node_t *new_node = malloc(sizeof(list_node_t));
    if (!new_node) {
	return NULL;
    }
    new_node->next = NULL;
    new_node->prev = NULL;
    new_node->patricia_node = NULL;
    return new_node;
}

/* Returns the first list node.
 * Input: Address of list head.
 * Returns: Address of node's patricia node
 */
patricia_node_t *get_first_node(list_node_t * head)
{
    return head->next->patricia_node;
}

/* Insert a new list node.
 * Inputs: Address of list head, Address of patricia node.
 * Returns: Address of new list node.
 */
list_node_t *insert(list_node_t * head, patricia_node_t * node)
{
    list_node_t *n = new_node();
    if (!n) {
	return NULL;
    }

    n->patricia_node = node;
    // Starting at list head, advance pointer until new node mask > the list node's bitlen
    if (!head->next) {
	head->next = n;
	n->prev = head;
	return n;
    }
    list_node_t *tmp = head->next;
    while (tmp->next) {
	if (tmp->next->patricia_node->prefix) {
	    if (tmp->next->patricia_node->prefix->bitlen <
		node->prefix->bitlen) {
		break;
	    }
	}
	tmp = tmp->next;
    }
    n->next = tmp;
    n->prev = tmp->prev;
    tmp->prev->next = n;
    tmp->prev = n;
    return n;
}

/* Delete the first node.
 * Inputs: Address of list head
 * Returns: 0 on success, -1 on failure.
 */
void remove_first_node(list_node_t * head)
{
    list_node_t *n = head->next;
    head->next = n->next;
    n->next->prev = head;
    n->next = NULL;
    n->prev = NULL;
    free(n);
}
