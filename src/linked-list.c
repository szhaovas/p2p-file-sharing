#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "linked-list.h"


/* Constants */
#define TRUE 1
#define FALSE 0



/* LinkedList */

/**
 * Initialze a linked list.
 * This function be called once and only once before a linked list
 * may be used.
 */
void init_list(LinkedList* list)
{
    list->head = NULL;
    list->size = 0;
    list->__id_gen = 0;
    list->__references = 0;
    list->__has_invalid = FALSE;
}



/**
 * Add an item, pointed to by |item|, to a linked list.
 */
Node* add_item(LinkedList* list, void* item)
{
    // Allocate a new node
    Node* node = malloc(sizeof(Node));
    node->item = item;
    node->prev = NULL;
    node->next = NULL;
    node->__id = list->__id_gen;
    node->__valid = TRUE;
    
    // Adding to an empty list
    if ( !list->head )
    {
        list->head = node;
    }
    // At least one elements => Insert at head
    else
    {
        node->next = list->head;
        list->head->prev = node;
        list->head = node;
    }
    list->size += 1;
    list->__id_gen += 1;
    return node;
}


/**
 * Drop a node from a linked list.
 */
void* drop_node(LinkedList* list, Node* node)
{
    assert(node);
    if (node->__valid)
    {
        node->__valid = FALSE;
        list->size -= 1;
        list->__has_invalid = TRUE;
    }
    return node->item;
}


/**
 * Find an item in a linked list.
 */
Node* find_item(LinkedList* list, void* item)
{
    ITER_LOOP(it, list)
    {
        if (iter_get_item(it) == item)
        {
            Node* node = iter_get_node(it);
            ITER_END(it);
            return node;
        }
    }
    ITER_END(it);
    return NULL;
}


/**
 * Drop an item from a linked list by iterating through it
 */
void* find_and_drop_item(LinkedList* list, void* item)
{
    Node* node = find_item(list, item);
    if (node)
        return drop_node(list, node);
    else
        return NULL;
}


/**
 * Remove invalid nodes from a linked list.
 */
void remove_invalid(LinkedList* list)
{
    if (!list->__has_invalid) return;
    
    // Remove invalid nodes at the head
    while (list->head && !list->head->__valid)
    {
        Node* next_node = list->head->next;
        free(list->head);
        list->head = next_node; // There is no prev link to fix
    }
    
    // Remove invalid nodes after head
    Node* node = list->head;
    while (node)
    {
        if ( !node->__valid )
        {
            // Fix prev and next link
            Node* prev_node = node->prev;
            Node* next_node = node->next;
            if (prev_node)
                prev_node->next = next_node;
            if (next_node)
                next_node->prev = prev_node;
            
            free(node);
            node = next_node;
        }
        else // Skip valid nodes
            node = node->next;
    }
    list->__has_invalid = FALSE;
}


/**
 * Convert a list to string and store it in the input buffer.
 */
char* list_to_str(LinkedList* list, char* buf)
{
    *buf++ = '[';
    for (Node* node = list->head; node != NULL; node = node->next)
    {
        if (node != list->head)
            buf += sprintf(buf, ", ");
        
        buf += sprintf(buf, "%i", node->__id);
    }
    *buf++ = ']';
    *buf++ = '\0';
    return buf;
}



/* Iterator_LinkedList */

/* Public functions */

/**
 * Go to the next valid node.
 * Pre-condition: |it->curr| must be non-null.
 */
void iter_next(Iterator_LinkedList* it)
{
    assert(it->curr);
    // Advance iterator until it finds a valid node, or
    // reaches the end of the list
    do {
        it->curr = it->curr->next;
    } while (it->curr && !it->curr->__valid);
}


/**
 * Obtain an iterator for the linked list |list|.
 */
Iterator_LinkedList* iter(LinkedList* list)
{
    Iterator_LinkedList* it = malloc(sizeof(Iterator_LinkedList));
    it->list = list;
    it->curr = list->head;
    list->__references += 1;
    // If head is invalid, go to the first valid node
    if (it->curr && !it->curr->__valid)
        iter_next(it);
    return it;
}



/**
 * Check if an iterator has any more node.
 */
int iter_empty(Iterator_LinkedList* it)
{
    return !it->curr;
}


/**
 * Clean iterator.
 * Pre-condition: Must be called when and only when an iterator is no longer in use.
 */
void iter_clean(Iterator_LinkedList* it)
{
    it->list->__references -= 1;
    // The last iterator refering to a list should call |remove_invalid|
    // to remove all invalid nodes
    if (it->list->__references == 0 && it->list->__has_invalid)
        remove_invalid(it->list);
    free(it);
}


/**
 * Return the current item from the iterator.
 * Pre-condition: |it->curr| must be non-null.
 */
void* iter_get_item(Iterator_LinkedList* it)
{
    assert(it->curr);
    return it->curr->item;
}

/**
 * Return the current node from the iterator.
 * Pre-condition: |it->curr| must be non-null.
 */
Node* iter_get_node(Iterator_LinkedList* it)
{
    assert(it->curr);
    return it->curr;
}


/**
 * Drop the current item from an iterator.
 */
void* iter_drop_curr(Iterator_LinkedList* it)
{
    return drop_node(it->list, it->curr);
}
