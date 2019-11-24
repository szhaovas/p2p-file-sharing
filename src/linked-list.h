#ifndef _LINKED_LIST_H_
#define _LINKED_LIST_H_

/* Node */
struct _node_struct {
    struct _node_struct* prev;
    struct _node_struct* next;
    void* item;
    int __id;
    int __valid;
};

typedef struct _node_struct Node;


/* Linked List */
typedef struct {
    Node* head;
    int size;
    int __id_gen;
    int __references;
    int __has_invalid;
} LinkedList;


LinkedList* new_list(void);

void delete_list(LinkedList* list);

Node* add_item(LinkedList* list, void* item);

Node* find_item(LinkedList* list, void* item);

void* drop_node(LinkedList* list, Node* node);

void* find_and_drop_item(LinkedList* list, void* item);

char* list_to_str(LinkedList* list, char* buf);


/**
 * Linked List Iterator.
 *
 * Example Usage
 
     LinkedList* list;
     // Adding items to |list| ...
     Iterator_LinkedList* it;
     for (it = iter(list); !iter_empty(it); it = iter_next(it))
     {
        // iter_get, iter_add, iter_drop_curr, etc.
     }
     iter_clean(it);
 
*/

typedef struct {
    LinkedList* list;
    Node* curr;
} Iterator_LinkedList;

Iterator_LinkedList* iter(LinkedList* list);

void iter_clean(Iterator_LinkedList* it);

int iter_empty(Iterator_LinkedList* it);

void iter_next(Iterator_LinkedList* it);

void* iter_get_item(Iterator_LinkedList* it);

Node* iter_get_node(Iterator_LinkedList* it);

void* iter_drop_curr(Iterator_LinkedList* it);

#define ITER_LOOP(it, list) \
    Iterator_LinkedList* it; \
    for (it = iter(list); !iter_empty(it); iter_next(it))

#define ITER_END(it) do { iter_clean(it); } while (0)


#endif /* _LINKED_LIST_H_ */

