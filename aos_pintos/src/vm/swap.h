#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stdbool.h>
#include <stddef.h>  

/* Type for swap slot indices */
typedef size_t swap_index_t;

/* Initialize the swap system */
void swap_init (void);

/* Swap out a page to the swap partition */
swap_index_t swap_out (void *frame);

/* Swap in a page from the swap partition */
bool swap_in (swap_index_t swap_index, void *frame);

#endif /* vm/swap.h */