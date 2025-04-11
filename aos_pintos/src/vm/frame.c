#include "../threads/palloc.h"
#include "../threads/malloc.h"
#include "../lib/kernel/list.h"
#include "../lib/debug.h"
#include "frame.h"
#include "../threads/synch.h"
#include "../userprog/pagedir.h"
#include "../threads/thread.h"
#include "swap.h"
#include "page.h"
struct lock frame_table_lock;
struct lock eviction_lock;
struct list frame_table;
struct list_elem *eviction_pointer = NULL;


void init_frame_table() {
    list_init (&frame_table);
    lock_init (&frame_table_lock);
    lock_init(&eviction_lock);
}

void* allocate_frame(enum palloc_flags flags) {
    void* page = palloc_get_page (flags);
    struct frame_entry* frame = malloc(sizeof(struct frame_entry));


    if (page == NULL) { // evict
        evict_page();
        return allocate_frame(flags); //once we evict, call function again and there should be space now
    }
    else { // Add to frame table

        frame->page_entry = page;
        frame->owner_thread = thread_current();
        frame->pinned = false;

        lock_acquire (&frame_table_lock);
        list_push_back (&frame_table, &frame->elem);
        lock_release (&frame_table_lock);
    }  
    
    return frame;
}

void * evict_page() {
    //go through fram table list, chcek the accessed bit for each page, if true -> set to false,
    //iterate through until there is an accessed=true (recently accessed)
    lock_acquire(&frame_table_lock);
    struct frame_entry *victim = NULL;
    
    if (eviction_pointer == NULL || eviction_pointer == list_end(&frame_table)) {
        eviction_pointer = list_begin(&frame_table);
        struct frame_entry *f = list_entry(eviction_pointer, struct frame_entry, elem);
        victim = f;
    }
    // Iterate using the eviction pointer
    while (true) {
        if (eviction_pointer == list_end(&frame_table)) {
            eviction_pointer = list_begin(&frame_table);
        }

        struct frame_entry *f = list_entry(eviction_pointer, struct frame_entry, elem);
        eviction_pointer = list_next(eviction_pointer);  // advance for next iteration

        if (f->pinned) continue;

        struct supplemental_page_table_entry *spte = fte_to_spte(f);
        // printf("Page Entry: %p\n",f->page_entry);
        printf("Page Directory: %p\n",f->owner_thread->pagedir);
        printf("Spte page adress: %p\n",spte->pageAdress);
        if(spte != NULL){
            
            if (!pagedir_is_accessed(f->owner_thread->pagedir, spte->pageAdress)) {
                victim = f;
                printf("Not Accessed\n");
                break;
            } else {
                pagedir_set_accessed(f->owner_thread->pagedir, spte->pageAdress, false);
                printf("Setting Access to Zero\n");
            }
        }else{
            continue;
        }
    }
    
    // Remove victim frame from table and free it
    struct supplemental_page_table_entry *spte = fte_to_spte(victim);
    printf("Checking dirty bit\n");
    // Check if the page is dirty and swap it out if necessary
    if (pagedir_is_dirty(victim->owner_thread->pagedir, spte->pageAdress)) {
        printf("Is dirty\n");
        // Swap out the page
        swap_index_t swap_index = swap_out(victim->page_entry);
        printf("Swapped out\n");
        if (swap_index != -1) {
            //update the supplemental page table entry
            victim->supplemental_page_table_entry->swap_index = swap_index;
            victim->supplemental_page_table_entry->is_swapped = true;
            victim->supplemental_page_table_entry->isFaulted = false; 
        }
    }
    lock_release(&frame_table_lock);

    free_frame(victim->page_entry);
}

void free_frame(void* page) {
    struct list_elem *e;

    lock_acquire (&frame_table_lock);
    for (e = list_begin (&frame_table); e != list_end (&frame_table); e = list_next (e))
    {
        struct frame_entry *f = list_entry (e, struct frame_entry, elem);
        if (f->page_entry == page) {
            list_remove (f);
            palloc_free_page (f->page_entry);
            free (f);
            break;
        }
    }
    lock_release (&frame_table_lock);
}

static struct frame_entry * find_frame_entry(void *page)
{
  struct list_elem *e;
  
  // Search through the frame table
  for (e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e))
  {
    struct frame_entry *entry = list_entry(e, struct frame_entry, elem);
    if (entry->page_entry == page)
      return entry;
  }
  
  return NULL;
}

void pin_frame(void *page) {
    lock_acquire(&frame_table_lock);
    struct frame_entry *entry = find_frame_entry(page);
    if (entry != NULL)
        entry->pinned = true;
    lock_release(&frame_table_lock);
}

void unpin_frame(void *page) {
    lock_acquire(&frame_table_lock);
    struct frame_entry *entry = find_frame_entry(page);
    if (entry != NULL)
        entry->pinned = false;
    lock_release(&frame_table_lock);
}
