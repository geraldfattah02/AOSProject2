#include "../threads/palloc.h"
#include "../threads/malloc.h"
#include "../lib/kernel/list.h"
#include "../lib/debug.h"
#include "frame.h"
#include "../threads/synch.h"

struct lock frame_table_lock;

struct list frame_table;

void init_frame_table() {
    list_init (&frame_table);
    lock_init (&frame_table_lock);
}

void* allocate_frame(enum palloc_flags flags) {
    void* page = palloc_get_page (flags);

    if (page == NULL) { // evict
        evict_page();
    }
    else { // Add to frame table
        struct frame_entry* frame = malloc(sizeof(struct frame_entry));

        frame->last_accessed = 0;
        frame->page_entry = page;

        lock_acquire (&frame_table_lock);
        list_push_back (&frame_table, &frame->elem);
        lock_release (&frame_table_lock);
    }  
    
    return page;
}

void evict_page() {
    PANIC ("No available pages!");
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