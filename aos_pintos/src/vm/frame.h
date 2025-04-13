#ifndef __VM_FRAME_H
#define __VM_FRAME_H

struct frame_table_entry {
    struct list_elem elem;
    void* kpage_addr;
    struct thread * owner_thread;
    struct sup_page_table_entry *current_sup_page;
    bool pinned;
};

void init_frame_table();

void* allocate_frame(enum palloc_flags flags);
void free_frame(void * page);
void pin_frame(void *page);
void unpin_frame(void *page);
void* evict_page(void);

#endif /* vm/frame.h */
