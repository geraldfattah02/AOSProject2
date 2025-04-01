#ifndef __VM_FRAME_H
#define __VM_FRAME_H

// 64 MB / 4 KB = 16 000 phyical frames
// 
struct frame_entry {
    void* page_entry;
    uint32_t last_accessed;
    struct list_elem elem;
};

void init_frame_table();

void* allocate_frame(enum palloc_flags flags);
void free_frame();

#endif /* vm/frame.h */
