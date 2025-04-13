#include "../threads/palloc.h"
#include "../threads/malloc.h"
#include "../lib/kernel/list.h"
#include "../lib/debug.h"
#include "frame.h"
#include "../threads/synch.h"
#include <stdbool.h>
#include "../userprog/pagedir.h"
#include "../threads/thread.h"
#include <stdbool.h>
#include "swap.h"

typedef int off_t; // Define off_t manually as an integer type
#define MAX_STACK_SIZE (1 << 23) // 8MB stack size limit

enum spte_type {
    PAGE_FROM_FILE,
    PAGE_ALL_ZERO,
    PAGE_CHANGED,
};

struct sup_page_table_entry {
    struct list_elem elem;
    void* user_page;
    enum spte_type page_type;
    swap_index_t swap_index;  
    bool is_swapped; 
    uint32_t read_bytes;
    uint32_t zero_bytes;
    off_t offset;
    bool writable;
    struct file * file;
};

bool install_page (void *upage, void *kpage, bool writable);
bool grow_stack (void *virtual_page);
struct sup_page_table_entry * lookup_sup_page_entry (void *upage);
bool load_spte_into_frame (void *frame, struct sup_page_table_entry *spte);

struct sup_page_table_entry *
init_file_entry (void *upage, struct file *file, off_t offset, bool writable,
                 uint32_t read_bytes, uint32_t zero_bytes);

void clear_current_supplemental_page_table (void);