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
typedef int off_t; // Define off_t manually as an integer type

#define PAGE_FILE 0
#define PAGE_ZERO 1
#define PAGE_FILE_ZERO 2

struct supplemental_page_table_entry{
    struct list_elem elem;

    void* pageAdress; 
    bool isFaulted;
    struct thread * owner;
    uint32_t read_bytes;
    uint32_t zero_bytes;
    struct file * file;
    off_t offset;
    bool writable;
    uint32_t type;
};


