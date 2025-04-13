#include "vm/swap.h"
#include "vm/page.h"
#include "devices/block.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include <bitmap.h>
#include <stdio.h>
#include <string.h>

/* The swap device */
static struct block *swap_device;

/* Bitmap to track which swap slots are in use */
static struct bitmap *swap_map;

/* Lock for synchronizing access to the swap table */
static struct lock swap_lock;

/* Number of sectors per page */
#define PAGE_SECTORS (PGSIZE / BLOCK_SECTOR_SIZE)

void swap_init (void)
{
  /* Get the swap device */
  swap_device = block_get_role (BLOCK_SWAP);
  if (swap_device == NULL)
  {
    printf("No swap device available, swapping disabled\n");
    return;
  }
  
  /* Calculate number of swap slots on the device */
  size_t swap_size = block_size (swap_device) / PAGE_SECTORS;
  
  /* Initialize bitmap - each bit represents one swap slot */
  swap_map = bitmap_create (swap_size);
  if (swap_map == NULL)
    PANIC("Could not create swap bitmap");
  
  /* Initialize all slots as free (0) */
  bitmap_set_all (swap_map, false);
  
  /* Initialize swap lock */
  lock_init (&swap_lock);
  
  DPRINT ("Swap initialized with %zu slots\n", swap_size);
}

/* Swap out a page to the swap device, returns the swap slot index */
swap_index_t 
swap_out (void *frame)
{
  ASSERT (frame != NULL);
  
  /* Acquire the swap lock */
  lock_acquire (&swap_lock);
  
  /* Find a free swap slot */
  size_t swap_index = bitmap_scan_and_flip (swap_map, 0, 1, false);
  if (swap_index == BITMAP_ERROR)
  {
    lock_release (&swap_lock);
    PANIC("Swap space is full!");
  }
  
  /* Write page to the swap slot, one sector at a time */
  for (size_t i = 0; i < PAGE_SECTORS; i++)
  {
    block_write (swap_device, 
                 swap_index * PAGE_SECTORS + i,
                 (uint8_t*) frame + i * BLOCK_SECTOR_SIZE);
  }

  DPRINT ("Swapping out %p to %d\n", frame, swap_index);
  
  lock_release (&swap_lock);
  
  return swap_index;
}

/* Swap in a page from the swap device to a frame */
bool
swap_in (swap_index_t swap_index, void *frame)
{
  ASSERT (frame != NULL);

  DPRINT ("Swapping in %d to %p\n", swap_index, frame);
  
  /* Acquire the swap lock */
  lock_acquire (&swap_lock);
  
  /* Verify the swap slot is in use */
  if (!bitmap_test (swap_map, swap_index))
  {
    PANIC ("Slot not in use");
    lock_release (&swap_lock);
    return false;
  }
  
  /* Read the page from swap one sector at a time */
  for (size_t i = 0; i < PAGE_SECTORS; i++)
  {
    block_read (swap_device,
               swap_index * PAGE_SECTORS + i,
               (uint8_t*) frame + i * BLOCK_SECTOR_SIZE);
  }
  
  /* Free the swap slot */
  bitmap_set (swap_map, swap_index, false);
  
  lock_release (&swap_lock);
  
  return true;
}
