#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "file.h"
#include "directory.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define DIRECT_BLOCKS 122
#define INDIRECT_SIZE 128
#define INVALID_SECTOR ((block_sector_t) -1)

static char zeros[BLOCK_SECTOR_SIZE];

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
{
  size_t blocks;        /* Total allocated blocks. */
  off_t length;         /* File size in bytes. */
  unsigned magic;       /* Magic number. */
  bool is_symlink;      /* True if symbolic link, false otherwise. */
  bool is_dir; //used to check if inode is bening used for directory
  block_sector_t direct_map[DIRECT_BLOCKS];
  block_sector_t indirect_block;
  block_sector_t doubly_indirect;
};

bool inode_allocate(size_t sectors, struct inode_disk *disk_inode);

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode
{
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct inode_disk data; /* Inode content. */
  struct lock lock;       /* Lock to protect data. */
  struct lock dir_lock;   /* Used to synchronize directory updates. */
};

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector (const struct inode *inode, off_t pos)
{
  ASSERT (inode != NULL);
  block_sector_t index = pos / BLOCK_SECTOR_SIZE;

  // Check if index is in the direct blocks
  if (index < DIRECT_BLOCKS) {
    return inode->data.direct_map[index];
  }

  index -= DIRECT_BLOCKS;
  block_sector_t buffer[INDIRECT_SIZE];

  // Check if index is in the indirect block section
  if (index < INDIRECT_SIZE) {
    if (inode->data.indirect_block == INVALID_SECTOR) {
      return INVALID_SECTOR;
    }
    block_read(fs_device, inode->data.indirect_block, &buffer);
    return buffer[index];
  }

  index -= INDIRECT_SIZE;

  // Must be in the doubly indirect block section
  if (inode->data.doubly_indirect == INVALID_SECTOR) {
    return INVALID_SECTOR;
  }
  block_read(fs_device, inode->data.doubly_indirect, &buffer);

  block_sector_t indirect_sector = buffer[index / INDIRECT_SIZE];
  if (indirect_sector == INVALID_SECTOR) {
    return INVALID_SECTOR;
  }
  block_read(fs_device, indirect_sector, &buffer);

  return buffer[index % INDIRECT_SIZE];
}

/* Allocate a block device sector to contain byte offset POS
   within INODE.
   Returns false if this fails. */
static bool allocate_sector (struct inode *inode, off_t pos, block_sector_t *sector)
{
  ASSERT (inode != NULL);
  bool success;
  block_sector_t index = pos / BLOCK_SECTOR_SIZE;

  // Check if index is in the direct blocks
  if (index < DIRECT_BLOCKS) {
    success = free_map_allocate (1, &inode->data.direct_map[index]);
    if (!success)
      return false;
    *sector = inode->data.direct_map[index];
    inode->data.blocks++;
    return true;
  }

  index -= DIRECT_BLOCKS;
  block_sector_t buffer[INDIRECT_SIZE];

  // Check if index is in the indirect block section
  if (index < INDIRECT_SIZE) {
    if (inode->data.indirect_block == INVALID_SECTOR) {
      success = free_map_allocate (1, &inode->data.indirect_block);
      if (!success) {
        return false;
      }
      memset(&buffer, (uint8_t) -1, BLOCK_SECTOR_SIZE);
      block_write (fs_device, inode->data.indirect_block, buffer);
    } else {
      block_read (fs_device, inode->data.indirect_block, &buffer);
    }
    success = free_map_allocate (1, &buffer[index]);
    if (!success) {
      return false;
    }
    block_write (fs_device, inode->data.indirect_block, buffer);
    *sector = buffer[index];

    inode->data.blocks++;
    return true;
  }

  index -= INDIRECT_SIZE;

  // Must be in the doubly indirect block section
  if (inode->data.doubly_indirect == INVALID_SECTOR) {
    success = free_map_allocate (1, &inode->data.doubly_indirect);
    if (!success) {
      return false;
    }
    memset(&buffer, (uint8_t) -1, BLOCK_SECTOR_SIZE);
    block_write (fs_device, inode->data.doubly_indirect, buffer);
  } else {
    block_read (fs_device, inode->data.doubly_indirect, &buffer);
  }

  block_sector_t indirect_sector = buffer[index / INDIRECT_SIZE];
  if (indirect_sector == INVALID_SECTOR) {
    success = free_map_allocate (1, &buffer[index / INDIRECT_SIZE]);
    if (!success) {
      return false;
    }
    indirect_sector = buffer[index / INDIRECT_SIZE];
    block_write (fs_device, inode->data.doubly_indirect, buffer);
    memset(&buffer, (uint8_t) -1, BLOCK_SECTOR_SIZE);
  } else {
    block_read (fs_device, indirect_sector, &buffer);
  }

  success = free_map_allocate (1, &buffer[index % INDIRECT_SIZE]);
  if (!success) {
    return false;
  }
  block_write (fs_device, indirect_sector, buffer);
  *sector = buffer[index % INDIRECT_SIZE];

  inode->data.blocks++;
  return true;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;
static struct lock inodes_lock;

/* Initializes the inode module. */
void inode_init (void)
{
  list_init (&open_inodes);
  lock_init (&inodes_lock);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create (block_sector_t sector, off_t length, bool is_dir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->is_symlink = false;
      disk_inode->is_dir = is_dir;
      //free_map_allocate (sectors, &disk_inode->start)
      if (inode_allocate(sectors, disk_inode))
        {
          block_write (fs_device, sector, disk_inode);
          success = true;
        }
      free (disk_inode);
    }
  return success;
}

// To create inode we need to allocate/map memory for the direct/indirect/doubly indirect
// portions of the disk_inode, and initialize data blocks to 0.
bool inode_allocate(size_t sectors, struct inode_disk *disk_inode)
{
  if (sectors > DIRECT_BLOCKS + INDIRECT_SIZE + INDIRECT_SIZE * INDIRECT_SIZE) {
    return false;
  }
  
  bool success = false;
  uint32_t allocated = 0;

  // First set all to uninitialized
  disk_inode->indirect_block = INVALID_SECTOR;
  disk_inode->doubly_indirect = INVALID_SECTOR;
  for (int i = 0; i < DIRECT_BLOCKS; i++) {
    disk_inode->direct_map[i] = INVALID_SECTOR;
  }

  // Allocate the direct blocks
  for (int i = 0; i < DIRECT_BLOCKS && allocated < sectors; i++) {
    success = free_map_allocate (1, &disk_inode->direct_map[i]);
    if (!success) {
      goto cleanup_direct;
    }
    block_write (fs_device, disk_inode->direct_map[i], zeros);
    allocated++;
  }

  if (allocated == sectors) {
    return true;
  }

  // Setup for the indirect blocks
  success = free_map_allocate (1, &disk_inode->indirect_block);
  if (!success) {
    goto cleanup_direct;
  }
  block_sector_t *indirect_block = calloc(INDIRECT_SIZE, sizeof(block_sector_t));
  if (indirect_block == NULL) {
    free_map_release (disk_inode->indirect_block, 1);
    goto cleanup_direct;
  }
  for (int i = 0; i < INDIRECT_SIZE; i++){
    indirect_block[i] = INVALID_SECTOR;
  }

  // Allocate the indirect blocks
  for (int i = 0; i < INDIRECT_SIZE && allocated < sectors; i++) {
    success = free_map_allocate (1, &indirect_block[i]);
    if (!success) {
      goto cleanup_indirect;
    }
    block_write (fs_device, indirect_block[i], zeros);
    allocated++;
  }
  block_write (fs_device, disk_inode->indirect_block, indirect_block);

  if (allocated == sectors) {
    return true;
  }

  // Setup for doubly indirect blocks
  success = free_map_allocate (1, &disk_inode->doubly_indirect);
  if (!success) {
    goto cleanup_indirect;
  }
  block_sector_t *doubly_indirect_block = calloc(INDIRECT_SIZE, sizeof(block_sector_t));
  if (doubly_indirect_block == NULL) {
    free_map_release (disk_inode->doubly_indirect, 1);
    goto cleanup_indirect;
  }
  for (int i = 0; i < INDIRECT_SIZE; i++){
    doubly_indirect_block[i] = INVALID_SECTOR;
  }

  // Allocate the doubly indirect blocks
  for (int i = 0; i < INDIRECT_SIZE && allocated < sectors; i++) {
    // Allocate an indirect block
    success = free_map_allocate (1, &doubly_indirect_block[i]);
    if (!success) {
      goto cleanup_doubly_indirect;
    }

    // Set each block sector to uninitialized
    for (int j = 0; j < INDIRECT_SIZE; j++){
      indirect_block[j] = INVALID_SECTOR;
    }

    // Allocate the data blocks
    for (int j = 0; j < INDIRECT_SIZE && allocated < sectors; j++) {
      success = free_map_allocate (1, &indirect_block[j]);
      if (!success) {
        goto cleanup_doubly_indirect;
      }
      block_write (fs_device, indirect_block[i], zeros);
      allocated++;
    }

    block_write (fs_device, doubly_indirect_block[i], indirect_block);
  }
  block_write (fs_device, disk_inode->doubly_indirect, doubly_indirect_block);

  if (allocated == sectors) {
    disk_inode->blocks = allocated;
    return true;
  }

  PANIC ("Tried to allocate too many sectors: inode_allocate");

cleanup_doubly_indirect:
  for (int i = 0; i < INDIRECT_SIZE; i++) {
    if (doubly_indirect_block[i] == INVALID_SECTOR)
      break;

    block_read (fs_device, doubly_indirect_block[i], indirect_block);
    for (int j = 0; j < INDIRECT_SIZE; j++) {
      if (indirect_block[j] == INVALID_SECTOR)
        break;

      free_map_release (1, indirect_block[i]);
    }
    free_map_release (1, doubly_indirect_block[i]);
  }
  free_map_release (1, disk_inode->doubly_indirect);
  free (doubly_indirect_block);

cleanup_indirect:
  block_read (fs_device, disk_inode->indirect_block, indirect_block);
  for (int i = 0; i < INDIRECT_SIZE; i++) {
    if (indirect_block[i] == INVALID_SECTOR)
      break;

    free_map_release (1, indirect_block[i]);
  }
  free (indirect_block);
  free_map_release (1, disk_inode->indirect_block);

cleanup_direct:
  for (int i = 0; i < DIRECT_BLOCKS; i++) {
    if (disk_inode->direct_map[i] == INVALID_SECTOR)
      break;

    free_map_release (disk_inode->direct_map[i], 1);
  }

  return false;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  lock_acquire (&inodes_lock);

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e))
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector)
        {
          lock_release (&inodes_lock);
          inode_reopen (inode);
          return inode;
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL) {
    lock_release (&inodes_lock);
    return NULL;
  }

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  DPRINT("Creating inode for sector %d, open_cnt=%d\n", sector, inode->open_cnt);
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init (&inode->lock);
  lock_init (&inode->dir_lock);
  block_read (fs_device, inode->sector, &inode->data);
  ASSERT (inode->data.magic == INODE_MAGIC);
  lock_release (&inodes_lock);

  return inode;
}

/* Reopens and returns INODE. */
struct inode *inode_reopen (struct inode *inode)
{
  if (inode != NULL) {
    lock_acquire (&inode->lock);
    DPRINT("Reopen inode for sector %d, open_cnt=%d\n", inode->sector, inode->open_cnt);
    inode->open_cnt++;
    lock_release (&inode->lock);
  }

  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk. (Does it?  Check code.)
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close (struct inode *inode)
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  DPRINT("Closing inode on sector %d\n", inode->sector);

  lock_acquire (&inodes_lock);
  lock_acquire (&inode->lock);

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove (&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      // TODO: also clean up the doubly indirect and direct blocks
      for (int i = 0; i < inode->data.length; i += BLOCK_SECTOR_SIZE) {
        free_map_release (byte_to_sector (inode, i), 1);
      }
      free_map_release (inode->sector, 1);
    }
    else { // Write to file
      block_write (fs_device, inode->sector, &inode->data);
    }

    DPRINT("Deleted inode on sector %d\n", inode->sector);

    lock_release (&inode->lock);
    lock_release (&inodes_lock);
    free (inode);
    return;
  }

  lock_release (&inode->lock);
  lock_release (&inodes_lock);
}

void check_open_inodes () {
  struct list_elem *e;

  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e))
    {
      struct inode *node = list_entry (e, struct inode, elem);
      if (node->open_cnt > 0) {
        DPRINT("inode left open: %p, sector %d, count %d\n", node, node->sector, node->open_cnt);
        // inode_close (node);
      }
    }

  DPRINT("Printing root dir\n");
  struct dir *root = dir_open_root ();
  debug_print_directory (root);
  dir_close (root);

  return NULL;
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove (struct inode *inode)
{
  ASSERT (inode != NULL);
  lock_acquire (&inode->lock);
  inode->removed = true;
  lock_release (&inode->lock);
}

bool is_inode_removed (struct inode *inode)
{
  return inode->removed;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at (struct inode *inode, void *buffer_, off_t size,
                     off_t offset)
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0)
    {
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0) {
        DPRINT("Chunk size %d\n", chunk_size);
        break;
      }

      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);

      if (sector_idx == INVALID_SECTOR) {
        if (offset < inode->data.length) { // Read zeros for unallocated sector
          memcpy (buffer + bytes_read, &zeros, chunk_size);
        } else {
          DPRINT("READ invalid sector %d\n", sector_idx);
          break;
        }
      }
      else if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          block_read (fs_device, sector_idx, buffer + bytes_read);
        }
      else
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL)
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                      off_t offset)
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  DPRINT("Writing %d bytes at off %d\n", size, offset);

  if (inode->deny_write_cnt)
    return 0;

  bool acquired_lock = false;
  while (size > 0)
    {
      if (offset > inode->data.length) {
        acquired_lock = true;
        lock_acquire (&inode->lock);
      }
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      if (sector_idx == INVALID_SECTOR) {
        bool success = allocate_sector (inode, offset, &sector_idx);
        DPRINT("Allocation: %d, sector %d\n", success, sector_idx);
        // Ran out of sectors
        if (!success) {
          break;
        }
        //inode->data.length += BLOCK_SECTOR_SIZE;
      }
      if (acquired_lock) {
        lock_release (&inode->lock);
        acquired_lock = false;
      }
      DPRINT("Writing to sector idx %d\n", sector_idx);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          block_write (fs_device, sector_idx, buffer + bytes_written);
        }
      else
        {
          /* We need a bounce buffer. */
          if (bounce == NULL)
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left)
            block_read (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          block_write (fs_device, sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  if (acquired_lock) {
    lock_release (&inode->lock);
  }
  free (bounce);

  if (bytes_written > 0) {
    lock_acquire (&inode->lock);
    inode->data.length = inode->data.length > offset 
      ? inode->data.length
      : offset;
    lock_release (&inode->lock);
  }
  DPRINT("Wrote bytes: %d, File size: %d\n", bytes_written, inode->data.length);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write (struct inode *inode)
{
  lock_acquire (&inode->lock);
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  lock_release (&inode->lock);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write (struct inode *inode)
{
  lock_acquire (&inode->lock);
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
  lock_release (&inode->lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length (const struct inode *inode) { return inode->data.length; }

bool inode_get_symlink (struct inode *inode) { 
  ASSERT (inode != NULL);
  return inode->data.is_symlink; 
}

void inode_set_symlink (struct inode *inode, bool is_symlink)
{
  inode->data.is_symlink = is_symlink;
  block_write (fs_device, inode->sector, &inode->data);
}

bool inode_is_dir (struct inode *inode)
{ 
  return inode->data.is_dir; 
}

size_t inode_count_blocks (struct inode *node)
{
  return node->data.blocks;
}

bool dir_is_empty (struct inode *node, bool *result)
{
  if (!inode_is_dir (node)) {
    *result = true;
    return true;
  }
  struct file *file = file_open (node);
  if (file == NULL) {
    return false;
  }
  char name[15];
  bool empty = !dir_readdir_file (file, &name);
  *result = empty;
  return true;
}

void dir_inode_lock (struct inode *node) {
  lock_acquire (&node->dir_lock);
}

void dir_inode_unlock (struct inode *node) {
  lock_release (&node->dir_lock);
}
