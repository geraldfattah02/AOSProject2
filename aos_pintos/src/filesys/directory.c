#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "filesys/free-map.h"
#include "file.h"

/* A directory. */
struct dir
{
  struct inode *inode; /* Backing store. */
  off_t pos;           /* Current position. */
};

/* A single directory entry. */
struct dir_entry
{
  block_sector_t inode_sector; /* Sector number of header. */
  char name[NAME_MAX + 1];     /* Null terminated file name. */
  bool in_use;                 /* In use or free? */
};

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool dir_create (block_sector_t sector, size_t entry_cnt, block_sector_t parent)
{
  bool success = inode_create (sector, entry_cnt * sizeof (struct dir_entry), true);
  struct dir_entry files[2];
  memcpy (&files[0].name, ".", 2);
  files[0].inode_sector = sector;
  files[0].in_use = true;

  memcpy (&files[1].name, "..", 3);
  files[1].inode_sector = parent;
  files[1].in_use = true;

  struct inode *node = inode_open (sector);
  off_t size = 2 * sizeof (struct dir_entry);
  if (inode_write_at (node, &files, size, 0) != size) {
    DPRINT("Failed to write into directory\n");
    success = false;
  }
  inode_close (node);
  return success;
}

static struct inode *dir_create_helper (struct dir *current, char *name, void *aux)
{
  DPRINT("[start] dir_create_helper\n");
  block_sector_t sector;
  bool success = free_map_allocate (1, &sector);
  if (!success) {
    dir_close (current);
    DPRINT("[end] dir_create_helper\n");
    return NULL;
  }

  block_sector_t parent = inode_get_inumber (dir_get_inode (current));

  success = dir_create (sector, 0, parent);
  if (!success) {
    free_map_release (sector, 1);
    dir_close (current);
    DPRINT("[end] dir_create_helper\n");
    return NULL;
  }

  success = dir_add (current, name, sector);
  if (!success) {
    free_map_release (sector, 1);
    dir_close (current);
    DPRINT("[end] dir_create_helper\n");
    return NULL;
  }

  dir_close (current);
  DPRINT("[end] dir_create_helper\n");
  return (struct inode *) 1; // 1 for success
}

bool dir_create_from_path (const char *syscall_path) {
  DPRINT("Creating dir %s\n", syscall_path);
  struct inode* node = path_to_inode(syscall_path, &dir_create_helper, NULL, NULL);
  return node == 1;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *dir_open (struct inode *inode)
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      dir->pos = 0;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL;
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *dir_reopen (struct dir *dir)
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void dir_close (struct dir *dir)
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *dir_get_inode (struct dir *dir) { return dir->inode; }

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool lookup (const struct dir *dir, const char *name,
                    struct dir_entry *ep, off_t *ofsp)
{
  struct dir_entry e;
  size_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
  {
    DPRINT("Checking name %s == (target) %s, use? %d, comp? %d\n", e.name, name, e.in_use, !strcmp (name, e.name));
    if (e.in_use && !strcmp (name, e.name))
    {
      if (ep != NULL)
        *ep = e;
      if (ofsp != NULL)
        *ofsp = ofs;
      DPRINT("Returning true\n");
      return true;
    }
  }
  DPRINT("Lookup: exit with read %d\n", inode_read_at (dir->inode, &e, sizeof e, ofs));
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool dir_lookup (const struct dir *dir, const char *name, struct inode **inode)
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  DPRINT("dir_lookup\n");
  if (lookup (dir, name, &e, NULL))
    *inode = inode_open (e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool dir_add (struct dir *dir, const char *name, block_sector_t inode_sector)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  DPRINT("dir_add\n");
  /* Check that NAME is not in use. */
  dir_inode_lock ( dir_get_inode (dir));
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.

     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

done:
  dir_inode_unlock ( dir_get_inode (dir));
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool dir_remove (struct dir *dir, const char *name)
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  DPRINT("dir_remove\n");
  /* Find directory entry. */
  dir_inode_lock ( dir_get_inode (dir));
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e)
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

done:
  dir_inode_unlock ( dir_get_inode (dir));
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e)
    {
      dir->pos += sizeof e;
      if (e.in_use)
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        }
    }
  return false;
}

/* Reads the next directory entry in FILE and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool dir_readdir_file (struct file *file, char name[NAME_MAX + 1])
{
  struct dir_entry e;
  if (file->pos == 0) {
    file->pos += 2 * sizeof(struct dir_entry); // skip . and ..
  }

  while (inode_read_at (file->inode, &e, sizeof e, file->pos) == sizeof e)
    {
      file->pos += sizeof e;
      if (e.in_use)
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        }
    }
  return false;
}

void debug_print_directory (struct dir *dir) {
  struct dir *temp = dir_reopen( dir );
  char name[15];
  while (dir_readdir (temp, &name)) {
    DPRINT("Contains: %s\n", name);
  }
  dir_close (temp);
}
