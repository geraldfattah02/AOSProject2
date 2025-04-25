#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "../threads/thread.h"
#include "threads/malloc.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init (bool format)
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format)
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done (void) { free_map_close (); }

static struct inode *path_to_inode (const char *syscall_path)
{
  DPRINT("path_to_inode: %s\n", syscall_path);
  char *path = malloc(strlen(syscall_path) + 1);
  if (!path) {
    DPRINT("Failed to allocate path\n");
    return NULL;
  }
  strlcpy (path, syscall_path, strlen(syscall_path) + 1);

  bool should_close = true;
  struct dir *current_dir = dir_open_root ();
  if (syscall_path[0] != '/' && thread_current ()->working_directory != NULL) {
    current_dir = thread_current ()->working_directory;
    should_close = false;
  }

  struct inode *node = NULL;
  char *token, *save_ptr;
  for (token = strtok_r (path, "/", &save_ptr);
       token != NULL;
       token = strtok_r (NULL, "/", &save_ptr))
  {
    DPRINT("Token %s\n", token);
    if (strlen(token) == 0) {
      continue;
    }
    bool success = dir_lookup (current_dir, token, &node);
    if (should_close) {
      dir_close (current_dir);
    }
    if (!success) {
      DPRINT("Dir doesn't contain file for %s\n", token);
      return NULL;
    }
    current_dir = dir_open (node);
    should_close = true;
  }
  free (path);

  if (node == NULL) {
    node = dir_get_inode (current_dir);
  }

  return node;
}


/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create (const char *name, off_t initial_size)
{
  block_sector_t inode_sector = 0;
  struct dir *dir = dir_open_root ();
  bool success = (dir != NULL && free_map_allocate (1, &inode_sector) &&
                  inode_create (inode_sector, initial_size, false) &&
                  dir_add (dir, name, inode_sector));
  if (!success && inode_sector != 0)
    free_map_release (inode_sector, 1);

  dir_close (dir);

  return success;
}

bool filesys_create_from_path (const char *syscall_path, struct dir* working_directory, off_t initial_size) {
  DPRINT("Creating file %s\n", syscall_path);
  block_sector_t sector;
  bool success = free_map_allocate (1, &sector);
  if (!success) {
    free_map_release (sector, 1);
    return false;
  }

  char *path = malloc(strlen(syscall_path) + 1);
  if (!path) {
    DPRINT("Failed to allocate path\n");
    free_map_release (sector, 1);
    return false;
  }
  strlcpy (path, syscall_path, strlen(syscall_path) + 1);

  bool should_close = false;
  struct dir *current_dir = working_directory;
  if (syscall_path[0] == '/') {
    current_dir = dir_open_root ();
    should_close = true;
  }

  struct inode *node = NULL;
  char *token, *save_ptr;
  for (token = strtok_r (path, "/", &save_ptr);
       token != NULL;
       token = strtok_r (NULL, "/", &save_ptr))
  {
    DPRINT("Token %s\n", token);
    if (strlen(token) == 0) {
      continue;
    }
    success = dir_lookup (current_dir, token, &node);
    if (!success) {
      DPRINT("DIR %s not found\n", token);
      break;
    }
    current_dir = dir_open (node);
    should_close = true;
  }
  block_sector_t parent = inode_get_inumber (dir_get_inode(current_dir));
  DPRINT("parent %d\n", parent);
  
  if (success) { // Full path was found, directory exists
    DPRINT("Full file path exists\n");
    if (should_close) {
      dir_close (current_dir);
    }
    free (path);
    return false;
  }
  if (token == NULL || strtok_r (NULL, "/", &save_ptr) != NULL) {
    DPRINT("Remaining token %s\n", token);
    if (should_close) {
      dir_close (current_dir);
    }
    free (path);
    return false; // Not the last name in the path
  }

  inode_create (sector, initial_size, false);
  dir_add (current_dir, token, sector);
  DPRINT("Created file %s\n", token);

  if (should_close) {
    dir_close (current_dir);
  }
  free (path);
  return true;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *filesys_open (const char *name)
{
  struct inode *inode = path_to_inode (name);

  if (inode == NULL)
    return NULL;

  if (inode_get_symlink (inode))
    {
      char target[15];
      inode_read_at (inode, target, NAME_MAX + 1, 0);
      struct dir *root = dir_open_root ();
      if (!dir_lookup (root, target, &inode))
        {
          return NULL;
        }
      dir_close (root);
    }

  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove (const char *name)
{
  struct dir *dir = dir_open_root ();
  bool success = dir != NULL && dir_remove (dir, name);
  dir_close (dir);

  return success;
}

/* Creates symbolic link LINKPATH to target file TARGET
   Returns true if symbolic link created successfully,
   false otherwise. */
bool filesys_symlink (char *target, char *linkpath)
{
  ASSERT (target != NULL && linkpath != NULL);
  bool success = filesys_create (linkpath, 15);
  struct file *symlink = filesys_open (linkpath);
  inode_set_symlink (file_get_inode (symlink), true);
  inode_write_at (file_get_inode (symlink), target, NAME_MAX + 1, 0);
  file_close (symlink);
  return success;
}

/* Formats the file system. */
static void do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16, ROOT_DIR_SECTOR))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}