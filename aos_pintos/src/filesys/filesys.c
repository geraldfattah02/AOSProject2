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

/* Get current thread's working directory, or set to root if NULL. */
static struct dir *get_current_working_directory ()
{
  if (!thread_current ()->working_directory) {
    DPRINT("Open root\n");
    thread_current ()->working_directory = dir_open_root ();
  }

  DPRINT("Working sector %u\n", inode_get_inumber(dir_get_inode(thread_current ()->working_directory)));
  return thread_current ()->working_directory;
}

;

/* Will close current_dir */
static struct inode *path_to_inode_helper (struct dir *current_dir, char *path, callback_fn missing_token, callback_fn last_token, void *aux)
{
  DPRINT("path_to_inode_helper: %s\n", path);
  
  struct inode *node = NULL;
  char *prev_token, *save_ptr;
  char *token = strtok_r (path, "/", &save_ptr);
  prev_token = token;
  while (token != NULL) 
  {
    DPRINT("Token %s\n", token);
    if (strlen(token) == 0) {
      token = strtok_r (NULL, "/", &save_ptr);
      continue;
    }
    bool success = dir_lookup (current_dir, token, &node);
    if (!success) {
      DPRINT("Dir doesn't contain file for %s, sector %u\n", token, inode_get_inumber (dir_get_inode (current_dir)));
      if (strtok_r (NULL, "/", &save_ptr) == NULL && missing_token != NULL) {
        DPRINT("Have callback for missing element: %s\n", token);

        return missing_token (current_dir, token, aux);
      }
      dir_close (current_dir);
      DPRINT("Returning null\n");
      return NULL;
    }
    prev_token = token;
    token = strtok_r (NULL, "/", &save_ptr);
    if (token == NULL) {
      if (last_token != NULL) {
        DPRINT("Have callback for last element: %s\n", prev_token);

        return last_token (current_dir, prev_token, aux);
      }
      DPRINT("Early exit\n");
      break;
    }
    dir_close (current_dir);
    current_dir = dir_open (node);
  }
  dir_close (current_dir);

  DPRINT("Returning node %p\n", node);
  return node;
}

struct inode *path_to_inode (const char *syscall_path, callback_fn missing_token, callback_fn last_token, void *aux)
{
  DPRINT("path_to_inode: %s\n", syscall_path);

  char *path = malloc(strlen(syscall_path) + 1);
  if (!path)
    return NULL;
  strlcpy (path, syscall_path, strlen(syscall_path) + 1);

  // New root, or copy of current working directory
  struct dir *current_dir = (syscall_path[0] == '/')
    ? dir_open_root ()
    : dir_open ( inode_reopen( dir_get_inode (get_current_working_directory ())));

  DPRINT("Working dir %u\n", inode_get_inumber(dir_get_inode(current_dir)));

  struct inode *node = path_to_inode_helper(current_dir, path, missing_token, last_token, aux);
  free(path);
  return node;
}

struct inode *create_file_helper (struct dir *current, char *name, void *initial_size)
{
  DPRINT("Creating file %s\n", name);
  block_sector_t sector;
  bool success = free_map_allocate (1, &sector);
  if (!success) {
    dir_close (current);
    return false;
  }
  success = inode_create (sector, (off_t)initial_size, false)
          && dir_add (current, name, sector);
  if (!success) {
    free_map_release (sector, 1);
    dir_close (current);
    return false;
  }
  DPRINT("Created file %s\n", name);
  dir_close (current);
  return (struct inode*) 1; // 1 for success;
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create (const char *path, off_t initial_size) {
  struct inode *node = path_to_inode (path, &create_file_helper, NULL, initial_size);
  return node == 1;
}

/* Path to directory */
struct dir *path_to_directory (const char *path)
{
  DPRINT ("Opening dir %s\n", path);
  struct inode *node = path_to_inode (path, NULL, NULL, NULL);
  if (node != NULL) {
    return dir_open ( inode_reopen (node));
  }
  return NULL;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *filesys_open (const char *name)
{
  struct inode *inode = path_to_inode (name, NULL, NULL, NULL);

  DPRINT("Returned inode %p\n", inode);
  if (inode == NULL)
    return NULL;

  if (inode_get_symlink (inode))
    {
      char target[15];
      inode_read_at (inode, target, NAME_MAX + 1, 0);
      struct dir *root = dir_open_root ();
      if (!dir_lookup (root, target, &inode))
        { 
          DPRINT("Failed symlink lookup %p\n", inode);
          return NULL;
        }
      dir_close (root);
    }

  DPRINT("Opening file at inode %p\n", inode);
  return file_open (inode);
}

struct inode *filesys_remove_helper (struct dir *current, char *name) {
  bool success = dir_remove (current, name);
  dir_close (current);
  return (struct inode *) success; // Non-zero => success
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove (const char *syscall_path)
{
  struct inode *node = path_to_inode (syscall_path, NULL, &filesys_remove_helper, NULL);
  return node != NULL;
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