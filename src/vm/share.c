#include <hash.h>
#include <stdio.h>
#include <string.h>
#include "threads/thread.h"
#include "threads/malloc.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/share.h"

static struct hash shared_file_table;

/* Initialises the shared file table hash map. */
void
init_shared_file_table (void)
{
  hash_init (&shared_file_table, &inode_hash_func, &inode_less_func, NULL);
  lock_init (&shared_table_lock);
}

/* Returns the shared_file entry corresponding to a given
   inode. If none exists, returns NULL. */
struct shared_file *
get_shared_file (struct inode *file_inode)
{
  struct shared_file file_query = {.file_inode = file_inode};
  struct hash_elem *found_file_elem = hash_find (&shared_file_table, &file_query.elem);

  return found_file_elem == NULL ? NULL : hash_entry (found_file_elem, struct shared_file, elem);
}

/* Returns the shared_file_page entry corresponding to a
   given offset in a given shared_file entry. If none exists,
   returns NULL. */
struct shared_file_page *
get_shared_page (struct shared_file *file, uint32_t page_offset)
{
  if (file == NULL)
    return NULL;

  struct shared_file_page page_query = {.page_offset = page_offset};
  struct hash_elem *found_page_elem = hash_find (&file->shared_pages_table, &page_query.elem);

  return found_page_elem == NULL ? NULL : hash_entry (found_page_elem, struct shared_file_page, elem);
}

/* Inserts a shared_file_page into the shared_pages_table corresponding to
   the given inode. If no shared_page_table exists, then we create one. */
void
insert_shared_page (struct inode *file_inode, uint32_t page_offset, void *kpage)
{
  lock_acquire (&shared_table_lock);
  struct shared_file *shared_file = get_shared_file (file_inode);

  /* If shared_file is NULL, then we must create an entry for the inode in the
    shared file table. */
  if (!shared_file) {
    shared_file = (struct shared_file *) malloc (sizeof (struct shared_file));
    if (shared_file == NULL) {
      lock_release (&shared_table_lock);
      exit_failure ();
    }

    shared_file->file_inode = file_inode;
    hash_init (&shared_file->shared_pages_table, &offset_hash_func, &offset_less_func, NULL);

    if (hash_insert (&shared_file_table, &shared_file->elem)) {
      lock_release (&shared_table_lock);
      exit_failure ();
    }
  }

  /* Insert the shared_file_page into the shared_page_table.  */
  struct shared_file_page *shared_file_page = (struct shared_file_page *) malloc (sizeof (struct shared_file_page));
  if (shared_file_page == NULL) {
    lock_release (&shared_table_lock);
    exit_failure ();
  }

  shared_file_page->page_offset = page_offset;
  shared_file_page->frame_entry = get_frame_by_kpage (kpage);

  if (hash_insert (&shared_file->shared_pages_table, &shared_file_page->elem)) {
    lock_release (&shared_table_lock);
    exit_failure ();
  }

  lock_release (&shared_table_lock);
}

/* Hashing function for a shared_file table entry.*/
unsigned
inode_hash_func (const struct hash_elem *elem, void *aux UNUSED)
{
  struct shared_file *e = hash_entry (elem, struct shared_file, elem);
  return hash_int ((int) e->file_inode);
}

/* Comparison function used to compare two elements of a shared_file table. */
bool
inode_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  struct shared_file *file_a = hash_entry (a, struct shared_file, elem);
  struct shared_file *file_b = hash_entry (b, struct shared_file, elem);

  return ((int) file_a->file_inode) < ((int) file_b->file_inode);
}

/* Hashing function for a shared_file_page table entry. */
unsigned
offset_hash_func (const struct hash_elem *elem, void *aux UNUSED)
{
  struct shared_file_page *e = hash_entry (elem, struct shared_file_page, elem);
  return hash_int ((int) e->page_offset);
}

/* Comparison function used to compare two elemnts of a shared_file_page table. */
bool
offset_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  struct shared_file_page *page_a = hash_entry (a, struct shared_file_page, elem);
  struct shared_file_page *page_b = hash_entry (b, struct shared_file_page, elem);

  return ((int) page_a->page_offset) < ((int) page_b->page_offset);
}

/* Auxilliary function for freeing shared table. */
void
free_shared_file_elem (struct hash_elem *e, void *aux UNUSED)
{
  struct shared_file *file = hash_entry(e, struct shared_file, elem);
  free(file);
}

/* Free shared files table. */
void
free_shared_table (void)
{
  hash_destroy(&shared_file_table, &free_shared_file_elem);
}


/* Frees a shared page entry from the share table if no other processes
   are owners of the corresponding frame and returns false. Also destroys the shared
   pages table (of a particular file) if there are no pages of that file being shared.

   Otherwise, we remove ourselves as an owner of the frame and return true. */
bool
free_shared_page (struct frame_table_entry *fte)
{
  struct spt_entry *spage_entry = get_spt_entry_by_uaddr (fte->upage);

  if (spage_entry != NULL && spage_entry->entry_type == FSYS && !spage_entry->writable) {

    lock_acquire (&shared_table_lock);
    struct shared_file *file = get_shared_file (file_get_inode (spage_entry->file));
    struct shared_file_page *page = get_shared_page (file, spage_entry->ofs);

    if (file != NULL && page != NULL) {

      if (list_size (&fte->owners) > 1) {
        /* Other processes are using this frame, so we cannot free it. */
        struct owner *owner = find_owner (&fte->owners);
        list_remove (&owner->elem);
        free (owner);
        lock_release (&shared_table_lock);
        return true;
      }

      /* If we reach this point, no other processes are using this frame so we
          can safely free it. We also need to remove the shared_file_page entry. */
      hash_delete (&file->shared_pages_table, &page->elem);
      free (page);

      if (hash_empty (&file->shared_pages_table)) {
        hash_destroy (&file->shared_pages_table, NULL);
        hash_delete (&shared_file_table, &file->elem);
        free (file);
      }
    }
    lock_release (&shared_table_lock);
  }
  return false;
}

