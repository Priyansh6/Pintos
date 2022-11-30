#include <hash.h>
#include <stdio.h>
#include <string.h>
#include "devices/swap.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"

bool load_page_from_filesys (struct spt_entry *entry);
bool load_zero_page (struct spt_entry *entry);
void *get_and_install_page (struct spt_entry *entry);
bool load_page_from_swap (struct spt_entry *entry);

/* If we encounter a page fault, we first want to check our supplemental page table
   to see if we are able to locate that memory (it may not have been loaded in yet, or 
   could be on our swap disk) and load it in if possible. Otherwise, we fail and exit the
   user process. */
void handle_user_page_fault (void *fault_addr) {
  struct hash spt = thread_current ()->spt;
   
  struct spt_entry spt_entry;
  spt_entry.uaddr = pg_round_down (fault_addr);

  struct hash_elem *found_elem = hash_find (&spt, &spt_entry.spt_hash_elem);
  struct spt_entry *entry = found_elem == NULL ? NULL : hash_entry (found_elem, struct spt_entry, spt_hash_elem);

  /* If we don't know how to locate the page, fail. */
  if (entry == NULL)
    exit_failure ();
    
  bool success = false;

  switch (entry->entry_type) {
    case SWAP:
        success = load_page_from_swap (entry);
        break;
    case MMAP:
    case FSYS:
        success = load_page_from_filesys (entry);
        break;
    case ZEROPAGE:
        success = load_zero_page (entry);
        break;
  }

  /* We should always succeed, so PANIC the kernel if we ever don't. */
  if (!success) {
    PANIC ("Failed to load page from filesystem.\n");
  }

  /* Remove the entry from the supplemental page table because it is now stored in memory. */
//  if (entry->entry_type != MMAP)
//    hash_delete (&spt, found_elem);

}

/* Loads a page in from swap into user address entry->uaddr. */
bool 
load_page_from_swap (struct spt_entry *entry) {
  swap_in (entry->uaddr, entry->swap_slot);
  return true;
}

/* Loads a file into a newly allocated page.
   OM WAS HERE
   We can't be in an interrupt when we call this function since we try to acquire 
   fs_lock. If another process had already acquired the fs_lock then we would
   deadlock. */
bool 
load_page_from_filesys (struct spt_entry *entry) {

  ASSERT (!intr_context ())

  bool should_release_lock = safe_acquire_fs_lock ();

  file_seek (entry->file, entry->ofs);
  
  void *kpage = get_and_install_page (entry);

  if (kpage == NULL) {
    safe_release_fs_lock (should_release_lock);
    return false; 
  }

  /* Load data into the page. */
  if (file_read (entry->file, kpage, entry->read_bytes) != (int) entry->read_bytes) {
    safe_release_fs_lock (should_release_lock);
    return false; 
  }

  /* Fills the rest of the page with zeros. */
  memset (kpage + entry->read_bytes, 0, entry->zero_bytes);

  safe_release_fs_lock (should_release_lock);
  return true;
}

/* Loads a page filled with zeros into physical memory. */
bool 
load_zero_page (struct spt_entry *entry) {
  void *kpage = get_and_install_page (entry);

  if (kpage == NULL)
    return false;

  memset (kpage, 0, PGSIZE);

  return true;
}

/* Makes a call to frame_table_get_frame and registers the returned
   page in the thread's page directory. */
void *
get_and_install_page (struct spt_entry *entry) {

  /* Check if virtual page already allocated */
  struct thread *t = thread_current ();
  uint8_t *kpage = pagedir_get_page (t->pagedir, entry->uaddr);
  
  if (kpage == NULL){
  
    /* Get a new page of memory. */
    kpage = frame_table_get_frame (entry->uaddr, PAL_USER);
  
    if (kpage == NULL)
      return NULL;
  
    /* Add the page to the process's address space. */
    if (pagedir_get_page (t->pagedir, entry->uaddr) != NULL
        || !pagedir_set_page (t->pagedir, entry->uaddr, kpage, entry->writable))
    {
      frame_table_free_frame (kpage);
      return NULL; 
    }     
  } else {
    /* Check if writable flag for the page should be updated OM WAS HERE */
    if(entry->writable && !pagedir_is_writable(t->pagedir, entry->uaddr)){
      pagedir_set_writable(t->pagedir, entry->uaddr, entry->writable); 
    }
  }

  return kpage;
}

void 
free_spt_entry (struct hash_elem *elem, void *aux UNUSED) {
  free (hash_entry (elem, struct spt_entry, spt_hash_elem));
}

unsigned 
spt_hash_func (const struct hash_elem *elem, void *aux UNUSED) {
  struct spt_entry *e = hash_entry (elem, struct spt_entry, spt_hash_elem);
  return hash_int ((int) e->uaddr);
}

bool 
spt_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
  struct spt_entry *spt_a = hash_entry (a, struct spt_entry, spt_hash_elem);
  struct spt_entry *spt_b = hash_entry (b, struct spt_entry, spt_hash_elem);

  return spt_a->uaddr < spt_b->uaddr;
}