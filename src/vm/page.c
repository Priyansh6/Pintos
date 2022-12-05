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
static void hash_free_spt_entry (struct hash_elem *elem, void *aux UNUSED);

/* If we encounter a page fault, we first want to check our supplemental page table
   to see if we are able to locate that memory (it may not have been loaded in yet, or 
   could be on our swap disk) and load it in if possible. Otherwise, we fail and exit the
   user process. */
void handle_user_page_fault (void *fault_addr) {
  struct spt_entry *entry = get_spt_entry_by_uaddr (pg_round_down (fault_addr));

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
  if (!success)
    PANIC ("Failed to load page from filesystem.\n");

}

/* Loads a page in from swap into user address entry->uaddr. */
bool 
load_page_from_swap (struct spt_entry *entry) {
  swap_in (entry->uaddr, entry->swap_slot);
  return true;
}

/* Loads a file into a newly allocated page.
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

/* Grows the current process user stack by one page. Called only from a page fault when
   we determine that accessing the fault_addr is likely to be a stack access, in which case,
   up to STACK_LIMIT, we want to grow the stack. */
void
stack_grow (void *fault_addr) {
  void *kpage = frame_table_get_frame (((uint8_t *) PHYS_BASE) - PGSIZE, PAL_USER | PAL_ZERO);
  void *upage = pg_round_down (fault_addr);
  struct thread *t = thread_current ();

  if (kpage != NULL) {
      if (pagedir_get_page (t->pagedir, upage) == NULL && pagedir_set_page (t->pagedir, upage, kpage, true))
        return;
      else
        exit_failure ();
  } else {
      exit_failure ();
  }
}

/* Returns the supplemental page table entry given by uaddr. */
struct spt_entry *
get_spt_entry_by_uaddr (void *uaddr)
{
  struct spt_entry spt_entry;
  spt_entry.uaddr = uaddr;
  struct hash_elem *found_elem = hash_find (&thread_current()->spt, &spt_entry.spt_hash_elem);

  return found_elem == NULL ? NULL : hash_entry (found_elem, struct spt_entry, spt_hash_elem);
}

/* Destroys the current thread's spt. */
void destroy_spt (void) {
  struct thread *cur = thread_current ();
  hash_destroy (&cur->spt, hash_free_spt_entry);
}

/* Frees a given spt_entry as well as the associated page by clearing it
   from the process's page directory and removing it from the frame table.
   Assumes the spt_entry is current thread's. */
void
free_spt_entry (struct spt_entry *entry) {
  struct thread *cur = thread_current ();
  uint32_t *pd = cur->pagedir;

  void *kpage = pagedir_get_page(pd, entry->uaddr);
  if (kpage) {
    pagedir_clear_page (pd, entry->uaddr);
    frame_table_free_frame (kpage);
  } else if (entry->entry_type == SWAP && load_page_from_swap (entry)) {
    frame_table_free_frame (kpage);
  }

  free (entry);
}

/* Frees the given spt hash table entry. Assumes the spt_entry is current thread's */
static void 
hash_free_spt_entry (struct hash_elem *elem, void *aux UNUSED) {
  struct spt_entry *entry = hash_entry (elem, struct spt_entry, spt_hash_elem);
  free_spt_entry (entry);
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