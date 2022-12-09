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
#include "vm/share.h"

static void *load_page_from_filesys (struct spt_entry *entry);
static void *load_zero_page (struct spt_entry *entry);
static void *load_page_from_swap (struct spt_entry *entry);
static bool load_shared_page (struct spt_entry *entry);
void *get_and_install_page (struct spt_entry *entry);
static void hash_free_spt_entry (struct hash_elem *elem, void *aux UNUSED);

/* If we encounter a page fault, we first want to check our supplemental page table
   to see if we are able to locate that memory (it may not have been loaded in yet, or 
   could be on our swap disk) and load it in if possible. Otherwise, we fail and exit the
   user process. */
void 
handle_user_page_fault (void *fault_addr) 
{
  struct spt_entry *entry = get_spt_entry_by_uaddr (pg_round_down (fault_addr));

  /* If we don't know how to locate the page, fail. */
  if (entry == NULL)
    exit_failure ();
    
  void *kpage = NULL;

  switch (entry->entry_type) {
    case SWAP:
        kpage = load_page_from_swap (entry);
        break;
    case FSYS:
        if (load_shared_page (entry)) {
          entry->in_memory = true;
          return;
        }
        kpage = load_page_from_filesys (entry);
        break;
    case ZEROPAGE:
        kpage = load_zero_page (entry);
        break;
  }

  /* We should always succeed, so PANIC the kernel if we ever don't. */
  if (kpage == NULL)
    PANIC ("Failed to load page from filesystem.\n");

  entry->in_memory = true;
}

/* Loads a page in from swap into user address entry->uaddr. */
static void * 
load_page_from_swap (struct spt_entry *entry) 
{
  void *kaddr = get_and_install_page (entry);
  swap_in (kaddr, entry->swap_slot);
  return kaddr;
}

/* Loads a file into a newly allocated page.
   We can't be in an interrupt when we call this function since we try to acquire 
   fs_lock. If another process had already acquired the fs_lock then we would
   deadlock. */
static void * 
load_page_from_filesys (struct spt_entry *entry) 
{
  ASSERT (!intr_context ())

  bool should_release_lock = reentrant_lock_acquire (&fs_lock);

  file_seek (entry->file, entry->ofs);
  
  void *kpage = get_and_install_page (entry);

  if (kpage == NULL) {
    reentrant_lock_release (&fs_lock, should_release_lock);
    return NULL; 
  }

  /* Load data into the page. */
  if (file_read (entry->file, kpage, entry->read_bytes) != (int) entry->read_bytes) {
    reentrant_lock_release (&fs_lock, should_release_lock);
    return NULL; 
  }

  /* Fills the rest of the page with zeros. */
  memset (kpage + entry->read_bytes, 0, entry->zero_bytes);

  reentrant_lock_release (&fs_lock, should_release_lock);

  if (!entry->writable)
    insert_shared_page (file_get_inode (entry->file), entry->ofs, kpage);

  return kpage;
}

/* Loads a page filled with zeros into physical memory. */
static void * 
load_zero_page (struct spt_entry *entry) 
{
  void *kpage = get_and_install_page (entry);

  if (kpage == NULL)
    return NULL;

  memset (kpage, 0, PGSIZE);

  return kpage;
}

/* Queries the shared_file table to determine whether or not the page
   given by the supplemental page table entry has already been placed in
   memory by another process, and if the correct process can share it. 
   
   If the page is already in memory and we can share it, then we do so and 
   return true. Otherwise we return false. */
static bool
load_shared_page (struct spt_entry *entry)
{
    if (entry->writable)
        return false;

    lock_acquire (&ft_lock);
    lock_acquire (&shared_table_lock);

    struct shared_file *shared_file = get_shared_file (file_get_inode (entry->file));
    struct shared_file_page *shared_page = get_shared_page (shared_file, entry->ofs);

    /* If the page can be shared and has already been placed in memory by another thread,
      then we can just update our page table to point to it. We also add ourselves as an
      owner of the frame. */
    if (shared_file != NULL && shared_page != NULL && thread_current ()->pagedir != NULL) {

        
        pagedir_set_page (thread_current ()->pagedir, shared_page->frame_entry->upage, shared_page->frame_entry->kpage, false);

        struct owner *owner = (struct owner *) malloc (sizeof (struct owner));
        ASSERT (owner != NULL);
        owner->thread = thread_current ();
        list_push_back (&shared_page->frame_entry->owners, &owner->elem);
        
        lock_release (&shared_table_lock);
        lock_release (&ft_lock);
        return true;
    }

    lock_release (&shared_table_lock);
    lock_release (&ft_lock);

    return false;
}

/* Makes a call to frame_table_get_frame and registers the returned
   page in the thread's page directory. */
void *
get_and_install_page (struct spt_entry *entry) 
{

  /* Check if virtual page already allocated */
  struct thread *t = thread_current ();
  uint8_t *kpage = pagedir_get_page (t->pagedir, entry->uaddr);
  
  if (kpage == NULL){
  
    /* Get a new page of memory. */
    kpage = frame_table_get_frame (entry->uaddr, PAL_USER);

    if (kpage == NULL) {
      return NULL;
    }

    struct frame_table_entry *fte = get_frame_by_kpage (kpage);
    fte->pinned = true;

    /* Add the page to the process's address space. */
    if (pagedir_get_page (t->pagedir, entry->uaddr) != NULL
        || !pagedir_set_page (t->pagedir, entry->uaddr, kpage, entry->writable))
    {
      fte->pinned = false;
      frame_table_free_frame (kpage);
      return NULL; 
    }

    fte->pinned = false;

  } else {
    /* Check if writable flag for the page should be updated */
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
stack_grow (void *fault_addr) 
{
  struct thread *t = thread_current ();
  void *stack_bottom = t->stack_bottom;
  while (stack_bottom > pg_round_down (fault_addr)) {

    void *upage = stack_bottom - PGSIZE;
    void *kpage = frame_table_get_frame (upage, PAL_USER | PAL_ZERO);

    if (kpage != NULL) {
        if (pagedir_get_page (t->pagedir, upage) == NULL && pagedir_set_page (t->pagedir, upage, kpage, true)) {
          stack_bottom -= PGSIZE;
        } else {
          frame_table_free_frame (kpage);
          exit_failure ();
        }
    } else {
        exit_failure ();
    }
  }
  t->stack_bottom = stack_bottom;
}

/* Returns the supplemental page table entry given by uaddr. */
struct spt_entry *
get_spt_entry_by_uaddr (void *uaddr)
{
  struct spt_entry spt_entry = {.uaddr = uaddr};
  struct hash_elem *found_elem = hash_find (&thread_current()->spt, &spt_entry.spt_hash_elem);

  return found_elem == NULL ? NULL : hash_entry (found_elem, struct spt_entry, spt_hash_elem);
}

/* Destroys the current thread's spt. */
void 
destroy_spt (void) 
{
  hash_clear (&thread_current ()->spt, &hash_free_spt_entry);
}

/* Frees a given spt_entry as well as the associated page by clearing it
   from the process's page directory and removing it from the frame table.
   Assumes the spt_entry is current thread's. */
void
free_spt_entry (struct spt_entry *entry) 
{
  if (entry->entry_type == SWAP && !entry->in_memory)
    swap_clear (entry->swap_slot);
  free (entry);
}

/* Frees the given spt hash table entry. Assumes the spt_entry is current thread's */
static void 
hash_free_spt_entry (struct hash_elem *elem, void *aux UNUSED) 
{
  struct spt_entry *entry = hash_entry (elem, struct spt_entry, spt_hash_elem);
  free_spt_entry (entry);
}

/* Hashing function for a supplemental page table entry. */
unsigned 
spt_hash_func (const struct hash_elem *elem, void *aux UNUSED) 
{
  struct spt_entry *e = hash_entry (elem, struct spt_entry, spt_hash_elem);
  return hash_int ((int) e->uaddr);
}

/* Comparison function used to compare two elements of the supplemental page table. */
bool 
spt_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) 
{
  struct spt_entry *spt_a = hash_entry (a, struct spt_entry, spt_hash_elem);
  struct spt_entry *spt_b = hash_entry (b, struct spt_entry, spt_hash_elem);

  return spt_a->uaddr < spt_b->uaddr;
}