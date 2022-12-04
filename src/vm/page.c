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

static void * load_page_from_filesys (struct spt_entry *entry);
static void * load_zero_page (struct spt_entry *entry);
static void * load_page_from_swap (struct spt_entry *entry);
static bool use_shareable_file (struct spt_entry *entry);
void *get_and_install_page (struct spt_entry *entry);

/* If we encounter a page fault, we first want to check our supplemental page table
   to see if we are able to locate that memory (it may not have been loaded in yet, or 
   could be on our swap disk) and load it in if possible. Otherwise, we fail and exit the
   user process. */
void handle_user_page_fault (void *fault_addr) {
  struct spt_entry *entry = get_spt_entry_by_uaddr (pg_round_down (fault_addr));

  /* If we don't know how to locate the page, fail. */
  if (entry == NULL)
    exit_failure ();
    
  void *kpage = NULL;

  switch (entry->entry_type) {
    case SWAP:
        kpage = load_page_from_swap (entry);
        break;
    case MMAP:
    case FSYS:
        if (entry->entry_type == FSYS && use_shareable_file (entry))
          return;
        kpage = load_page_from_filesys (entry);
        break;
    case ZEROPAGE:
        kpage = load_zero_page (entry);
        break;
  }

  /* We should always succeed, so PANIC the kernel if we ever don't. */
  if (kpage == NULL)
    PANIC ("Failed to load page from filesystem.\n");

  

}

/* Loads a page in from swap into user address entry->uaddr. */
static void * 
load_page_from_swap (struct spt_entry *entry) {
  // Needs fixing
  swap_in (entry->uaddr, entry->swap_slot);
  return NULL;
}

/* Loads a file into a newly allocated page.
   We can't be in an interrupt when we call this function since we try to acquire 
   fs_lock. If another process had already acquired the fs_lock then we would
   deadlock. */
static void * 
load_page_from_filesys (struct spt_entry *entry) {

  ASSERT (!intr_context ())

  bool should_release_lock = safe_acquire_fs_lock ();

  file_seek (entry->file, entry->ofs);
  
  void *kpage = get_and_install_page (entry);

  if (kpage == NULL) {
    safe_release_fs_lock (should_release_lock);
    return NULL; 
  }

  /* Load data into the page. */
  if (file_read (entry->file, kpage, entry->read_bytes) != (int) entry->read_bytes) {
    safe_release_fs_lock (should_release_lock);
    return NULL; 
  }

  /* Fills the rest of the page with zeros. */
  memset (kpage + entry->read_bytes, 0, entry->zero_bytes);

  safe_release_fs_lock (should_release_lock);


  if (!entry->writable)
    insert_shared_page (file_get_inode (entry->file), entry->ofs, kpage);

  return kpage;
}

/* Loads a page filled with zeros into physical memory. */
static void * 
load_zero_page (struct spt_entry *entry) {
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
use_shareable_file (struct spt_entry *entry)
{
    if (entry->writable)
        return false;

    struct shared_file *shared_file = get_shared_file (file_get_inode (entry->file));
    struct shared_file_page *shared_page = get_shared_page (shared_file, entry->ofs);

    /* If the page can be shared and has already been placed in memory by another thread,
      then we can just update our page table to point to it. We also add ourselves as an
      owner of the frame. */
    if (shared_file != NULL && shared_page != NULL) {
        pagedir_set_page (thread_current ()->pagedir, shared_page->frame_entry->upage, shared_page->frame_entry->kpage, false);

        struct owner *owner = (struct owner *) malloc (sizeof (struct owner));
        ASSERT (owner != NULL);
        owner->thread = thread_current ();
        list_push_back (&shared_page->frame_entry->owners, &owner->elem);

        return true;
    }

    return false;
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

    if (entry->entry_type == FSYS) {
      // printf("Installed inode %p with offset %d into thread %d's page table at user address %p.\n", file_get_inode (entry->file), entry->ofs, thread_current()->tid, entry->uaddr);
    }

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
  struct spt_entry spt_entry = {.uaddr = uaddr};
  struct hash_elem *found_elem = hash_find (&thread_current()->spt, &spt_entry.spt_hash_elem);

  return found_elem == NULL ? NULL : hash_entry (found_elem, struct spt_entry, spt_hash_elem);
}

/* Initialises the shared file table hash map. */
void
init_shared_file_table (void)
{
  hash_init (&shared_file_table, &inode_hash_func, &inode_less_func, NULL);
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
    struct shared_file *shared_file = get_shared_file (file_inode);

    /* If shared_file is NULL, then we must create an entry for the inode in the
       shared file table. */
    if (!shared_file) {
        shared_file = (struct shared_file *) malloc (sizeof (struct shared_file));
        if (shared_file == NULL)
            exit_failure ();

        shared_file->file_inode = file_inode;
        shared_file->num_sharers = 1;
        hash_init (&shared_file->shared_pages_table, &offset_hash_func, &offset_less_func, NULL);

        
        
        if (hash_insert (&shared_file_table, &shared_file->elem))
            exit_failure ();
    }
    
    /* Insert the shared_file_page into the shared_page_table.  */
    struct shared_file_page *shared_file_page = (struct shared_file_page *) malloc (sizeof (struct shared_file_page));
    if (shared_file_page == NULL)
        exit_failure ();

    shared_file_page->page_offset = page_offset;
    shared_file_page->frame_entry = get_frame_by_kpage (kpage);

    if (hash_insert (&shared_file->shared_pages_table, &shared_file_page->elem))
        exit_failure ();

    //printf("Inserted inode %p with offset %d into the shared table.\n", file_inode, page_offset);

}

/* Frees a supplemental page table entry. */
void 
free_spt_entry (struct hash_elem *elem, void *aux UNUSED) 
{
  free (hash_entry (elem, struct spt_entry, spt_hash_elem));
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