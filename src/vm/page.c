#include <hash.h>
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"

void handle_user_page_fault (void *fault_addr) {
  struct hash spt = thread_current ()->spt;
   
  struct spt_entry spt_entry;
  spt_entry.uaddr = pg_round_down (fault_addr);

  struct hash_elem *found_elem = hash_find (&spt, &spt_entry.spt_hash_elem);
  struct spt_entry *entry = found_elem == NULL ? NULL : hash_entry (found_elem, struct spt_entry, spt_hash_elem);

  if (entry == NULL)
    exit_failure ();
    
  switch (entry->entry_type) {
    case SWAP:
        break;
    case FSYS:
        if (!load_page_from_filesys (entry)) {
          printf("Failed to load page from filesystem.\n");
          exit_failure ();
        }
        break;
    case ZEROPAGE:
        break;
  }
}

bool load_page_from_filesys (struct spt_entry *entry) {
    /* We can't be in an interrupt when we call this function since we try to acquire 
       fs_lock. If another process had already acquired the fs_lock then we would
       deadlock. */
    ASSERT (!intr_context ())

    lock_acquire (&fs_lock);

    file_seek (entry->file, entry->ofs);

    /* Check if virtual page already allocated */
    struct thread *t = thread_current ();
    uint8_t *kpage = pagedir_get_page (t->pagedir, entry->uaddr);
    
    if (kpage == NULL){
    
      /* Get a new page of memory. */
      kpage = frame_table_get_frame (entry->uaddr, PAL_USER);
    
      if (kpage == NULL)
        return false;
    
      /* Add the page to the process's address space. */
      if (pagedir_get_page (t->pagedir, entry->uaddr) != NULL
          || !pagedir_set_page (t->pagedir, entry->uaddr, kpage, entry->writable))
      {
        frame_table_free_frame (kpage);
        lock_release (&fs_lock);
        return false; 
      }     
    } else {
      /* Check if writable flag for the page should be updated */
      if(entry->writable && !pagedir_is_writable(t->pagedir, entry->uaddr)){
        pagedir_set_writable(t->pagedir, entry->uaddr, entry->writable); 
      }
    }

    /* Load data into the page. */
    if (file_read (entry->file, kpage, entry->read_bytes) != (int) entry->read_bytes) {
      lock_release (&fs_lock);
      return false; 
    }

    memset (kpage + entry->read_bytes, 0, entry->zero_bytes);
 
    lock_release (&fs_lock);
    return true;
}

void free_spt_entry (struct hash_elem *elem, void *aux UNUSED) {
    free (hash_entry (elem, struct spt_entry, spt_hash_elem));
}

unsigned spt_hash_func (const struct hash_elem *elem, void *aux UNUSED) {
    struct spt_entry *e = hash_entry (elem, struct spt_entry, spt_hash_elem);
    return hash_int ((int) e->uaddr);
}

bool spt_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    struct spt_entry *spt_a = hash_entry (a, struct spt_entry, spt_hash_elem);
    struct spt_entry *spt_b = hash_entry (b, struct spt_entry, spt_hash_elem);

    return spt_a->uaddr < spt_b->uaddr;
}