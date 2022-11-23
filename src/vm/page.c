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

    // hex_dump (0, pagedir_get_page (t->pagedir, entry->uaddr), 4096, false);

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