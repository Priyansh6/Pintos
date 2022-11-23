#include <hash.h>
#include <stdio.h>
#include "threads/malloc.h"
#include "page.h"

void load_page_from_filesys (void) {
    /* Check if virtual page already allocated */
    // struct thread *t = thread_current ();
    // uint8_t *kpage = pagedir_get_page (t->pagedir, upage);
    
    // if (kpage == NULL){
    
    //   /* Get a new page of memory. */
    //   kpage = frame_table_get_frame (upage, PAL_USER);
    
    //   if (kpage == NULL)
    //     return false;
    
    //   /* Add the page to the process's address space. */
    //   if (!install_page (upage, kpage, writable)) 
    //   {
    //     frame_table_free_frame (kpage);
    //     return false; 
    //   }     
    
    // } else {
    
    //   /* Check if writable flag for the page should be updated */
    //   if(writable && !pagedir_is_writable(t->pagedir, upage)){
    //     pagedir_set_writable(t->pagedir, upage, writable); 
    //   }
    
    // }

    // /* Load data into the page. */
    // if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
    //   return false; 
    // }
    // memset (kpage + page_read_bytes, 0, page_zero_bytes);
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
