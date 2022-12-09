#include "hash.h"
#include <stdio.h>
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "vm/mmap.h"
#include "vm/page.h"

static int pages_required(struct file *file);

mapid_t 
mmap_create (int fd, void *uaddr) 
{
    /* Check that file mapped by fd has non-zero length
        and has already been opened by the process. */
    struct file *file = process_get_file (fd);
    if (file == NULL || file_length (file) == 0)
        return -1;

    /* Check uaddr is page aligned and is not 0. */
    if (uaddr == 0 || pg_ofs (uaddr) != 0)
        return -1;

    int n_pages = pages_required (file);

    /* Check mmapped file doesn't overlap any existing set of mapped 
        pages (including lazy loaded executables). */
    for (int i = 0; i < n_pages; i++) {
        struct spt_entry spt;
        spt.uaddr = uaddr;

        struct hash_elem *e = hash_find (&thread_current ()->spt, &spt.spt_hash_elem);
        if (e != NULL)
            return -1;
    }

    /* Check mmapped file won't overlap with user stack. */
    if (uaddr + PGSIZE * n_pages > PHYS_BASE - MAX_USER_STACK_SIZE)
        return -1;

    /* mmap the whole file by seeking to the beginning. */
    file_seek (file, 0);

    uint32_t left_to_map = file_length (file);
    for (int i = 0; i < n_pages; i++) {
        struct spt_entry *page = (struct spt_entry *) malloc (sizeof (struct spt_entry));

        /* Set the file mapping in the pcb to be the first spt entry for the file. */
        if (i == 0) {
            struct process_file *pfile = process_get_process_file (fd);
            process_file_set_mapping (pfile, page);
        }

        page->writable = true; 
        page->uaddr = uaddr + PGSIZE * i;
        page->entry_type = FSYS;
        page->file = file_reopen (file);
        page->ofs = PGSIZE * i;

        uint32_t map_bytes = left_to_map < PGSIZE ? left_to_map : PGSIZE;
        page->read_bytes = map_bytes;
        page->zero_bytes = PGSIZE - map_bytes;
        page->in_memory = false;

        ASSERT (hash_insert (&thread_current()->spt, &page->spt_hash_elem) == NULL);

        left_to_map -= map_bytes;
    }

    return fd;
}

/* Removes a file's mapping from its pcb. */
void 
mmap_unmap(mapid_t mapping)
{
    struct process_file *pfile = process_get_process_file(mapping);
    mmap_writeback(pfile);
    process_file_set_mapping(pfile, NULL);
}

/* Writes any mmaped file data that has been changed back to the original file. */
void 
mmap_writeback(struct process_file *pfile)
{

    struct spt_entry *first = process_file_get_mapping (pfile);

    if (first == NULL)
        return;

    int n_pages = pages_required (first->file);

    void *uaddr = first->uaddr;

    for (int i = 0; i < n_pages; i++) {
        struct spt_entry spt;
        spt.uaddr = uaddr;

        struct hash_elem *e = hash_find (&thread_current ()->spt, &spt.spt_hash_elem);
        struct spt_entry *page = hash_entry (e, struct spt_entry, spt_hash_elem);

        /* If page has been written to, write its data back to the original file struct. */
        if (pagedir_is_dirty(thread_current()->pagedir, page->uaddr))
        {
            bool should_release_lock = reentrant_lock_acquire (&fs_lock);
            file_write_at (page->file, page->uaddr, PGSIZE, page->ofs);
            reentrant_lock_release (&fs_lock, should_release_lock);
        }

        uaddr += PGSIZE;

        /* Remove spt_entry from process's spt. */
        hash_delete (&thread_current ()->spt, &page->spt_hash_elem);
    }

    /* File is no longer mapped. */
    process_file_set_mapping(pfile, NULL);
}

/* Calculate number of pages required to mmap the file, rounding up. */
static int 
pages_required (struct file *file)
{
    return (file_length (file) + (PGSIZE - 1)) / PGSIZE;   
}