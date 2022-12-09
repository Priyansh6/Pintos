#ifndef VM_MMAP_H
#define VM_MMAP_H

#include "userprog/process.h"

typedef int mapid_t;

mapid_t mmap_create (int fd, void *uaddr);
void mmap_unmap (mapid_t mapping);
void mmap_writeback (struct process_file *pfile);

#endif