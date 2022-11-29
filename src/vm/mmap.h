#ifndef VM_MMAP_H
#define VM_MMAP_H

typedef int mapid_t;

mapid_t mmap_create (int fd, void *uaddr);
void mmap_unmap (mapid_t mapping);
void mmap_writeback (mapid_t mapping);

#endif