#ifndef VM_MMAP_H
#define VM_MMAP_H

typedef int mapid_t;

mapid_t mmap_create (int fd, void *uaddr);

#endif