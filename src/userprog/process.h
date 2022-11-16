#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "filesys/file.h"
#include "threads/thread.h"

void destroy_blocks (void);

void init_process (void);
void process_set_status_code (int status_code);
tid_t process_execute (const char *file_name);
tid_t process_wait_on_load (tid_t);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

int process_add_file (struct file* file);
struct file *process_get_file (int fb);
bool process_remove_file (int fd);
void process_remove_all_files (void);

#endif /* userprog/process.h */
