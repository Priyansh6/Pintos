#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "filesys/file.h"
#include <hash.h>
#include <list.h>
#include "threads/synch.h"
#include "threads/thread.h"

/* Each process has its own process control block responsible
   for keeping track of any children it could wait on and storing
   the return status of these children. It also keeps track of the file
   descriptors associated with the process. */
struct process_control_block {
  tid_t tid;                      /* tid of process. */

  struct process_control_block *parent_pcb;               /* tid of parent process */

  int status;                     /* Stores the exit status of this process. */
  bool was_waited_on;             /* Processes can't be waited on more than once. */

  bool has_loaded;                /* Marks whether or not the process has successfully loaded. */
  bool has_exited;                /* Marks whether or not the process has exited. */
  
  struct semaphore wait_sema;     /* Semaphore to synchronise parent and child process. */
  struct semaphore load_sema;

  struct list children;           /* Each process_control_block contains a list of all its children. */
  struct list_elem child_elem;    /* Required to embed process_control_blocks in a struct list. */

  int next_fd;                    /* Contains the next possible file descriptor for this process */
  struct hash files;              /* Map from file descriptors to struct process_file */
};

/* This struct is used to store pointers to files associated with processes
   as well as the corresponding file descriptors. */
struct process_file {
  int fd;                         /* Stores the file descriptor for this file in a process. */
  struct file *file;              /* Stores pointer to associated file */

  struct hash_elem hash_elem;     /* Enables process_file to be in files list of process_control_block. */
};

void init_process (void);
void destroy_initial_process (void);
tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct process_control_block *process_control_block_init (tid_t tid);
int process_add_file (struct file* file);
struct file *process_get_file (int fb);
bool process_remove_file (int fd);
void process_destroy_files (void);

#endif /* userprog/process.h */
