#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

/* There are 13 syscalls in task two. */
#define N_SYSCALLS 13
#define MAX_CONSOLE_BUFFER_OUTPUT 250

static void syscall_handler (struct intr_frame *);
static bool is_valid_user_ptr (void *uaddr);
static void syscall_handlers_init (void);

static void exit_handler (struct intr_frame *f);
static void write_handler (struct intr_frame *f);

static struct lock fs_lock;

static void (*syscall_ptrs[N_SYSCALLS]) (struct intr_frame *f);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&fs_lock);
  syscall_handlers_init ();
  printf("syscall_init\n");
}

static void 
syscall_handlers_init (void)
{
  syscall_ptrs[SYS_HALT] = NULL;
  syscall_ptrs[SYS_EXIT] = &exit_handler;
  syscall_ptrs[SYS_EXEC] = NULL;
  syscall_ptrs[SYS_WAIT] = NULL;
  syscall_ptrs[SYS_CREATE] = NULL;
  syscall_ptrs[SYS_REMOVE] = NULL;
  syscall_ptrs[SYS_OPEN] = NULL;
  syscall_ptrs[SYS_FILESIZE] = NULL;
  syscall_ptrs[SYS_READ] = NULL;
  syscall_ptrs[SYS_WRITE] = &write_handler;
  syscall_ptrs[SYS_SEEK] = NULL;
  syscall_ptrs[SYS_TELL] = NULL;
  syscall_ptrs[SYS_CLOSE] = NULL;
}

static void
syscall_handler (struct intr_frame *f) 
{
  /* Do we need validation here to prevent syscalls outside the range of the syscall array? */
  int syscall_n = *((int *) f->esp);
  if (is_valid_user_ptr (syscall_n)) {
    void (*fp) (struct intr_frame *) = syscall_ptrs[*((int *) f->esp)];
    printf("syscall_handler\n");
    if (fp) {
      printf("function pointer\n");
      fp (f);
    } else {
      printf ("Unimplemented syscall!\n");
      thread_exit ();
    }
  }
}

static bool 
is_valid_user_ptr (void *uaddr)
{
  return uaddr && is_user_vaddr (uaddr) && pagedir_get_page (thread_current ()->pagedir, uaddr);
}

static void 
exit_handler (struct intr_frame *f UNUSED) 
{
  process_exit ();
}

static void 
write_handler (struct intr_frame *f)
{
  
  int fd = *(((int *) f->esp) + 1);
  char *buffer =  *((char **) f->esp + 2);
  int size = *((int *) f->esp + 3);

  if (fd == 1) {
    printf("cameron smells good.\n");
    putbuf (buffer, size);
  }

}
