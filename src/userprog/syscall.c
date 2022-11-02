#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#define N_TASK_ONE_SYSCALLS 13

static void syscall_handler (struct intr_frame *);
static bool is_valid_user_ptr (void *uaddr);
static void syscall_handlers_init (void);

static void exit (void);
static void write (void);

static struct lock fs_lock;

static void (*syscall_ptrs[N_TASK_ONE_SYSCALLS]) (void);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&fs_lock);
  syscall_handlers_init ();
}

static void 
syscall_handlers_init (void)
{
  syscall_ptrs[SYS_HALT] = NULL;
  syscall_ptrs[SYS_EXIT] = &exit;
  syscall_ptrs[SYS_EXEC] = NULL;
  syscall_ptrs[SYS_WAIT] = NULL;
  syscall_ptrs[SYS_CREATE] = NULL;
  syscall_ptrs[SYS_REMOVE] = NULL;
  syscall_ptrs[SYS_OPEN] = NULL;
  syscall_ptrs[SYS_FILESIZE] = NULL;
  syscall_ptrs[SYS_READ] = NULL;
  syscall_ptrs[SYS_WRITE] = &write;
  syscall_ptrs[SYS_SEEK] = NULL;
  syscall_ptrs[SYS_TELL] = NULL;
  syscall_ptrs[SYS_CLOSE] = NULL;
}

static void
syscall_handler (struct intr_frame *f) 
{
  /* Do we need validation here to prevent syscalls outside the range of the syscall array? */
  void (*fp) (void) = syscall_ptrs[(int) f->esp];
  if (fp)
  {
    fp ();
  } else {
    printf ("Unimplemented syscall!\n");
    thread_exit ();
  }
}

static bool 
is_valid_user_ptr (void *uaddr)
{
  return is_user_vaddr (uaddr) && pagedir_get_page (thread_current ()->pagedir, uaddr);
}

static void 
exit (void) 
{

}

static void 
write (void)
{

}
