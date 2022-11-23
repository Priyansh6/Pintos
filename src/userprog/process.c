#include "userprog/process.h"
#include <debug.h>
#include <hash.h>
#include <inttypes.h>
#include <list.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "threads/malloc.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "vm/frame.h"

#define MAX_NUM_OF_CMD_LINE_ARGS 256
#define PUSH_STACK(type, pointer, value) pointer = ((type*) pointer) - 1; (*((type*) pointer) = (type) (value))
#define MAX_BYTES_PER_PAGE 4096

#define INITIAL_USER_PROCESS_TID 3

struct process_file;

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

static void process_file_hash_close (struct hash_elem *e, void *aux UNUSED);
static void process_file_close (struct process_control_block *pcb, struct process_file *pfile);

static bool fd_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
static unsigned process_file_hash (const struct hash_elem *elem, void *aux UNUSED);

static bool is_stack_overflow (uint32_t *bytes_written, uint32_t bytes_to_write);

/* Each process has its own process control block responsible
   for keeping track of any children it could wait on and storing
   the return status of these children. It also keeps track of the file
   descriptors associated with the process. */
struct process_control_block {
  tid_t tid;                                  /* tid of process. */
  struct process_control_block *parent_pcb;   /* Pointer to PCB of parent process */

  int status;                                 /* Stores the exit status of this process. */
  bool was_waited_on;                         /* Processes can't be waited on more than once. */

  bool has_loaded;                            /* Marks whether or not the process has successfully loaded. */
  bool has_exited;                            /* Marks whether or not the process has exited. */
  
  struct semaphore wait_sema;                 /* Semaphore to synchronise parent and child process. */
  struct semaphore load_sema;

  struct list children;                       /* Each process_control_block contains a list of all its children. */
  struct list_elem child_elem;                /* Required to embed process_control_blocks in a struct list. */

  int next_fd;                                /* Contains the next possible file descriptor for this process */
  struct hash files;                          /* Map from file descriptors to struct process_file */
};

/* This struct is used to store pointers to files associated with processes
   as well as the corresponding file descriptors. */
struct process_file {
  int fd;                         /* Stores the file descriptor for this file in a process. */
  struct file *file;              /* Stores pointer to associated file */

  struct hash_elem hash_elem;     /* Enables process_file to be in files list of process_control_block. */
};

/* Returns the current process's process control block. */
struct process_control_block *
process_get_pcb (void)
{
  return thread_current ()->pcb;
}

/* Allocates kernel-space memory and initialises a process control block with the provided tid. */
struct process_control_block *
process_control_block_init (tid_t tid)
{
  /* This is freed either by a process or it's parent's process in process_exit. As
     a special case, the main thread will free the PCB for the first user process created. */
  struct process_control_block *block = (struct process_control_block *) malloc (sizeof (struct process_control_block));
  if (block == NULL)
    return NULL;

  block->tid = tid;

  /* Assume that if a process does not update this in a call to exit() 
     then the process has not executed correctly - so we set the initial
     status to -1. */
  block->status = -1;

  block->has_exited = false;
  block->was_waited_on = false;

  block->next_fd = 2;

  sema_init (&block->wait_sema, 0);
  sema_init (&block->load_sema, 0);
  list_init (&block->children);
  hash_init (&block->files, process_file_hash, fd_less, NULL);

  /* If we have a parent, then we add our block to the parent's list of children. */
  struct process_control_block *parent_block = process_get_pcb ();
  if (parent_block != NULL)
    list_push_back (&parent_block->children, &block->child_elem);

  return block;
}

/* Sets the parent of the pcb child to parent. */
void
pcb_set_parent (struct process_control_block *child, struct process_control_block *parent) {
  child->parent_pcb = parent;
}

struct process_control_block *
pcb_get_child_by_tid (tid_t child_tid) {
  struct process_control_block *parent = process_get_pcb ();
  struct process_control_block *child;

  struct list_elem *e;
  for (e = list_begin (&parent->children); e != list_end (&parent->children); e = list_next (e)) {
    child = list_entry (e, struct process_control_block, child_elem);

    if (child->tid == child_tid)
      return child;
  }

  return NULL;
}

/* Closes and frees file pointed to by process_file pfile */
static void
process_file_close (struct process_control_block *pcb, struct process_file *pfile)
{
  hash_delete (&pcb->files, &pfile->hash_elem);
  lock_acquire (&fs_lock);
  file_close (pfile->file);
  lock_release (&fs_lock);
  free (pfile);
}

/* Executes process_file_close on process_file associated with hash_elem e */
static void
process_file_hash_close (struct hash_elem *e, void *aux UNUSED)
{
  struct process_file *pfile = hash_entry (e, struct process_file, hash_elem);
  file_close (pfile->file);
  free (pfile);
}

/* Calculate how many bytes would be pushed to the stack for the current
   argument and terminate the process if this would cause a stack overflow. */
static bool
is_stack_overflow (uint32_t *bytes_written, uint32_t bytes_to_write)
{
  *bytes_written += bytes_to_write;
  return *bytes_written > MAX_BYTES_PER_PAGE;
}

/* Sets the current process's status code to the provided one. */
void
process_set_status_code (int status_code)
{
  struct process_control_block *pcb = process_get_pcb ();
  pcb->status = status_code;
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *args;
  tid_t tid;

  /* Allocate a page of virtual memory for the arguments (so the total size of arguments are limited to 4KB). 
     This page will store the tokenised arguments: "echo x" will be stored as "echo\0x\0\0\0\0 ..." meaning that
     reading args as a string returns the name of the user program, but since we have allocated an entire page
     to args, we can safely inspect up to 4095 memory addresses after the one given by the args pointer. 
     
     We take advantage of this in the stack setup (see start_process) by iterating over these 4096 addresses to get
     each argument. We can break once we reach two sentinel characters in a row (just one marks the end of each argument
     string, whereas two represents that there is nothing else stored in the rest of the page). */
  args = palloc_get_page (0);
  if (args == NULL)
    return TID_ERROR;

  /* Initialise the page to sentinel characters. */
  memset (args, '\0', MAX_BYTES_PER_PAGE);

  /* Make a copy of FILE_NAME, because we mustn't modify file_name. */
  char *fn_copy = (char *) malloc ((1 + strlen (file_name)) * sizeof (char));
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);
  
  char *token, *save_ptr;
  int characters_written = 0;

  /* Populate args page with each word in the command being run (file_name). Effectively, this removes all unnecessary spaces
     and then replaces the remaining spaces with sentinel characters. */
  for (token = strtok_r (fn_copy, " ", &save_ptr); token != NULL; token = strtok_r (NULL, " ", &save_ptr)) {
    strlcpy ((args + characters_written), token, sizeof (char) * (strlen (token) + 1));
    characters_written += sizeof (char) * (strlen (token) + 1);
  }

  free(fn_copy);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (args, PRI_DEFAULT, start_process, args);

  if (tid == TID_ERROR)
    palloc_free_page (args);

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *args = file_name_;

  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  success = load (args, &if_.eip, &if_.esp);

  /* We can let any parent process that has made a call to exec know that 
     they can now return, and we tell them if we managed to successfully load
     their child process or not. */
  struct process_control_block *pcb = process_get_pcb ();
  pcb->has_loaded = success;
  sema_up (&pcb->load_sema);
  
  /* If load failed, quit. Make sure to free the memory allocated to
     the arguments. */
  if (!success) {
    palloc_free_page (args);
    thread_exit ();
  }

  /* We use these variables to keep track of the original stack pointer
     address (esp_start) and to mark the address of the first character
     of the last argument pushed to the stack. These are used later in
     order to push pointers to the start of each argument to the stack. */
  char *esp_start = if_.esp;
  char *last_arg_start = if_.esp;

  /* We need to push argc to the stack later on, so we calculate it here. */
  uint32_t argc = 0;

  /* Keeps track of how many bytes we have already pushed to the stack (to avoid stack overflows). */
  uint32_t bytes_written = 0;

  /* First, push the arg strings onto the stack and free the memory
     allocated to them. */
  for (int i = 0; i < MAX_BYTES_PER_PAGE; ) {
    if (*(args + i) == '\0' && *(args + i + 1) == '\0') {
      /* Once we reach two sentinel characters in a row, we know that
         there are no arguments left to push to the stack so we can
         break out of the loop. */
      break;
    } else {
      /* Size of string starting at current memory address (args + i). */
      uint32_t size = strlen(args + i) + 1;
      if (is_stack_overflow (&bytes_written, size * sizeof (char)))
        exit_failure ();

      /* Push string to stack. */
      last_arg_start -= size;
      strlcpy (last_arg_start, args + i, size);

      /* Increment i by the length of the argument we just pushed to get to the start
         of the next argument. Increment argc so that we can keep track of the number
         of arguments pushed. */
      i += size;
      argc++;
    }
  }

  /* Free the page allocated for the arguments. */
  palloc_free_page (args);

  /* Calculate number of bytes needed to word align the stack. */
  int word_align = (esp_start - last_arg_start) % 4;
  
  /* We are about to push: 
     (i) a char for the number of word align bytes 
     (ii) a char* for the sentinel character 
     (iii) a char* for each argument (argc lots of char*)
     (iv) a char** for argv 
     (v) two ints representing argc and the fake return address respectively
          so we check to see if these will also fit on the stack. */
  size_t remaining_setup_bytes = sizeof (char) * word_align + 
                                 sizeof (char *) + 
                                 sizeof (char *) * argc + 
                                 sizeof (char **) + 
                                 sizeof (int) + 
                                 sizeof (int);

  /* If pushing the remaining bytes to the stack will cause a stack overflow,
     gracefully exit the user process. */
  if (is_stack_overflow (&bytes_written, remaining_setup_bytes))
    exit_failure ();

  /* Word align the stack. */
  if_.esp = last_arg_start - word_align;
  memset (if_.esp, 0, word_align);

  /* Push sentinel character to stack to mark end of argv. */
  PUSH_STACK (char *, if_.esp, '\0');

  /* Traverse back up the stack from last_arg_start until we reach esp_start 
     and push the address of the following element each time we encounter 
     a sentinel character. This pushes a pointer to the first character 
     of each argument. */
  char *word_start = last_arg_start;  

  while (last_arg_start++ != esp_start) {
    if (*last_arg_start == '\0') {
      PUSH_STACK (char *, if_.esp, word_start);
      word_start = last_arg_start + 1;
    }
  }

  /* Push argv, argc and return address to the stack. */
  PUSH_STACK (char **, if_.esp, ((char **) if_.esp) + 1);
  PUSH_STACK (int, if_.esp, argc);
  PUSH_STACK (int, if_.esp, 0);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for the child with tid child_tid. Returns -1 if load failed otherwise
   child_tid. */
tid_t
process_wait_on_load (tid_t child_tid)
{
  struct process_control_block *pcb = pcb_get_child_by_tid (child_tid);

  if (pcb == NULL)
    return TID_ERROR;

  sema_down (&pcb->load_sema);
  return pcb->has_loaded ? child_tid : -1;
}

/* Waits for thread TID to die and returns its exit status. 
   If it was terminated by the kernel (i.e. killed due to an exception), 
   returns -1.  

   If TID is invalid or if it was not a child of the calling process, or if 
   process_wait() has already been successfully called for the given TID, 
   returns -1 immediately, without waiting. */
int
process_wait (tid_t child_tid) 
{
  struct process_control_block *child_pcb = pcb_get_child_by_tid (child_tid);

  /* If the tid does not correspond to a PCB or if we have already waited on
     it or if it not our child, then return -1. */
  if (child_pcb == NULL || child_pcb->was_waited_on)
    return -1;

  /* If the tid does not correspond to a child of the current thread, return -1.*/
  child_pcb->was_waited_on = true;
  sema_down (&child_pcb->wait_sema);
  
  return child_pcb->status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Gets our own PCB. */

  struct process_control_block *pcb = process_get_pcb ();

  /* Close all files open by the current process and remove all
     files from our PCB's file list. Also handles re-allowing writes
     to our executable. */
  process_destroy_files ();

  struct list_elem *e;

  /* Iterates through our children and frees their PCB's if they have already exited. */
  for (e = list_begin (&pcb->children); e != list_end (&pcb->children); ) {
    struct process_control_block *child_pcb = list_entry (e, struct process_control_block, child_elem);

    /* Before we free our child's PCB, get a reference to the next child in the list. */
    e = list_next (e);

    /* Free our child's PCB if it has exited. */
    if (child_pcb->has_exited)
      free (child_pcb);
  }

  /* Mark our process as having exited, so our parent and children know (needed when they exit to ensure
     all PCBs are freed). */
  pcb->has_exited = true;

  /* If we were still alive whilst our parent process was exiting, our PCB won't have 
     been freed. Therefore, it is our responsibility to free our own PCB. */
  struct process_control_block *parent_pcb = process_get_pcb ()->parent_pcb;

  /* Allow any parent process waiting on our process to continue. */
  sema_up (&pcb->wait_sema);
  if (parent_pcb == NULL || parent_pcb->has_exited)
    free (pcb);

  /* Mark our process as having exited, so our parent and children know (needed when they exit to ensure
     all PCBs are freed).*/
  pcb->has_exited = true;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
    
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  lock_acquire (&fs_lock);
  file = filesys_open (file_name);
  
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* We deny write to our own executable for the duration of our process' lifespan.*/
  file_deny_write (file);

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  /* We add our own executable file to our PCB's files list, so that 
     we re-allow writing to it once we exit. */
  
  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  if (success) {
    process_add_file (file);
  } else {
    file_close (file);
  }
  lock_release (&fs_lock);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
      
      /* Check if virtual page already allocated */
      struct thread *t = thread_current ();
      uint8_t *kpage = pagedir_get_page (t->pagedir, upage);
      
      if (kpage == NULL){
        
        /* Get a new page of memory. */
        kpage = frame_table_get_frame (upage, PAL_USER);
        
        if (kpage == NULL)
          return false;
        
        /* Add the page to the process's address space. */
        if (!install_page (upage, kpage, writable)) 
        {
          frame_table_free_frame (kpage);
          return false; 
        }     
        
      } else {
        
        /* Check if writable flag for the page should be updated */
        if(writable && !pagedir_is_writable(t->pagedir, upage)){
          pagedir_set_writable(t->pagedir, upage, writable); 
        }
        
      }

      /* Load data into the page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
        return false; 
      }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = frame_table_get_frame (((uint8_t *) PHYS_BASE) - PGSIZE, PAL_USER | PAL_ZERO);

  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        frame_table_free_frame (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/* Adds a file to current process's pcb as well as assigning it a file 
   descriptor, which it returns. Returns -1 if fails */
int
process_add_file (struct file* file)
{
  struct process_control_block *pcb = process_get_pcb ();

  struct process_file *pfile = (struct process_file *) malloc (sizeof (struct process_file));
  if (pfile == NULL)
    return -1;

  int assigned_fd = pcb->next_fd++;
  pfile->fd = assigned_fd;
  pfile->file = file;

  if (hash_insert (&pcb->files, &pfile->hash_elem))
    return -1;
  
  return assigned_fd;
}

/* Returns process_file struct associated with file descriptor fd in the current process's pcb or
   NULL if no file could be found. */
static struct process_file *
process_get_process_file (int fd)
{
  struct process_control_block *pcb = process_get_pcb ();

  struct process_file pfile;
  pfile.fd = fd;

  struct hash_elem *found_elem = hash_find (&pcb->files, &pfile.hash_elem);
  return found_elem == NULL ? NULL : hash_entry (found_elem, struct process_file, hash_elem);
}

/* Returns file struct associated with file descriptor fd in the current process's pcb or
   NULL if no file could be found. */
struct file *
process_get_file (int fd)
{
  struct process_file *pfile = process_get_process_file (fd);
  return pfile == NULL ? NULL : pfile->file;
}

/* Removes file with file descriptor fd from current process's pcb.
   Returns true if a file is removed. */
bool
process_remove_file (int fd)
{
  struct process_file *pfile = process_get_process_file (fd);
  if (pfile == NULL) {
    return false;
  }
  process_file_close (process_get_pcb (), pfile);
  return true;
}

/* Removes all files associated with current process's pcb. */
void 
process_destroy_files (void) {
  struct process_control_block *pcb = process_get_pcb ();
  hash_destroy (&pcb->files, process_file_hash_close);
}

/* Compares process_files on the basis of their associated file descriptors. */
static bool 
fd_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  const struct process_file *pfile_a = hash_entry (a, struct process_file, hash_elem);
  const struct process_file *pfile_b = hash_entry (b, struct process_file, hash_elem);

  return pfile_a->fd < pfile_b->fd;
}

/* Hashes the fd field of a process file */
static unsigned 
process_file_hash (const struct hash_elem *elem, void *aux UNUSED)
{
  const struct process_file *pfile = hash_entry (elem, struct process_file, hash_elem);

  return hash_int (pfile->fd);
}