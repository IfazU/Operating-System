#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/synch.h"
#include "lib/string.h"

static void syscall_handler (struct intr_frame *);

/* Helper functions for system calls. */
static void access_user_mem(const void *);
uint32_t *get_arg (struct intr_frame *, int);
static void exit(int);

/* File descriptor helper functions. */
static int allocate_fd(void);
static struct file_descriptor *fd_to_file_descriptor(int);
static struct file *fd_to_file(int);

/* Standard input and output fd values respectively. */
const int STDIN_FILENUM = 0;
const int STDOUT_FILENUM = 1;

/* Maximum and minimum number values for system calls (implemented). */
const int SYSCALL_MAX = 12;
const int SYSCALL_MIN = 0;

/* System call type definition. */
typedef void syscall(struct intr_frame *f);

/* Function declarations for system calls. */
static syscall sys_halt;
static syscall sys_exit;
static syscall sys_exec;
static syscall sys_wait;
static syscall sys_create;
static syscall sys_remove;
static syscall sys_open;
static syscall sys_filesize;
static syscall sys_read;
static syscall sys_write;
static syscall sys_seek;
static syscall sys_tell;
static syscall sys_close;

/* Function pointer table for system calls, indexed in order of and by their system call numbers. */
static void (*system_calls[]) (struct intr_frame *) = {
  sys_halt, sys_exit, sys_exec, sys_wait, sys_create, sys_remove,
  sys_open, sys_filesize, sys_read, sys_write, sys_seek, sys_tell, sys_close
};

/* Writes size bytes from buffer to the open file fd. Returns the number of bytes actually
written, which may be less than size if some bytes could not be written.
Writing past end-of-file would normally extend the file, but file growth is not implemented
by the basic file system. The expected behavior is to write as many bytes as possible up to
end-of-file and return the actual number written, or 0 if no bytes could be written at all.
Fd 1 writes to the console. Your code to write to the console should write all of buffer in
one call to putbuf(), at least as long as size is not bigger than a few hundred bytes. (It is
reasonable to break up larger buffers.) Otherwise, lines of text output by different processes
may end up interleaved on the console, confusing both human readers and our grading scripts.*/

/* Questions :
- What can cause less bytes to be written?
- How do I check for this?
- Is it fine I return 0 if charBuffer is null

Writes the N characters in BUFFER to the console.
void
putbuf (const char *buffer, size_t n)
{
  acquire_console ();
  while (n-- > 0)
    putchar_have_lock (*buffer++);
  release_console ();
}
*/

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  filesys_lock = (struct lock *) malloc(sizeof(struct lock));
  lock_init(filesys_lock);
}

/* System calls handler that reroutes to correct system calls function depending on the value in
   the 32 bit word at the caller's stack pointer. */
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  uint32_t *syscall_number_address = get_arg(f, 0);
  access_user_mem(syscall_number_address);

  uint32_t syscall_number = *syscall_number_address;

  /* Checks if the system call value is within range. */
  if (syscall_number < SYSCALL_MIN || syscall_number > SYSCALL_MAX) {
    exit(-1);
  }

  /* Calls indexed system call on f. Stores result in f->eax internally for each system call. */
  system_calls[syscall_number](f);
}

/* Grabs an argument i starting from the stack pointer, and returns it. */
uint32_t *get_arg (struct intr_frame *f, int i) {
  uint32_t *syscall_number_address = (uint32_t *) f->esp;
  uint32_t *arg = syscall_number_address + i;
  access_user_mem(arg);
  return arg;
}

/* Function that checks if a pointer is safe and valid. */
static void access_user_mem (const void *uaddr) {
  if (!is_user_vaddr(uaddr) || pagedir_get_page(thread_current()->pagedir, uaddr) == NULL) {
    exit(-1);
  }
}

/* Terminates Pintos. */
static void sys_halt(struct intr_frame *f UNUSED) {
  free(filesys_lock);
  shutdown_power_off();
}

/* Terminates current user program. */
static void sys_exit(struct intr_frame *f) {
  int status = (int) *get_arg(f, 1);
  exit(status);
}

/* Helper for sys_exit() to support 'int status' variable yet mantain syscall modularity. */
static void exit(int status) {
  thread_current()->exit_status = status;
  thread_exit();
}

/* Runs the executable given. */
static void sys_exec(struct intr_frame *f) {
  const char *file = (const char *) *get_arg(f, 1);

  access_user_mem(file);

  lock_acquire(filesys_lock);
  int result = process_execute(file);
  lock_release(filesys_lock);

  f->eax = result;
}

/* Calls process_wait() to handle parent/child wait functionality. */
static void sys_wait(struct intr_frame *f) {
  pid_t pid = (pid_t) *get_arg(f, 1);
  f->eax = process_wait(pid);
};

/* Creates a new file named by input with a specified size. */
static void sys_create(struct intr_frame *f) {
  const char *file = (const char *) *get_arg(f, 1);
  unsigned initial_size = (unsigned) *get_arg(f, 2);

  access_user_mem(file);
  lock_acquire(filesys_lock);
  bool result = filesys_create(file, initial_size);
  lock_release(filesys_lock);

  f->eax = result;
}

/* Deletes specified file if possible, returning a value depending on success or failure. */
static void sys_remove(struct intr_frame *f) {
  const char *file = (const char *) *get_arg(f, 1); 

  access_user_mem(file);
  lock_acquire(filesys_lock);
  bool result = filesys_remove(file);
  lock_release(filesys_lock);

  f->eax = result;
}

/* Opens the file specified. */
static void sys_open(struct intr_frame *f) {
  const char *file = (const char *) *get_arg(f, 1); 

  access_user_mem(file);

  lock_acquire(filesys_lock);
  struct file *file_open = filesys_open(file);
  lock_release(filesys_lock);

  /* Returns -1 if file does not exist. */
  if (file_open == NULL) {
    f->eax = -1;
    return;
  }

  struct file_descriptor *fd_elem = malloc(sizeof(struct file_descriptor));

  /* Returns -1 if memory could not be allocated for this file (descriptor). */
  if (fd_elem == NULL) {
    file_close(file_open);
    f->eax = -1;
    return;
  }

  lock_acquire(filesys_lock);
  fd_elem->file = file_open;
  fd_elem->fd = allocate_fd();
  list_push_back(thread_current()->file_descriptors, &fd_elem->elem);
  lock_release(filesys_lock);

  f->eax = fd_elem->fd;
}

/* Returns filesize for a specified file descriptor. */
static void sys_filesize(struct intr_frame *f) {
  int fd = (int) *get_arg(f, 1);

  struct file *file = fd_to_file(fd);
  int size = -1;

  if (file != NULL) {
    lock_acquire(filesys_lock);
    size = file_length(file);
    lock_release(filesys_lock);
  }
  
  f->eax = size;
}

/* Reads "size" bytes from file open as fd into buffer. */
static void sys_read(struct intr_frame *f) {
  int fd = (int) *get_arg(f, 1);
  void *buffer = (void *) *get_arg(f, 2);
  unsigned size = (unsigned) *get_arg(f, 3);

  access_user_mem(buffer);

  int bytes_read = -1;

  /* Handles reading from keyboard if fd value is 0 or greater than 1. */
  if (fd == STDIN_FILENUM) {
    uint8_t *buf = (uint8_t *) buffer;

    for (unsigned i = 0; i < size; i++) {
      buf[i] = input_getc();
    }
    
    f->eax = size;
    return;
  } else if (fd > STDOUT_FILENUM) {
    lock_acquire(filesys_lock);
    struct file *file = fd_to_file(fd);

    if (file != NULL) {
      bytes_read = file_read(file, buffer, size);
    }

    lock_release(filesys_lock);

    f->eax = bytes_read;
    return;
  }

  /* Handles invalid fd values. */
  f->eax = -1;
}

/* Writes to file or console depending on fd value. */
static void sys_write(struct intr_frame *f) {
  int fd = (int) *get_arg(f, 1);
  const void *buffer = (const void *) *get_arg(f, 2);
  unsigned size = (unsigned) *get_arg(f, 3);

  access_user_mem(buffer);
  int bytes_written = -1;

  /* Handles standard output fd value to write to console, or anything greater. */
  if (fd == STDOUT_FILENUM) {
    const char *charBuffer = (const char *) buffer;

    /* Checking buffer is not NULL, if NULL return 0 since no byte was written. */
    if (charBuffer == NULL) {
      f->eax = -1;
      return;
    }

    /* Handles sizes that are greater than 400 bytes and breaks it down. */
    int sizeCount = size;

    while (sizeCount != 0) {
      if (sizeCount <= 400) {
        putbuf(charBuffer, sizeCount);
        sizeCount = 0;
      } else {
        putbuf(charBuffer, 400);
        sizeCount -= 400;
        charBuffer += 400;
        access_user_mem(charBuffer);
      }
    }

    f->eax = size;
    return;
  } else if (fd > STDOUT_FILENUM) {
    lock_acquire(filesys_lock);

    struct file *file = fd_to_file(fd);

    if (file != NULL) {
      bytes_written = file_write(file, buffer, size);
    }

    lock_release(filesys_lock);

    f->eax = bytes_written;
    return;
  }

  /* Handles invalid fd values. */
  f->eax = bytes_written;
}

/* Changes the next byte to be read in a file to "position". */
static void sys_seek (struct intr_frame *f) {
  int fd = (int) *get_arg(f, 1);
  unsigned position = (unsigned) *get_arg(f, 2);
  struct file *file = fd_to_file(fd);

  /* If the fd value is not valid or the file is NULL, it exits. */
  if (file != NULL && fd > STDOUT_FILENUM) {
    lock_acquire(filesys_lock);
    file_seek(file, position);
    lock_release(filesys_lock);
  } else {
    exit(-1);
  }
}

/* Returns the poisiton of the next byte to be written for fd. */
static void sys_tell(struct intr_frame *f) {
  int fd = (int) *get_arg(f, 1);
  struct file *file = fd_to_file(fd);

  /* If the fd value is not valid or the file is NULL, it exits. */
  if (file != NULL && fd > STDOUT_FILENUM) {
    lock_acquire(filesys_lock);
    unsigned position = file_tell(file);
    lock_release(filesys_lock);
    f->eax = position;
  } else {
    exit(-1);
  }
}

/* Closes file descriptor fd. */
static void sys_close(struct intr_frame *f) {
  int fd = (int) *get_arg(f, 1);
  struct file *file = fd_to_file(fd);

  if (file != NULL && fd > STDOUT_FILENUM) {
    file_close(file);
    struct file_descriptor *file_descriptor = fd_to_file_descriptor(fd);
    
    if (file_descriptor != NULL) {
      lock_acquire(filesys_lock);
      list_remove(&file_descriptor->elem);
      free(file_descriptor);
      lock_release(filesys_lock);
    }
  }
}

/* Finds an available fd value by iterating through file_descriptors of thread. */
static int allocate_fd(void) {
  int fd = 2; /* Starts from 2 to avoid conflicts with standard input/output values. */

  while (fd_to_file_descriptor(fd) != NULL) {
    fd++;
  }

  return fd;
}

/* Grabs the file_descriptor struct associated with an fd value from some thread. */
static struct file_descriptor *fd_to_file_descriptor(int fd) {
  struct list_elem *e;
  struct thread *current_thread = thread_current();

  for (e = list_begin(current_thread->file_descriptors); 
       e != list_end(current_thread->file_descriptors); 
       e = list_next(e)) {
    struct file_descriptor *fd_elem = list_entry(e, struct file_descriptor, elem);

    if (fd_elem->fd == fd) {
      return fd_elem;
    }
  }

  /* If the file descriptor is not found, return NULL. */
  return NULL;
}

/* Grabs the file associated with an fd value from some thread, otherwise NULL. */
static struct file *fd_to_file(int fd) {
  struct file_descriptor *file_descriptor = fd_to_file_descriptor(fd);

  if (file_descriptor == NULL) {
    return NULL;
  } else {
    return file_descriptor->file;
  }
}