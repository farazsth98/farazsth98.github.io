---
layout: post
title: ASIS 2015 CTF Dark Reverse Engineering 100
category: CTF
tags: RE CTF ASIS Dark
---

# ASIS 2015 Quals - Dark
**Points:** 125
**Solves:** 47
**Category:** Reverse
**Description:**

> Find the flag in [this]({{site.url}}/assets/dark_aba92f5882a156452b18b895c722cea6) file.

## Write-up

This time we are presented with two files. Binary 'dark' and data file 'flag.enc'.

	$ file dark 
	dark: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.26, BuildID[sha1]=0xb737fdb3a9bd03650483d4149efb981729b98ac8, stripped
	$ file flag.enc 
	flag.enc: data
	$ ./dark 
	Usage: ./dark inputfile outputfile
 
Ok, so it's an encryption function taking input file outputting encrypted file.
No decryption functionality :), so let's find it out.  

Main function:  

{% highlight bash %}
(gdb) x/200i 0x400715
   0x400715:	push   rbp
   0x400716:	mov    rbp,rsp
   0x400719:	push   rbx
   0x40071a:	sub    rsp,0x98
   0x400721:	mov    DWORD PTR [rbp-0x84],edi
   0x400727:	mov    QWORD PTR [rbp-0x90],rsi
   0x40072e:	cmp    DWORD PTR [rbp-0x84],0x3  <== argc == 3 ?
   0x400735:	je     0x400758
   0x400737:	mov    rax,QWORD PTR [rbp-0x90]
   0x40073e:	mov    rax,QWORD PTR [rax]
   0x400741:	mov    rsi,rax
   0x400744:	mov    edi,0x400a20  <=== usage
   0x400749:	mov    eax,0x0
   0x40074e:	call   0x400560 <printf@plt>
   0x400753:	jmp    0x40095d  <=== exit
{% endhighlight %}

Function prolog.  
If argc != 3 print usage and exit.

{% highlight bash %}
   0x400758:	mov    rax,rsp
   0x40075b:	mov    rbx,rax
   0x40075e:	mov    rax,QWORD PTR [rbp-0x90]
   0x400765:	add    rax,0x8
   0x400769:	mov    rax,QWORD PTR [rax]
   0x40076c:	mov    esi,0x400a40
   0x400771:	mov    rdi,rax
   0x400774:	call   0x400590 <fopen@plt>
   0x400779:	mov    QWORD PTR [rbp-0x20],rax
   0x40077d:	mov    rax,QWORD PTR [rbp-0x90]
   0x400784:	add    rax,0x10
   0x400788:	mov    rax,QWORD PTR [rax]
   0x40078b:	mov    esi,0x400a42
   0x400790:	mov    rdi,rax
   0x400793:	call   0x400590 <fopen@plt>
   0x400798:	mov    QWORD PTR [rbp-0x28],rax

{% endhighlight %}

First fopen function opens inputfile for reading.  
Second fopen function opens outfile for writing.

From the return of the functions, we know that rbp-0x20 will store the file descriptor returned by fopen("inputfile", 'r').
rbp-0x28 will store the file descriptor from fopen("outputfile", 'wb').

{% highlight bash %}
   0x40079c:	mov    DWORD PTR [rbp-0x2c],0x7607  
   0x4007a3:	mov    DWORD PTR [rbp-0x30],0x10
   0x4007aa:	mov    eax,DWORD PTR [rbp-0x2c]
   0x4007ad:	movsxd rdx,eax
   0x4007b0:	sub    rdx,0x1
   0x4007b4:	mov    QWORD PTR [rbp-0x38],rdx
   0x4007b8:	cdqe   
   0x4007ba:	mov    edx,0x10
   0x4007bf:	sub    rdx,0x1
   0x4007c3:	add    rax,rdx
   0x4007c6:	mov    QWORD PTR [rbp-0x98],0x10
   0x4007d1:	mov    edx,0x0
   0x4007d6:	div    QWORD PTR [rbp-0x98]
   0x4007dd:	imul   rax,rax,0x10
   0x4007e1:	sub    rsp,rax
   0x4007e4:	mov    rax,rsp
   0x4007e7:	add    rax,0x0
   0x4007eb:	mov    QWORD PTR [rbp-0x40],rax
   0x4007ef:	mov    eax,DWORD PTR [rbp-0x2c]
   0x4007f2:	movsxd rdx,eax
   0x4007f5:	sub    rdx,0x1
   0x4007f9:	mov    QWORD PTR [rbp-0x48],rdx
   0x4007fd:	cdqe   
   0x4007ff:	mov    edx,0x10
   0x400804:	sub    rdx,0x1
   0x400808:	add    rax,rdx
   0x40080b:	mov    QWORD PTR [rbp-0x98],0x10
   0x400816:	mov    edx,0x0
   0x40081b:	div    QWORD PTR [rbp-0x98]
   0x400822:	imul   rax,rax,0x10
   0x400826:	sub    rsp,rax
   0x400829:	mov    rax,rsp
   0x40082c:	add    rax,0x0
   0x400830:	mov    QWORD PTR [rbp-0x50],rax
   0x400834:	mov    eax,DWORD PTR [rbp-0x2c]
   0x400837:	movsxd rdx,eax
   0x40083a:	mov    rax,QWORD PTR [rbp-0x40]
   0x40083e:	mov    rcx,QWORD PTR [rbp-0x20]
   0x400842:	mov    esi,0x1
   0x400847:	mov    rdi,rax
   0x40084a:	call   0x400540 <fread@plt>           # Call fread like fread(buff, 1, 30215, "inputfile");
   0x40084f:	mov    DWORD PTR [rbp-0x14],0x0
   0x400856:	jmp    0x400913
   0x40085b:	mov    DWORD PTR [rbp-0x18],0x0 <----------------------| Outter loop of encryption routine.
   0x400862:	jmp    0x400903                                        | 
   0x400867:	mov    eax,DWORD PTR [rbp-0x14] <---|< inner loop      |
   0x40086a:	add    eax,0x1                      |< ++              |
   0x40086d:	imul   eax,DWORD PTR [rbp-0x30]     |< counter * 16    |
   0x400871:	sub    eax,DWORD PTR [rbp-0x18]     |< -outter loop ctr|
   0x400874:	sub    eax,0x1                      |< --              |
   0x400877:	mov    rdx,QWORD PTR [rbp-0x40]     |Splits read on 16 |
   0x40087b:	cdqe                                |byte chunks and   |
   0x40087d:	movzx  eax,BYTE PTR [rdx+rax*1]     |takes chunk[15]   |
   0x400881:	movzx  eax,al                       |                  |
   0x400884:	mov    DWORD PTR [rbp-0x54],eax     |sprintf transforms|
   0x400887:	mov    edx,DWORD PTR [rbp-0x54]     |the 16th byte and |
   0x40088a:	lea    rax,[rbp-0x70]               |transforms HEX    |
   0x40088e:	mov    esi,0x400a45                 |< %02x\n          |
   0x400893:	mov    rdi,rax                      |                  |
   0x400896:	mov    eax,0x0                      |                  |
   0x40089b:	call   0x4005a0 <sprintf@plt>       |                  |
   0x4008a0:	movzx  eax,BYTE PTR [rbp-0x6f]      |< flips           |
   0x4008a4:	mov    BYTE PTR [rbp-0x80],al       |< the             |
   0x4008a7:	movzx  eax,BYTE PTR [rbp-0x70]      |< nibbles         |
   0x4008ab:	mov    BYTE PTR [rbp-0x7f],al       |<                 |
   0x4008ae:	lea    rax,[rbp-0x80]               |                  |
   0x4008b2:	mov    edx,0x10                     |                  |
   0x4008b7:	mov    esi,0x0                      |                  |
   0x4008bc:	mov    rdi,rax                      |                  |
   0x4008bf:	call   0x400580 <strtol@plt>        |Transforms to hex |
   0x4008c4:	mov    QWORD PTR [rbp-0x60],rax     |                  |
   0x4008c8:	mov    eax,DWORD PTR [rbp-0x14]     |                  |
   0x4008cb:	mov    edx,eax                      |                  |
   0x4008cd:	imul   edx,DWORD PTR [rbp-0x30]     |                  |
   0x4008d1:	mov    eax,DWORD PTR [rbp-0x18]     |                  |
   0x4008d4:	lea    esi,[rdx+rax*1]              |                  |
   0x4008d7:	mov    rax,QWORD PTR [rbp-0x60]     |                  |
   0x4008db:	mov    edx,eax                      |                  |
   0x4008dd:	mov    eax,DWORD PTR [rbp-0x18]     |< inner counter   |
   0x4008e0:	mov    ecx,DWORD PTR [rbp-0x18]     |< inner counter   |
   0x4008e3:	imul   eax,ecx                      |< multiply        |
   0x4008e6:	xor    edx,eax                      | XOR byte with    | inner counter * inner counter
   0x4008e8:	mov    eax,DWORD PTR [rbp-0x14]     |< outter counter  |
   0x4008eb:	mov    ecx,DWORD PTR [rbp-0x14]     |< outter counter  |
   0x4008ee:	imul   eax,ecx                      |< multiply        | 
   0x4008f1:	mov    ecx,edx                      |                  |
   0x4008f3:	xor    ecx,eax                      |< XOR byte with   | outter counter * outter counter
   0x4008f5:	mov    rdx,QWORD PTR [rbp-0x50]     |                  |
   0x4008f9:	movsxd rax,esi                      |Move the result in|
   0x4008fc:	mov    BYTE PTR [rdx+rax*1],cl      |buffer            |
   0x4008ff:	add    DWORD PTR [rbp-0x18],0x1     |                  |
   0x400903:	mov    eax,DWORD PTR [rbp-0x18]     |                  |
   0x400906:	cmp    eax,DWORD PTR [rbp-0x30]     | <================|== compare inner loop counter < 16
   0x400909:	jl     0x400867    ,----------------|                  |
   0x40090f:	add    DWORD PTR [rbp-0x14],0x1                        |
   0x400913:	mov    eax,DWORD PTR [rbp-0x2c]                        |
   0x400916:	mov    edx,eax                                         |
   0x400918:	sar    edx,0x1f                                        |
   0x40091b:	idiv   DWORD PTR [rbp-0x30]                            |
   0x40091e:	cmp    eax,DWORD PTR [rbp-0x14]       <================|==== Loop if outter loop counter < 30216 / 16
   0x400921:	jg     0x40085b   <-------------------------------------
{% endhighlight %}

Ok, we know how the encryption algorythm works. So it reads 30216 bytes from inputfile. Splits it into chunks of 16 bytes.
It loops 1888 times (once per 16 bytes chunk) which we call outter loop and takes the each byte from the chunk in reverse order.
chunk[15], chunk[14], chunk[13]... flips the nibbles, XORs with the inner loops counter (which iterates through the bytes in a chunk) * inner loop counter.
After that XORs the result with the outter loop counter * outter loop counter.
For example in our input is file with content "AAAAAAAAAAAAAAAA". It takes input[15] (AAAAAAAAAAAAAAA[A]) transforms into HEX 0x41.
Flips the bits 0x14 and for the initial loop it would XOR with 0 twice. It puts this byte as the first byte in the outputfile.

{% highlight bash %}
   0x400927:	mov    eax,DWORD PTR [rbp-0x2c]
   0x40092a:	movsxd rdx,eax
   0x40092d:	mov    rax,QWORD PTR [rbp-0x50]
   0x400931:	mov    rcx,QWORD PTR [rbp-0x28]
   0x400935:	mov    esi,0x1
   0x40093a:	mov    rdi,rax
   0x40093d:	call   0x4005b0 <fwrite@plt>
   0x400942:	mov    rax,QWORD PTR [rbp-0x28]
   0x400946:	mov    rdi,rax
   0x400949:	call   0x400550 <fclose@plt>
   0x40094e:	mov    rax,QWORD PTR [rbp-0x20]
   0x400952:	mov    rdi,rax
   0x400955:	call   0x400550 <fclose@plt>
   0x40095a:	mov    rsp,rbx
   0x40095d:	mov    eax,0x0
   0x400962:	mov    rbx,QWORD PTR [rbp-0x8]
   0x400966:	leave  
   0x400967:	ret    
{% endhighlight %}

At the last code section the function writes the encrypted bytes into the outfile, closes both files and exits.

We now know how the encryption works, let's make our python script in reverse order.

{% highlight python %}
#!/usr/bin/env python

import sys

flag = open('flag', 'w')
infile = bytearray(open(sys.argv[1], 'r').read())
outfile = []

n = 16
enc = [list(infile[i:i+n]) for i in range(0, len(infile), n)]

for outter in range(1888):
	a = []
	for inner in range(0,16):
		x = enc[outter][inner] ^ ((outter * outter) & 0xFF)
		y = x ^ (inner * inner)
		z = []
		z.append("%2x" % (y))
		b = []
		b.append(z[0][1])
		b.append(z[0][0])
		if b[1] == ' ':
			b[1] = '0'
		a.append(''.join(b))
	for p in reversed(xrange(16)):
		outfile.append(a[p])

for byte in outfile:
	flag.write(byte.decode("hex"))
flag.close()

{% endhighlight %}

## Links

* <http://www.asis-ctf.ir/challenges/>

