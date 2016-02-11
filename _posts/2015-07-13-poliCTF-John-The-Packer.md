---
layout: post
title: poliCTF 2015 John the packer 350
category: Reverse Engineering
tags: RE poliCTF
comments: true
---

**Points:** 350
**Solves:** 50
**Category:** Reverse Engineering
**Description:**

> John's greatest skill is to pack everything and everywhere with everyone. He doesn't want that someone reverse his super secret program. So he wrote a magic packing system. Can you show to John that his packing system is not a good anti-reversing solution? N.B. Unfortunately John The Packer has multiple solution, so if you have a solution that is not accepted by the scoreboard (but is accepted by the binary) please contact an OP on IRC

[john the packer]({{site.url}}/assets/topack)

## Write-up

Let's see what are we presented with here. 32-bit ELF stripped and we have to find the flag by passing it as an argument.

{% highlight bash %}
$ file topack 
topack: ELF 32-bit LSB  executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, BuildID[sha1]=1c3cb4e123e1be23724aa03af0b2307acb7bbe8a, stripped
$ ./topack 
Usage:
 ./topack flag{<key>}
$ ./topack AAAA
wrong Header for AAAA
wrong End for AAAA
Loser
$ 
{% endhighlight %}
 
Notice the 'wrong Header' and 'wrong End' warnings ? Let's try passing the right flag format as it tells us.

{% highlight bash %}
$ ./topack flag{AAAA}
Loser
$ 
{% endhighlight %}

This time no warnings...

Let's take a look at the main function.

{% highlight bash %}
(gdb) x/50i 0x8048bf2
=> 0x8048bf2:	lea    ecx,[esp+0x4]
   0x8048bf6:	and    esp,0xfffffff0
   0x8048bf9:	push   DWORD PTR [ecx-0x4]
   0x8048bfc:	push   ebp
   0x8048bfd:	mov    ebp,esp
   0x8048bff:	push   ecx
   0x8048c00:	sub    esp,0x4
   0x8048c03:	mov    eax,ecx
   0x8048c05:	push   DWORD PTR [eax+0x4]
   0x8048c08:	push   DWORD PTR [eax]
   0x8048c0a:	push   0x53
   0x8048c0f:	push   0x8048aa5
   0x8048c14:	call   0x80485e0
   0x8048c19:	add    esp,0x10
   0x8048c1c:	mov    eax,0x0
   0x8048c21:	mov    ecx,DWORD PTR [ebp-0x4]
   0x8048c24:	leave  
{% endhighlight %}

Hm... this is a weird main function :). Anyway, let's continue with the next function, 0x80485e0.

{% highlight bash %}
(gdb) x/50i 0x80485e0
   0x80485e0:	push   ebp
   0x80485e1:	mov    ebp,esp
   0x80485e3:	sub    esp,0x8
   0x80485e6:	mov    eax,DWORD PTR [ebp+0x8]
   0x80485e9:	and    eax,0xfffff000
   0x80485ee:	sub    esp,0x4
   0x80485f1:	push   0x7
   0x80485f3:	push   0x1000
   0x80485f8:	push   eax
   0x80485f9:	call   0x8048430 <mprotect@plt>
   0x80485fe:	add    esp,0x10
   0x8048601:	mov    ecx,DWORD PTR [ebp+0x8]
   0x8048604:	mov    edx,0x66666667
   0x8048609:	mov    eax,ecx
   0x804860b:	imul   edx
   0x804860d:	sar    edx,1
   0x804860f:	mov    eax,ecx
   0x8048611:	sar    eax,0x1f
   0x8048614:	sub    edx,eax
   0x8048616:	mov    eax,edx
   0x8048618:	mov    edx,eax
   0x804861a:	shl    edx,0x2
   0x804861d:	add    edx,eax
   0x804861f:	mov    eax,ecx
   0x8048621:	sub    eax,edx
   0x8048623:	mov    edx,DWORD PTR [eax*4+0x804a294]
   0x804862a:	mov    eax,DWORD PTR [ebp+0x8]
   0x804862d:	mov    ecx,DWORD PTR [ebp+0xc]
   0x8048630:	add    esp,0x8
   0x8048633:	push   eax
   0x8048634:	mov    edx,DWORD PTR [edx]
   0x8048636:	xor    DWORD PTR [eax],edx
   0x8048638:	add    eax,0x4
   0x804863b:	dec    ecx
   0x804863c:	jne    0x8048636
   0x804863e:	pop    eax
   0x804863f:	call   eax
   0x8048641:	sub    esp,0x8
   0x8048644:	push   DWORD PTR [ebp+0xc]
   0x8048647:	push   DWORD PTR [ebp+0x8]
   0x804864a:	call   0x804859b
   0x804864f:	add    esp,0x10
   0x8048652:	nop
   0x8048653:	leave
{% endhighlight %}

Aha, here comes the unpacking routine! First it modifies 0x08048000 section with size of 0x1000 is hex with READ, WRITE and EXEC permissions using mprotect().
Next it actually does the modification and almost to the end we see call EAX, if we add a breakpoint there we actually see that EAX is the address pushed before
we enter this unpacking function, '0x8048aa5'.

{% highlight bash %}
(gdb) b *0x804863f
Breakpoint 1 at 0x804863f
(gdb) run flag{AAAA}

Starting program: /home/user/ctfs/poliCTF/re350/topack flag{AAAA}

Breakpoint 1, 0x0804863f in ?? ()
(gdb) info reg
eax            0x8048aa5	134515365
ecx            0x0	0
edx            0x4030201	67305985
ebx            0xb7f76000	-1208524800
esp            0xbffff0b8	0xbffff0b8
ebp            0xbffff0b8	0xbffff0b8
esi            0x0	0
edi            0x0	0
eip            0x804863f	0x804863f
eflags         0x246	[ PF ZF IF ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
(gdb) 
{% endhighlight %}

Let's step inside and see what's going on here.
It looks like we have arrived at the 'real' main function. However we can't dump the process just yet,
if we pay close attention, we are can recognize the 0x80485e0 function which unpacked 'main' and the address argument passed
to it.

{% highlight bash %}
(gdb) x/200i $eip
=> 0x8048aa5:	push   ebp
   0x8048aa6:	mov    ebp,esp
   0x8048aa8:	sub    esp,0x18
   0x8048aab:	cmp    DWORD PTR [ebp+0x18],0x1
   0x8048aaf:	jg     0x8048ad1
   0x8048ab1:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8048ab4:	mov    eax,DWORD PTR [eax]
   0x8048ab6:	sub    esp,0x8
   0x8048ab9:	push   eax
   0x8048aba:	push   0x8048db8
   0x8048abf:	call   0x8048440 <printf@plt>
   0x8048ac4:	add    esp,0x10
   0x8048ac7:	sub    esp,0xc
   0x8048aca:	push   0x0
   0x8048acc:	call   0x8048470 <exit@plt>
   0x8048ad1:	mov    DWORD PTR [ebp-0xc],0x0
   0x8048ad8:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8048adb:	add    eax,0x4
   0x8048ade:	mov    eax,DWORD PTR [eax]
   0x8048ae0:	sub    esp,0x4
   0x8048ae3:	push   eax
   0x8048ae4:	push   0x11
   0x8048ae9:	push   0x8048655
   0x8048aee:	call   0x80485e0
   0x8048af3:	add    esp,0x10
   0x8048af6:	add    DWORD PTR [ebp-0xc],eax
   0x8048af9:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8048afc:	add    eax,0x4
   0x8048aff:	mov    eax,DWORD PTR [eax]
   0x8048b01:	sub    esp,0x4
   0x8048b04:	push   eax
   0x8048b05:	push   0x11
   0x8048b0a:	push   0x804869a
   0x8048b0f:	call   0x80485e0
   0x8048b14:	add    esp,0x10
   0x8048b17:	add    DWORD PTR [ebp-0xc],eax
   0x8048b1a:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8048b1d:	add    eax,0x4
   0x8048b20:	mov    eax,DWORD PTR [eax]
   0x8048b22:	sub    esp,0x4
   0x8048b25:	push   eax
   0x8048b26:	push   0x17
   0x8048b2b:	push   0x80486de
   0x8048b30:	call   0x80485e0
   0x8048b35:	add    esp,0x10
   0x8048b38:	add    DWORD PTR [ebp-0xc],eax
   0x8048b3b:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8048b3e:	add    eax,0x4
   0x8048b41:	mov    eax,DWORD PTR [eax]
   0x8048b43:	sub    esp,0x4
   0x8048b46:	push   eax
   0x8048b47:	push   0x18
   0x8048b4c:	push   0x8048a42
   0x8048b51:	call   0x80485e0
   0x8048b56:	add    esp,0x10
   0x8048b59:	add    DWORD PTR [ebp-0xc],eax
   0x8048b5c:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8048b5f:	add    eax,0x4
   0x8048b62:	mov    eax,DWORD PTR [eax]
   0x8048b64:	sub    esp,0x4
   0x8048b67:	push   eax
   0x8048b68:	push   0x26
   0x8048b6d:	push   0x80489a9
   0x8048b72:	call   0x80485e0
   0x8048b77:	add    esp,0x10
   0x8048b7a:	add    DWORD PTR [ebp-0xc],eax
   0x8048b7d:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8048b80:	add    eax,0x4
   0x8048b83:	mov    eax,DWORD PTR [eax]
   0x8048b85:	push   0x0
   0x8048b87:	push   eax
   0x8048b88:	push   0x27
   0x8048b8d:	push   0x804890b
   0x8048b92:	call   0x80485e0
   0x8048b97:	add    esp,0x10
   0x8048b9a:	add    DWORD PTR [ebp-0xc],eax
   0x8048b9d:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8048ba0:	add    eax,0x4
   0x8048ba3:	mov    eax,DWORD PTR [eax]
   0x8048ba5:	sub    esp,0x4
   0x8048ba8:	push   eax
   0x8048ba9:	push   0x9
   0x8048bae:	push   0x80488e4
   0x8048bb3:	call   0x80485e0
   0x8048bb8:	add    esp,0x10
   0x8048bbb:	add    DWORD PTR [ebp-0xc],eax
   0x8048bbe:	cmp    DWORD PTR [ebp-0xc],0x7
   0x8048bc2:	jne    0x8048bdf
   0x8048bc4:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8048bc7:	add    eax,0x4
   0x8048bca:	mov    eax,DWORD PTR [eax]
   0x8048bcc:	sub    esp,0x8
   0x8048bcf:	push   eax
   0x8048bd0:	push   0x8048dd0
   0x8048bd5:	call   0x8048440 <printf@plt>
   0x8048bda:	add    esp,0x10
   0x8048bdd:	jmp    0x8048bef
   0x8048bdf:	sub    esp,0xc
   0x8048be2:	push   0x8048df8
   0x8048be7:	call   0x8048440 <printf@plt>
   0x8048bec:	add    esp,0x10
   0x8048bef:	nop
   0x8048bf0:	leave  
   0x8048bf1:	ret    
{% endhighlight %}

The way I organized the analysis was in sections. The unpacking routine was called 7 times with different address as argument.
That means we are going to have to complete 7 'levels' each one is being unpacked before execution reached there.
So let me split the main routine in 7 sections...

{% highlight bash %}
(gdb) x/200i $eip
=> 0x8048aa5:	push   ebp
   0x8048aa6:	mov    ebp,esp
   0x8048aa8:	sub    esp,0x18
   0x8048aab:	cmp    DWORD PTR [ebp+0x18],0x1
   0x8048aaf:	jg     0x8048ad1
   0x8048ab1:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8048ab4:	mov    eax,DWORD PTR [eax]
   0x8048ab6:	sub    esp,0x8
   0x8048ab9:	push   eax
   0x8048aba:	push   0x8048db8
   0x8048abf:	call   0x8048440 <printf@plt>
   0x8048ac4:	add    esp,0x10
   0x8048ac7:	sub    esp,0xc
   0x8048aca:	push   0x0
   0x8048acc:	call   0x8048470 <exit@plt>
   0x8048ad1:	mov    DWORD PTR [ebp-0xc],0x0
   0x8048ad8:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8048adb:	add    eax,0x4
   0x8048ade:	mov    eax,DWORD PTR [eax]
   0x8048ae0:	sub    esp,0x4
   0x8048ae3:	push   eax
   0x8048ae4:	push   0x11
   0x8048ae9:	push   0x8048655
   0x8048aee:	call   0x80485e0
   0x8048af3:	add    esp,0x10
   0x8048af6:	add    DWORD PTR [ebp-0xc],eax
   0x8048af9:	mov    eax,DWORD PTR [ebp+0x1c]

-------------- section 1 ---------------

   0x8048afc:	add    eax,0x4
   0x8048aff:	mov    eax,DWORD PTR [eax]
   0x8048b01:	sub    esp,0x4
   0x8048b04:	push   eax
   0x8048b05:	push   0x11
   0x8048b0a:	push   0x804869a
   0x8048b0f:	call   0x80485e0
   0x8048b14:	add    esp,0x10
   0x8048b17:	add    DWORD PTR [ebp-0xc],eax
   0x8048b1a:	mov    eax,DWORD PTR [ebp+0x1c]

-------------- section 2 ---------------

   0x8048b1d:	add    eax,0x4
   0x8048b20:	mov    eax,DWORD PTR [eax]
   0x8048b22:	sub    esp,0x4
   0x8048b25:	push   eax
   0x8048b26:	push   0x17
   0x8048b2b:	push   0x80486de
   0x8048b30:	call   0x80485e0
   0x8048b35:	add    esp,0x10
   0x8048b38:	add    DWORD PTR [ebp-0xc],eax
   0x8048b3b:	mov    eax,DWORD PTR [ebp+0x1c]
   
-------------- section 3 ---------------

   0x8048b3e:	add    eax,0x4
   0x8048b41:	mov    eax,DWORD PTR [eax]
   0x8048b43:	sub    esp,0x4
   0x8048b46:	push   eax
   0x8048b47:	push   0x18
   0x8048b4c:	push   0x8048a42
   0x8048b51:	call   0x80485e0
   0x8048b56:	add    esp,0x10
   0x8048b59:	add    DWORD PTR [ebp-0xc],eax
   0x8048b5c:	mov    eax,DWORD PTR [ebp+0x1c]

-------------- section 4 ---------------

   0x8048b5f:	add    eax,0x4
   0x8048b62:	mov    eax,DWORD PTR [eax]
   0x8048b64:	sub    esp,0x4
   0x8048b67:	push   eax
   0x8048b68:	push   0x26
   0x8048b6d:	push   0x80489a9
   0x8048b72:	call   0x80485e0
   0x8048b77:	add    esp,0x10
   0x8048b7a:	add    DWORD PTR [ebp-0xc],eax
   0x8048b7d:	mov    eax,DWORD PTR [ebp+0x1c]

-------------- section 5 ---------------

   0x8048b80:	add    eax,0x4
   0x8048b83:	mov    eax,DWORD PTR [eax]
   0x8048b85:	push   0x0
   0x8048b87:	push   eax
   0x8048b88:	push   0x27
   0x8048b8d:	push   0x804890b
   0x8048b92:	call   0x80485e0
   0x8048b97:	add    esp,0x10
   0x8048b9a:	add    DWORD PTR [ebp-0xc],eax
   0x8048b9d:	mov    eax,DWORD PTR [ebp+0x1c]

-------------- section 6 ---------------

   0x8048ba0:	add    eax,0x4
   0x8048ba3:	mov    eax,DWORD PTR [eax]
   0x8048ba5:	sub    esp,0x4
   0x8048ba8:	push   eax
   0x8048ba9:	push   0x9
   0x8048bae:	push   0x80488e4
   0x8048bb3:	call   0x80485e0
   0x8048bb8:	add    esp,0x10
   0x8048bbb:	add    DWORD PTR [ebp-0xc],eax

-------------- section 7 ---------------

   0x8048bbe:	cmp    DWORD PTR [ebp-0xc],0x7 <=== Compare if all sections returned '1'
   0x8048bc2:	jne    0x8048bdf
   0x8048bc4:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8048bc7:	add    eax,0x4
   0x8048bca:	mov    eax,DWORD PTR [eax]
   0x8048bcc:	sub    esp,0x8
   0x8048bcf:	push   eax
   0x8048bd0:	push   0x8048dd0                 <===== Good Boy
   0x8048bd5:	call   0x8048440 <printf@plt>
   0x8048bda:	add    esp,0x10
   0x8048bdd:	jmp    0x8048bef
   0x8048bdf:	sub    esp,0xc
   0x8048be2:	push   0x8048df8                 <===== Bad Boy
   0x8048be7:	call   0x8048440 <printf@plt>
   0x8048bec:	add    esp,0x10
   0x8048bef:	nop
   0x8048bf0:	leave  
   0x8048bf1:	ret    
{% endhighlight %}

If you take a look at the end here, past section #7. You can see that the result of each return is compared to 0x7.
This means that each level needs to return '1' in order to reach the "Good Boy" statement. So let's continue and add a breakpoint
at each address passed to 0x80485e0, starting with section number 1 with address '0x8048655'.

# Section number 1

{% highlight bash %}
(gdb) b *0x8048655
Breakpoint 4 at 0x8048655
(gdb) c
Continuing.

Breakpoint 4, 0x08048655 in ?? ()
(gdb) x/50i $eip
=> 0x8048655:	inc    ebp
   0x8048656:	mov    ebp,esp
   0x8048658:	sub    esp,0x18
   0x804865b:	sub    esp,0x8
   0x804865e:	push   0x8048cf9
   0x8048663:	push   DWORD PTR [ebp+0x18]
   0x8048666:	call   0x8048420 <strstr@plt>
   0x804866b:	add    esp,0x10
   0x804866e:	mov    DWORD PTR [ebp-0xc],eax
   0x8048671:	mov    eax,DWORD PTR [ebp-0xc]
   0x8048674:	cmp    eax,DWORD PTR [ebp+0x18]
   0x8048677:	jne    0x8048680           <----- Bad
   0x8048679:	mov    eax,0x1             <----- Good
   0x804867e:	jmp    0x8048698
   0x8048680:	sub    esp,0x8
   0x8048683:	push   DWORD PTR [ebp+0x18]
   0x8048686:	push   0x8048cff
   0x804868b:	call   0x8048440 <printf@plt>
   0x8048690:	add    esp,0x10
   0x8048693:	mov    eax,0x0
   0x8048698:	leave 
(gdb) x/s 0x8048cf9
0x8048cf9:	"flag{"
(gdb) x/s 0x8048cff
0x8048cff:	"wrong Header for %s\n"
(gdb) 
{% endhighlight %}


It looks like strstr() is looking for string "flag{", if it's not present in our input "[ebp+0x18]", (remember throughout the entire
binary, each section will reference our input argument as [ebp+0x18]) it prints "wrong Header" and does not return the desired '1'.

Anyway, let's continue.

{% highlight bash %}
(gdb) c
Continuing.
wrong Header for [=���s��X�

Program received signal SIGSEGV, Segmentation fault.
0xbffff0b0 in ?? ()
(gdb) 
{% endhighlight %}

Oh-uh, what happened here ? I thought we had the right header, why we didn't continue to section number 2?
Well, it's because we used a software breakpoint, if the unpacking routine encounters a software breakpoint, which is a 0xCC byte,
it will unpack wrongfully. I think that's pretty cool ! So from now on we will only be using a Hardware Breakpoints, with the exception
of the __start because GDB can't add hardware breakpoints if the program is not running :(.

# Section number 2

{% highlight bash %}
user@ubuntu:~/ctfs/poliCTF/re350$ readelf --header topack | grep -i entry
  Entry point address:               0x80484a0
user@ubuntu:~/ctfs/poliCTF/re350$ gdb -q ./topack
Reading symbols from ./topack...(no debugging symbols found)...done.
(gdb) b *0x80484a0
Breakpoint 1 at 0x80484a0
(gdb) run flag{AAAA}
Starting program: /home/user/ctfs/poliCTF/re350/topack flag{AAAA}

Breakpoint 1, 0x080484a0 in ?? ()
(gdb) hbreak *0x804869a
Hardware assisted breakpoint 2 at 0x804869a
(gdb) c
Continuing.

Breakpoint 2, 0x0804869a in ?? ()
(gdb) x/50i $eip
=> 0x804869a:	push   ebp
   0x804869b:	mov    ebp,esp
   0x804869d:	sub    esp,0x8
   0x80486a0:	sub    esp,0xc
   0x80486a3:	push   DWORD PTR [ebp+0x18]
   0x80486a6:	call   0x8048480 <strlen@plt>
   0x80486ab:	add    esp,0x10
   0x80486ae:	lea    edx,[eax-0x1]              <--- strlen() - 1
   0x80486b1:	mov    eax,DWORD PTR [ebp+0x18]   
   0x80486b4:	add    eax,edx
   0x80486b6:	movzx  eax,BYTE PTR [eax]        <--- last index char from input
   0x80486b9:	cmp    al,0x7d                   <--- compare if input[-1:] == 0x7d, '}'
   0x80486bb:	jne    0x80486c4                 <--- badboy
   0x80486bd:	mov    eax,0x1
   0x80486c2:	jmp    0x80486dc
   0x80486c4:	sub    esp,0x8
   0x80486c7:	push   DWORD PTR [ebp+0x18]
   0x80486ca:	push   0x8048d14
   0x80486cf:	call   0x8048440 <printf@plt>
   0x80486d4:	add    esp,0x10
   0x80486d7:	mov    eax,0x0
   0x80486dc:	leave  
   0x80486dd:	ret
(gdb) x/s 0x8048d14
0x8048d14:	"wrong End for %s\n"
(gdb) 
{% endhighlight %}

At section number 2 we see that the last character of our input is being compared with 0x7d, which is a closed-curly-brace.
If it's not, it prints "wrong End"...

# Section number 3

{% highlight bash %}
(gdb) hbreak *0x80486de
Hardware assisted breakpoint 3 at 0x80486de
(gdb) c
Continuing.

Breakpoint 3, 0x080486de in ?? ()
(gdb) x/50i $eip
=> 0x80486de:	push   ebp
   0x80486df:	mov    ebp,esp
   0x80486e1:	sub    esp,0x18
   0x80486e4:	sub    esp,0xc
   0x80486e7:	push   DWORD PTR [ebp+0x18]
   0x80486ea:	call   0x8048480 <strlen@plt>
   0x80486ef:	add    esp,0x10
   0x80486f2:	mov    DWORD PTR [ebp-0x10],eax
   0x80486f5:	mov    DWORD PTR [ebp-0xc],0x0
   0x80486fc:	jmp    0x804872b
   0x80486fe:	mov    edx,DWORD PTR [ebp-0xc]
   0x8048701:	mov    eax,DWORD PTR [ebp+0x18]
   0x8048704:	add    eax,edx
   0x8048706:	movzx  eax,BYTE PTR [eax]
   0x8048709:	test   al,al
   0x804870b:	jns    0x8048727
   0x804870d:	sub    esp,0x8
   0x8048710:	push   DWORD PTR [ebp+0x18]
   0x8048713:	push   0x8048d26
   0x8048718:	call   0x8048440 <printf@plt>
   0x804871d:	add    esp,0x10
   0x8048720:	mov    eax,0x0
   0x8048725:	jmp    0x8048738
   0x8048727:	add    DWORD PTR [ebp-0xc],0x1
   0x804872b:	mov    eax,DWORD PTR [ebp-0xc]
   0x804872e:	cmp    eax,DWORD PTR [ebp-0x10]
   0x8048731:	jl     0x80486fe
   0x8048733:	mov    eax,0x1
   0x8048738:	leave  
   0x8048739:	ret 
(gdb) x/s 0x8048d26
0x8048d26:	"Not ascii character in %s\n"
(gdb) 
{% endhighlight %}

Needless to say this section only checks if our input is composed of only printable characters.

# Section number 4

{% highlight bash %}
(gdb) hbreak *0x8048a42
Hardware assisted breakpoint 6 at 0x8048a42
(gdb) c
Continuing.

Breakpoint 6, 0x08048a42 in ?? ()
(gdb) x/100i $eip
=> 0x8048a42:	push   ebp
   0x8048a43:	mov    ebp,esp
   0x8048a45:	push   ebx
   0x8048a46:	sub    esp,0x14
   0x8048a49:	mov    DWORD PTR [ebp-0x10],0x6
   0x8048a50:	mov    DWORD PTR [ebp-0xc],0x1
   0x8048a57:	jmp    0x8048a93
   0x8048a59:	mov    eax,DWORD PTR [ebp-0xc]
   0x8048a5c:	add    eax,0x4
   0x8048a5f:	mov    edx,eax
   0x8048a61:	mov    eax,DWORD PTR [ebp+0x18]
   0x8048a64:	add    eax,edx
   0x8048a66:	movzx  eax,BYTE PTR [eax]
   0x8048a69:	movsx  ebx,al
   0x8048a6c:	sub    esp,0x4
   0x8048a6f:	push   DWORD PTR [ebp-0xc]
   0x8048a72:	push   0x36
   0x8048a77:	push   0x804873a
   0x8048a7c:	call   0x80485e0
   0x8048a81:	add    esp,0x10
   0x8048a84:	cmp    ebx,eax
   0x8048a86:	je     0x8048a8f
   0x8048a88:	mov    eax,0x0
   0x8048a8d:	jmp    0x8048aa0
   0x8048a8f:	add    DWORD PTR [ebp-0xc],0x1
   0x8048a93:	mov    eax,DWORD PTR [ebp-0xc]
   0x8048a96:	cmp    eax,DWORD PTR [ebp-0x10]
   0x8048a99:	jle    0x8048a59
   0x8048a9b:	mov    eax,0x1
   0x8048aa0:	mov    ebx,DWORD PTR [ebp-0x4]
   0x8048aa3:	leave  
   0x8048aa4:	ret 
{% endhighlight %}

Interesting... Here we see that it's calling the unpacking routine again... Well, we know the procedure, let's setup a hardware breakpoint
at 0x804873a. Don't forget to remove the previous hardware breakpoints for the sections we have already completed.

{% highlight bash %}
(gdb) hb *0x804873a
Hardware assisted breakpoint 7 at 0x804873a
(gdb) c
Continuing.

Breakpoint 7, 0x0804873a in ?? ()

(gdb) x/150i $eip
=> 0x804873a:	push   ebp
   0x804873b:	mov    ebp,esp
   0x804873d:	sub    esp,0x28
   0x8048740:	fild   DWORD PTR [ebp+0x18]
   0x8048743:	fld    QWORD PTR ds:0x8048e10
   0x8048749:	lea    esp,[esp-0x8]
   0x804874d:	fstp   QWORD PTR [esp]
   0x8048750:	lea    esp,[esp-0x8]
   0x8048754:	fstp   QWORD PTR [esp]
   0x8048757:	call   0x8048450 <pow@plt>
   0x804875c:	add    esp,0x10
   0x804875f:	fld    QWORD PTR ds:0x8048e18
   0x8048765:	fmulp  st(1),st
   0x8048767:	fstp   QWORD PTR [ebp-0x28]
   0x804876a:	fild   DWORD PTR [ebp+0x18]
   0x804876d:	fld    QWORD PTR ds:0x8048e20
   0x8048773:	lea    esp,[esp-0x8]
   0x8048777:	fstp   QWORD PTR [esp]
   0x804877a:	lea    esp,[esp-0x8]
   0x804877e:	fstp   QWORD PTR [esp]
   0x8048781:	call   0x8048450 <pow@plt>
   0x8048786:	add    esp,0x10
   0x8048789:	fld    QWORD PTR ds:0x8048e28
   0x804878f:	fmulp  st(1),st
   0x8048791:	fsubr  QWORD PTR [ebp-0x28]
   0x8048794:	fstp   QWORD PTR [ebp-0x28]
   0x8048797:	fild   DWORD PTR [ebp+0x18]
   0x804879a:	fld    QWORD PTR ds:0x8048e30
   0x80487a0:	lea    esp,[esp-0x8]
   0x80487a4:	fstp   QWORD PTR [esp]
   0x80487a7:	lea    esp,[esp-0x8]
   0x80487ab:	fstp   QWORD PTR [esp]
   0x80487ae:	call   0x8048450 <pow@plt>
   0x80487b3:	add    esp,0x10
   0x80487b6:	fld    QWORD PTR ds:0x8048e38
   0x80487bc:	fmulp  st(1),st
   0x80487be:	fadd   QWORD PTR [ebp-0x28]
   0x80487c1:	fstp   QWORD PTR [ebp-0x28]
   0x80487c4:	fild   DWORD PTR [ebp+0x18]
   0x80487c7:	fld    QWORD PTR ds:0x8048e40
   0x80487cd:	lea    esp,[esp-0x8]
   0x80487d1:	fstp   QWORD PTR [esp]
   0x80487d4:	lea    esp,[esp-0x8]
   0x80487d8:	fstp   QWORD PTR [esp]
   0x80487db:	call   0x8048450 <pow@plt>
   0x80487e0:	add    esp,0x10
   0x80487e3:	fld    QWORD PTR ds:0x8048e48
   0x80487e9:	fmulp  st(1),st
   0x80487eb:	fld    QWORD PTR [ebp-0x28]
   0x80487ee:	fsubp  st(1),st
   0x80487f0:	fild   DWORD PTR [ebp+0x18]
   0x80487f3:	fld    QWORD PTR ds:0x8048e50
   0x80487f9:	fmulp  st(1),st
   0x80487fb:	faddp  st(1),st
   0x80487fd:	fld    QWORD PTR ds:0x8048e58
   0x8048803:	faddp  st(1),st
   0x8048805:	fstp   DWORD PTR [ebp-0xc]
   0x8048808:	movss  xmm0,DWORD PTR [ebp-0xc]
   0x804880d:	cvttss2si eax,xmm0
   0x8048811:	leave  
   0x8048812:	ret  
{% endhighlight %}

Oh my god ! Who would have time to reverse all this ? Having dealt with floating point number and double extended precisions in python before
I know that sometimes results are not the same as in C so I didn't even wasted any time putting this into script. Instead let's look
at it from a high-level. If we take a look at the section 4 function 0x8048a42, we can see that it actually loops 6 times through
the unpacking function, only if cmp ebx, eax at 0x8048a84 is equal. So let's setup a Hardware Breakpoint there and just print the
content of the registers.

{% highlight bash %}
(gdb) hb *0x8048a84
Hardware assisted breakpoint 8 at 0x8048a84
(gdb) c
Continuing.

Breakpoint 8, 0x08048a84 in ?? ()
(gdb) info reg
eax            0x70	112
ecx            0x0	0
edx            0x4030201	67305985
ebx            0x41	65
esp            0xbffff060	0xbffff060
ebp            0xbffff078	0xbffff078
esi            0x0	0
edi            0x0	0
eip            0x8048a84	0x8048a84
eflags         0x10286	[ PF SF IF RF ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
(gdb) 
{% endhighlight %}

Ok, it looks like our first 'A' (0x41 in ebx) is compared with 0x70 ('p'). Cool, let's adjust our input and continue the loop.

{% highlight bash %}
eax            0x70	112
eax            0x61	97
eax            0x63	99
eax            0x6b	107
eax            0x65	101
eax            0x72	114
{% endhighlight %}

So the flag so far is flag{packer}...

# Section 5

{% highlight bash %}
(gdb) hb *0x80489a9
Hardware assisted breakpoint 9 at 0x80489a9
(gdb) c
Continuing.

Breakpoint 9, 0x080489a9 in ?? ()

(gdb) x/100i $eip
=> 0x80489a9:	push   ebp
   0x80489aa:	mov    ebp,esp
   0x80489ac:	push   edi
   0x80489ad:	push   esi
   0x80489ae:	push   ebx
   0x80489af:	sub    esp,0x6c
   0x80489b2:	lea    eax,[ebp-0x78]
   0x80489b5:	mov    ebx,0x8048d60
   0x80489ba:	mov    edx,0x16
   0x80489bf:	mov    edi,eax
   0x80489c1:	mov    esi,ebx
   0x80489c3:	mov    ecx,edx
   0x80489c5:	rep movs DWORD PTR es:[edi],DWORD PTR ds:[esi]
   0x80489c7:	mov    DWORD PTR [ebp-0x1c],0x0
   0x80489ce:	jmp    0x8048a2f
   0x80489d0:	mov    eax,DWORD PTR [ebp-0x1c]
   0x80489d3:	mov    edx,DWORD PTR [ebp+eax*8-0x74]
   0x80489d7:	mov    eax,DWORD PTR [ebp+eax*8-0x78]
   0x80489db:	mov    ecx,DWORD PTR [ebp-0x1c]
   0x80489de:	add    ecx,0xb
   0x80489e1:	mov    ebx,ecx
   0x80489e3:	mov    ecx,DWORD PTR [ebp+0x18]
   0x80489e6:	add    ecx,ebx
   0x80489e8:	movzx  ecx,BYTE PTR [ecx]
   0x80489eb:	movsx  ecx,cl
   0x80489ee:	sub    esp,0xc
   0x80489f1:	push   edx
   0x80489f2:	push   eax
   0x80489f3:	push   ecx
   0x80489f4:	push   0x34
   0x80489f9:	push   0x8048813
   0x80489fe:	call   0x80485e0
   0x8048a03:	add    esp,0x20
   0x8048a06:	test   eax,eax
   0x8048a08:	jne    0x8048a11
   0x8048a0a:	mov    eax,0x0
   0x8048a0f:	jmp    0x8048a3a
   0x8048a11:	mov    eax,DWORD PTR [ebp+0x18]
   0x8048a14:	add    eax,0x11
   0x8048a17:	movzx  eax,BYTE PTR [eax]
   0x8048a1a:	movsx  eax,al
   0x8048a1d:	and    eax,0x1
   0x8048a20:	test   eax,eax
   0x8048a22:	jne    0x8048a2b
   0x8048a24:	mov    eax,0x0
   0x8048a29:	jmp    0x8048a3a
   0x8048a2b:	add    DWORD PTR [ebp-0x1c],0x1
   0x8048a2f:	cmp    DWORD PTR [ebp-0x1c],0xa
   0x8048a33:	jle    0x80489d0
   0x8048a35:	mov    eax,0x1
   0x8048a3a:	lea    esp,[ebp-0xc]
   0x8048a3d:	pop    ebx
   0x8048a3e:	pop    esi
   0x8048a3f:	pop    edi
   0x8048a40:	pop    ebp
   0x8048a41:	ret
{% endhighlight %}

It's almost the same thing here except that on line 42, the code checks if the return from 0x8048813 is equal to 0 or not.
So this time we won't be given the values of the correct bytes. So let's see what's going on inside 0x8048813.

{% highlight bash %}
(gdb) hb *0x8048813
Hardware assisted breakpoint 10 at 0x8048813
(gdb) c
Continuing.

Breakpoint 10, 0x08048813 in ?? ()
(gdb) x/150i $eip
=> 0x8048813:	push   ebp
   0x8048814:	mov    ebp,esp
   0x8048816:	push   esi
   0x8048817:	push   ebx
   0x8048818:	sub    esp,0x30
   0x804881b:	mov    eax,DWORD PTR [ebp+0x1c]
   0x804881e:	mov    DWORD PTR [ebp-0x20],eax
   0x8048821:	mov    eax,DWORD PTR [ebp+0x20]
   0x8048824:	mov    DWORD PTR [ebp-0x1c],eax
   0x8048827:	fild   DWORD PTR [ebp+0x18]
   0x804882a:	lea    esp,[esp-0x8]
   0x804882e:	fstp   QWORD PTR [esp]
   0x8048831:	fld    QWORD PTR ds:0x8048e40
   0x8048837:	lea    esp,[esp-0x8]
   0x804883b:	fstp   QWORD PTR [esp]
   0x804883e:	call   0x8048450 <pow@plt>
   0x8048843:	add    esp,0x10
   0x8048846:	fld    QWORD PTR ds:0x8048e60
   0x804884c:	fxch   st(1)
   0x804884e:	fucomi st,st(1)
   0x8048850:	fstp   st(1)
   0x8048852:	jae    0x8048872
   0x8048854:	fnstcw WORD PTR [ebp-0x22]
   0x8048857:	movzx  eax,WORD PTR [ebp-0x22]
   0x804885b:	mov    ah,0xc
   0x804885d:	mov    WORD PTR [ebp-0x24],ax
   0x8048861:	fldcw  WORD PTR [ebp-0x24]
   0x8048864:	fistp  QWORD PTR [ebp-0x30]
   0x8048867:	fldcw  WORD PTR [ebp-0x22]
   0x804886a:	mov    eax,DWORD PTR [ebp-0x30]
   0x804886d:	mov    edx,DWORD PTR [ebp-0x2c]
   0x8048870:	jmp    0x80488ae
   0x8048872:	fld    QWORD PTR ds:0x8048e60
   0x8048878:	fsubrp st(1),st
   0x804887a:	fnstcw WORD PTR [ebp-0x22]
   0x804887d:	movzx  eax,WORD PTR [ebp-0x22]
   0x8048881:	mov    ah,0xc
   0x8048883:	mov    WORD PTR [ebp-0x24],ax
   0x8048887:	fldcw  WORD PTR [ebp-0x24]
   0x804888a:	fistp  QWORD PTR [ebp-0x30]
   0x804888d:	fldcw  WORD PTR [ebp-0x22]
   0x8048890:	mov    eax,DWORD PTR [ebp-0x30]
   0x8048893:	mov    edx,DWORD PTR [ebp-0x2c]
   0x8048896:	mov    ecx,eax
   0x8048898:	xor    ch,0x0
   0x804889b:	mov    DWORD PTR [ebp-0x38],ecx
   0x804889e:	mov    eax,edx
   0x80488a0:	xor    eax,0x80000000
   0x80488a5:	mov    DWORD PTR [ebp-0x34],eax
   0x80488a8:	mov    eax,DWORD PTR [ebp-0x38]
   0x80488ab:	mov    edx,DWORD PTR [ebp-0x34]
   0x80488ae:	shld   edx,eax,0x2
   0x80488b2:	shl    eax,0x2
   0x80488b5:	add    eax,0x15
   0x80488b8:	adc    edx,0x0
   0x80488bb:	mov    DWORD PTR [ebp-0x10],eax
   0x80488be:	mov    DWORD PTR [ebp-0xc],edx
   0x80488c1:	mov    eax,DWORD PTR [ebp-0x10]
   0x80488c4:	xor    eax,DWORD PTR [ebp-0x20]
   0x80488c7:	mov    ebx,eax
   0x80488c9:	mov    eax,DWORD PTR [ebp-0xc]
   0x80488cc:	xor    eax,DWORD PTR [ebp-0x1c]
   0x80488cf:	mov    esi,eax
   0x80488d1:	mov    eax,ebx
   0x80488d3:	or     eax,esi
   0x80488d5:	test   eax,eax
   0x80488d7:	sete   al
   0x80488da:	movzx  eax,al
   0x80488dd:	lea    esp,[ebp-0x8]
   0x80488e0:	pop    ebx
   0x80488e1:	pop    esi
   0x80488e2:	pop    ebp
   0x80488e3:	ret 
{% endhighlight %}

I will be honest, I spend some here, actually most of my time on this single function. We see that it takes input for pow() from
the rest of my flag values and as well as the initialized values of section 4's main function at line 21. After that depending on the
result at line 27 (fucomi st,st(1)) with "jump if above or equal" at line 29 performs different actions. After some trial and error
I noticed that if the result always has to be below that comparison. Let me show you what that comparison looks like:

{% highlight bash %}
(gdb) hb *0x804884e
Hardware assisted breakpoint 11 at 0x804884e
(gdb) c
Continuing.

Breakpoint 11, 0x0804884e in ?? ()
(gdb) info all-registers 
eax            0x1	1
ecx            0xbd2fffff	-1120927745
edx            0x0	0
ebx            0xb	11
esp            0xbfffef88	0xbfffef88
ebp            0xbfffefc0	0xbfffefc0
esi            0x8048db8	134516152
edi            0xbffff048	-1073745848
eip            0x804884e	0x804884e
eflags         0x10286	[ PF SF IF RF ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
st0            36893488147419103232	(raw 0x40408000000000000000)  <--- greater than st1, no good
st1            9223372036854775808	(raw 0x403e8000000000000000)
{% endhighlight %}

So here, we are in violation. My input is "A" so let's try one character less..

{% highlight bash %}
(gdb) run flag{packer@AAAAAA}
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user/ctfs/poliCTF/re350/topack flag{packer@AAAAAA}

Breakpoint 1, 0x080484a0 in ?? ()
(gdb) c
Continuing.

Breakpoint 9, 0x080489a9 in ?? ()
(gdb) 
Continuing.

Breakpoint 10, 0x08048813 in ?? ()
(gdb) 
Continuing.

Breakpoint 11, 0x0804884e in ?? ()
(gdb) info all-registers 
eax            0x1	1
ecx            0xbbffffff	-1140850689
edx            0x0	0
ebx            0xb	11
esp            0xbfffef88	0xbfffef88
ebp            0xbfffefc0	0xbfffefc0
esi            0x8048db8	134516152
edi            0xbffff048	-1073745848
eip            0x804884e	0x804884e
eflags         0x10286	[ PF SF IF RF ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
st0            18446744073709551616	(raw 0x403f8000000000000000)  <-- greater than st1, no good
st1            9223372036854775808	(raw 0x403e8000000000000000)
{% endhighlight %}

Looks like we are still in violation. Let's try one less, which is an question mark.

{% highlight bash %}
(gdb) run flag{packer?AAAAAA}
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user/ctfs/poliCTF/re350/topack flag{packer?AAAAAA}

Breakpoint 1, 0x080484a0 in ?? ()
(gdb) c
Continuing.

Breakpoint 9, 0x080489a9 in ?? ()
(gdb) c
Continuing.

Breakpoint 10, 0x08048813 in ?? ()
(gdb) c
Continuing.

Breakpoint 11, 0x0804884e in ?? ()
(gdb) info all-registers 
eax            0x1	1
ecx            0xbc0fffff	-1139802113
edx            0x0	0
ebx            0xb	11
esp            0xbfffef88	0xbfffef88
ebp            0xbfffefc0	0xbfffefc0
esi            0x8048db8	134516152
edi            0xbffff048	-1073745848
eip            0x804884e	0x804884e
eflags         0x10286	[ PF SF IF RF ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
st0            9223372036854775808	(raw 0x403e8000000000000000) <--- equal, OK
st1            9223372036854775808	(raw 0x403e8000000000000000)
{% endhighlight %}

Looks like we have a match. This means that our input needs to be computed from characters with value equal or less than the question mark, which is just some symbols and numbers.
We now know that the main function of section 5, checks for 11 characters and they all need to be numeric + some symbols.
Ok, but where does the real comparison is being worked at ? Well, it's outside this crazy looking floating numbers routine,
at line 42 address 0x8048a06 and also line number 51 address 0x8048a20. The first check at line 42, checks if the return of 0x8048813
different from 0. If it's a zero it's no good because it puts 0 in eax and exits and thus our section number 5 function will not
return the desired '1'. The check at line 51 address 0x8048a20 checks if all 11 characters past "flag{packer" has been evaluated.
The way I solved this is to add hardware breakpoints on those 2 locations and start brute-forcing my input.
After some tedious manual brute-forcing the input ended up being "flag{packer-15-4-?41="

# Section number 6

{% highlight bash %}
(gdb) hb *0x804890b
Hardware assisted breakpoint 12 at 0x804890b
(gdb) run flag{packer-15-4-?41=-AAAAAAAAA}
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user/ctfs/poliCTF/re350/topack flag{packer-15-4-?41=AAAAAAAAA}

Breakpoint 1, 0x080484a0 in ?? ()
(gdb) c
Continuing.

Breakpoint 12, 0x0804890b in ?? ()
(gdb) x/100i $eip
=> 0x804890b:	push   ebp
   0x804890c:	mov    ebp,esp
   0x804890e:	push   ebx
   0x804890f:	sub    esp,0x14
   0x8048912:	mov    DWORD PTR [ebp-0xc],0x8048d41
   0x8048919:	mov    eax,DWORD PTR [ebp+0x1c]
   0x804891c:	add    eax,0x16
   0x804891f:	mov    ebx,eax
   0x8048921:	sub    esp,0xc
   0x8048924:	push   DWORD PTR [ebp+0x18]
   0x8048927:	call   0x8048480 <strlen@plt>
   0x804892c:	add    esp,0x10
   0x804892f:	cmp    ebx,eax
   0x8048931:	jb     0x804893a
   0x8048933:	mov    eax,0x1
   0x8048938:	jmp    0x80489a4
   0x804893a:	mov    edx,DWORD PTR [ebp+0x1c]
   0x804893d:	mov    eax,DWORD PTR [ebp-0xc]
   0x8048940:	add    eax,edx
   0x8048942:	movzx  ecx,BYTE PTR [eax]
   0x8048945:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8048948:	lea    edx,[eax+0x14]
   0x804894b:	mov    eax,DWORD PTR [ebp+0x18]
   0x804894e:	add    eax,edx
   0x8048950:	movzx  eax,BYTE PTR [eax]
   0x8048953:	xor    eax,ecx
   0x8048955:	mov    BYTE PTR [ebp-0xd],al
   0x8048958:	mov    eax,DWORD PTR [ebp+0x1c]
   0x804895b:	add    eax,0x15
   0x804895e:	mov    edx,eax
   0x8048960:	mov    eax,DWORD PTR [ebp+0x18]
   0x8048963:	add    eax,edx
   0x8048965:	movzx  eax,BYTE PTR [eax]
   0x8048968:	mov    BYTE PTR [ebp-0xe],al
   0x804896b:	movzx  eax,BYTE PTR [ebp-0xd]
   0x804896f:	cmp    al,BYTE PTR [ebp-0xe]
   0x8048972:	je     0x804897b
   0x8048974:	mov    eax,0x0
   0x8048979:	jmp    0x80489a4
   0x804897b:	mov    eax,DWORD PTR [ebp+0x1c]
   0x804897e:	add    eax,0x1
   0x8048981:	sub    esp,0x8
   0x8048984:	push   eax
   0x8048985:	push   DWORD PTR [ebp+0x18]
   0x8048988:	push   0xdeadb00b
   0x804898d:	push   0xdeadb00b
   0x8048992:	push   0xdeadb00b
   0x8048997:	push   0xdeadb00b
   0x804899c:	call   0x804890b
   0x80489a1:	add    esp,0x20
   0x80489a4:	mov    ebx,DWORD PTR [ebp-0x4]
   0x80489a7:	leave  
   0x80489a8:	ret
{% endhighlight %}

We can see that this is a recursive function, on lines 14-27 this function takes each character from our input starting from the 22nd byte until the end of the input and it calls itself at line 62.
At lines 49 and 50 it checks if the character currently being checks is correct or not, otherwise continues to line 51 where it fails.
So let's add a breakpoint at 0x804896f and check the compared values.

{% highlight bash %}
(gdb) hb *0x804896f
Hardware assisted breakpoint 13 at 0x804896f
(gdb) c
Continuing.

Breakpoint 13, 0x0804896f in ?? ()
(gdb) info reg
eax            0x2d	45
ecx            0x10	16
edx            0x15	21
ebx            0x16	22
esp            0xbffff040	0xbffff040
ebp            0xbffff058	0xbffff058
esi            0x0	0
edi            0x0	0
eip            0x804896f	0x804896f
eflags         0x10286	[ PF SF IF RF ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
(gdb) x/bx $ebp-0xe
0xbffff04a:	0x41
(gdb) 
{% endhighlight %}

0x2d is a dash "-" and our value in [ebp-0xe] "A". Good, just an easy comparison, however I found that I needed to restart the process
after each time I find the correct next byte...

{% highlight bash %}
(gdb) x/bx $ebp-0xe
0xbffff04a:	0x2d

(gdb) x/bx $ebp-0xe
0xbffff00a:	0x69

(gdb) x/bx $ebp-0xe
0xbffff00a:	0x6e

(gdb) x/bx $ebp-0xe
0xbfffef8a:	0x2d

(gdb) x/bx $ebp-0xe
0xbfffef8a:	0x74

(gdb) x/bx $ebp-0xe
0xbfffef0a:	0x68

(gdb) x/bx $ebp-0xe
0xbfffef0a:	0x33

(gdb) x/bx $ebp-0xe
0xbfffee8a:	0x2d

(gdb) x/bx $ebp-0xe
0xbfffee8a:	0x34

(gdb) x/bx $ebp-0xe
0xbfffee0a:	0x73

(gdb) x/bx $ebp-0xe
0xbfffee0a:	0x73

{% endhighlight %}

So far the flag is "flag{packer-15-4-?41=-in-th3-4ss", of to the last section, Section number 7.

# Section number 7

{% highlight bash %}
(gdb) run flag{packer-15-4-?41=-in-th3-4ssAAAAAAAAAA
Starting program: /home/user/ctfs/poliCTF/re350/topack flag{packer-15-4-?41=-in-th3-4ssAAAAAAAAAA

Breakpoint 1, 0x080484a0 in ?? ()
(gdb) hb *0x80488e4
Hardware assisted breakpoint 14 at 0x80488e4
(gdb) c
Continuing.
wrong End for flag{packer-15-4-?41=-in-th3-4ssAAAAAAAAAA

Breakpoint 14, 0x080488e4 in ?? ()
(gdb) x/100i $eip
=> 0x80488e4:	push   ebp
   0x80488e5:	mov    ebp,esp
   0x80488e7:	sub    esp,0x8
   0x80488ea:	sub    esp,0xc
   0x80488ed:	push   DWORD PTR [ebp+0x18]
   0x80488f0:	call   0x8048480 <strlen@plt>
   0x80488f5:	add    esp,0x10
   0x80488f8:	cmp    eax,0x21
   0x80488fb:	jne    0x8048904
   0x80488fd:	mov    eax,0x1
   0x8048902:	jmp    0x8048909
   0x8048904:	mov    eax,0x0
   0x8048909:	leave  
   0x804890a:	ret  
{% endhighlight %}

Thank god this is a simple one, it just checks if the length of our input is equal 33 chars. So if the input of our flag so far
"flag{packer-15-4-?41=-in-th3-4ss" is 32 and we know it needs to end with "}", I think we have the flag.

{% highlight bash %}

user@ubuntu:~/ctfs/poliCTF/re350$ ./topack flag{packer-15-4-?41=-in-th3-4ss}
You got the flag: flag{packer-15-4-?41=-in-th3-4ss}
user@ubuntu:~/ctfs/poliCTF/re350$ 

{% endhighlight %}

Sorry for the lengthy write-up and thank you for reading.

## Links

* <http://polictf.it/>

