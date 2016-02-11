---
layout: post
title: ASIS 2015 CTF KeyLead Reverse Engineering 150
category: Reverse Engineering
tags: RE ASIS
comments: true
---

**Points:** 150
**Solves:** 123
**Category:** Reverse Engineering
**Description:**

> Find the flag in [this]({{site.url}}/assets/keylead_068128f7cacc63375c9cbab8114e15da) file.

## Write-up

Another 64 bit ELF binary, stripped.

	$ file keylead
	keylead: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, BuildID[sha1]=0xa7a4d5c1237aa5ff9380f8359cc80d5372ec711c, stripped

Let's run the binary first.

{% highlight bash %}
# ./keylead 
hi all ----------------------
Welcome to dice game!
You have to roll 5 dices and get 3, 1, 3, 3, 7 in order.
Press enter to roll.

You rolled 6, 3, 6, 1, 5.
You DID NOT roll as I said!
Bye bye~
$
{% endhighlight %}

Let's see how our roll gets generated.  
Main function:

{% highlight bash %}
(gdb) x/300i 0x400e6e
   0x400e6e:	push   rbp
   0x400e6f:	mov    rbp,rsp
   0x400e72:	sub    rsp,0x20
   0x400e76:	mov    edi,0x401198
   0x400e7b:	call   0x400540 <puts@plt>
   0x400e80:	mov    edi,0x4011b6
   0x400e85:	call   0x400540 <puts@plt>
   0x400e8a:	mov    edi,0x4011d0
   0x400e8f:	call   0x400540 <puts@plt>
   0x400e94:	mov    edi,0x401209
   0x400e99:	call   0x400540 <puts@plt>
   0x400e9e:	call   0x400580 <getchar@plt>
   0x400ea3:	mov    BYTE PTR [rbp-0x1],al
   0x400ea6:	mov    edi,0x0
   0x400eab:	call   0x4005a0 <time@plt>
   0x400eb0:	mov    edi,eax
   0x400eb2:	call   0x400570 <srand@plt>
   0x400eb7:	mov    edi,0x0
   0x400ebc:	call   0x4005a0 <time@plt>
   0x400ec1:	mov    DWORD PTR [rbp-0x8],eax
   0x400ec4:	call   0x4005b0 <rand@plt>
{% endhighlight %}

In the first chunk of block code, we see the function prolog. The initial text is also being displayed on stdout.
After that we see the time(NULL) is being used and the return is used in srand for the rand following time(NULL) again.

{% highlight bash %}
   0x400ec9:	mov    ecx,eax
   0x400ecb:	mov    edx,0x2aaaaaab
   0x400ed0:	mov    eax,ecx
   0x400ed2:	imul   edx
   0x400ed4:	mov    eax,ecx
   0x400ed6:	sar    eax,0x1f
   0x400ed9:	sub    edx,eax
   0x400edb:	mov    eax,edx
   0x400edd:	add    eax,eax
   0x400edf:	add    eax,edx
   0x400ee1:	add    eax,eax
   0x400ee3:	sub    ecx,eax
   0x400ee5:	mov    edx,ecx
   0x400ee7:	lea    eax,[rdx+0x1]
   0x400eea:	mov    DWORD PTR [rbp-0xc],eax
   0x400eed:	call   0x4005b0 <rand@plt>
   0x400ef2:	mov    ecx,eax
   0x400ef4:	mov    edx,0x2aaaaaab
   0x400ef9:	mov    eax,ecx
   0x400efb:	imul   edx
   0x400efd:	mov    eax,ecx
   0x400eff:	sar    eax,0x1f
   0x400f02:	sub    edx,eax
   0x400f04:	mov    eax,edx
   0x400f06:	add    eax,eax
   0x400f08:	add    eax,edx
   0x400f0a:	add    eax,eax
   0x400f0c:	sub    ecx,eax
   0x400f0e:	mov    edx,ecx
   0x400f10:	lea    eax,[rdx+0x1]
   0x400f13:	mov    DWORD PTR [rbp-0x10],eax
   0x400f16:	call   0x4005b0 <rand@plt>
   0x400f1b:	mov    ecx,eax
   0x400f1d:	mov    edx,0x2aaaaaab
   0x400f22:	mov    eax,ecx
   0x400f24:	imul   edx
   0x400f26:	mov    eax,ecx
   0x400f28:	sar    eax,0x1f
   0x400f2b:	sub    edx,eax
   0x400f2d:	mov    eax,edx
   0x400f2f:	add    eax,eax
   0x400f31:	add    eax,edx
   0x400f33:	add    eax,eax
   0x400f35:	sub    ecx,eax
   0x400f37:	mov    edx,ecx
   0x400f39:	lea    eax,[rdx+0x1]
   0x400f3c:	mov    DWORD PTR [rbp-0x14],eax
   0x400f3f:	call   0x4005b0 <rand@plt>
   0x400f44:	mov    ecx,eax
   0x400f46:	mov    edx,0x2aaaaaab
   0x400f4b:	mov    eax,ecx
   0x400f4d:	imul   edx
   0x400f4f:	mov    eax,ecx
   0x400f51:	sar    eax,0x1f
   0x400f54:	sub    edx,eax
   0x400f56:	mov    eax,edx
   0x400f58:	add    eax,eax
   0x400f5a:	add    eax,edx
   0x400f5c:	add    eax,eax
   0x400f5e:	sub    ecx,eax
   0x400f60:	mov    edx,ecx
   0x400f62:	lea    eax,[rdx+0x1]
   0x400f65:	mov    DWORD PTR [rbp-0x18],eax
   0x400f68:	call   0x4005b0 <rand@plt>
   0x400f6d:	mov    ecx,eax
   0x400f6f:	mov    edx,0x2aaaaaab
   0x400f74:	mov    eax,ecx
   0x400f76:	imul   edx
   0x400f78:	mov    eax,ecx
   0x400f7a:	sar    eax,0x1f
   0x400f7d:	sub    edx,eax
   0x400f7f:	mov    eax,edx
   0x400f81:	add    eax,eax
   0x400f83:	add    eax,edx
   0x400f85:	add    eax,eax
   0x400f87:	sub    ecx,eax
   0x400f89:	mov    edx,ecx
   0x400f8b:	lea    eax,[rdx+0x1]
   0x400f8e:	mov    DWORD PTR [rbp-0x1c],eax
   0x400f91:	mov    edi,DWORD PTR [rbp-0x1c]
   0x400f94:	mov    esi,DWORD PTR [rbp-0x18]
   0x400f97:	mov    ecx,DWORD PTR [rbp-0x14]
   0x400f9a:	mov    edx,DWORD PTR [rbp-0x10]
   0x400f9d:	mov    eax,DWORD PTR [rbp-0xc]
   0x400fa0:	mov    r9d,edi
   0x400fa3:	mov    r8d,esi
   0x400fa6:	mov    esi,eax
   0x400fa8:	mov    edi,0x401220
   0x400fad:	mov    eax,0x0
   0x400fb2:	call   0x400550 <printf@plt>
(gdb) x/s 0x401220
0x401220:	 "You rolled %d, %d, %d, %d, %d.\n"
(gdb) 
{% endhighlight %}

Well after all that we know rand is being called 5 times for each of our rolls.
Following is the comparison of our roll with "3 1 3 3 7"

{% highlight bash %}
   0x400fb7:	cmp    DWORD PTR [rbp-0xc],0x3     <==== First compare
   0x400fbb:	jne    0x4010f3
   0x400fc1:	mov    edi,0x0
   0x400fc6:	call   0x4005a0 <time@plt>
   0x400fcb:	mov    rdx,rax
   0x400fce:	mov    eax,DWORD PTR [rbp-0x8]
   0x400fd1:	cdqe   
   0x400fd3:	sub    rdx,rax
   0x400fd6:	mov    rax,rdx
   0x400fd9:	cmp    rax,0x2
   0x400fdd:	jle    0x400ff3
   0x400fdf:	mov    edi,0x401240
   0x400fe4:	call   0x400540 <puts@plt>
   0x400fe9:	mov    eax,0xffffffff
   0x400fee:	jmp    0x40110d
   0x400ff3:	cmp    DWORD PTR [rbp-0x10],0x1  <==== Second compare
   0x400ff7:	jne    0x4010f1
   0x400ffd:	mov    edi,0x0
   0x401002:	call   0x4005a0 <time@plt>
   0x401007:	mov    rdx,rax
   0x40100a:	mov    eax,DWORD PTR [rbp-0x8]
   0x40100d:	cdqe   
   0x40100f:	sub    rdx,rax
   0x401012:	mov    rax,rdx
   0x401015:	cmp    rax,0x2
   0x401019:	jle    0x40102f
   0x40101b:	mov    edi,0x401240
   0x401020:	call   0x400540 <puts@plt>
   0x401025:	mov    eax,0xffffffff
   0x40102a:	jmp    0x40110d
   0x40102f:	cmp    DWORD PTR [rbp-0x14],0x3   <=== Third compare
   0x401033:	jne    0x4010ef
   0x401039:	mov    edi,0x0
   0x40103e:	call   0x4005a0 <time@plt>
   0x401043:	mov    rdx,rax
   0x401046:	mov    eax,DWORD PTR [rbp-0x8]
   0x401049:	cdqe   
   0x40104b:	sub    rdx,rax
   0x40104e:	mov    rax,rdx
   0x401051:	cmp    rax,0x2
   0x401055:	jle    0x40106b
   0x401057:	mov    edi,0x401240
   0x40105c:	call   0x400540 <puts@plt>
   0x401061:	mov    eax,0xffffffff
   0x401066:	jmp    0x40110d
   0x40106b:	cmp    DWORD PTR [rbp-0x18],0x3   <=== Fourth compare
   0x40106f:	jne    0x4010ed
   0x401071:	mov    edi,0x0
   0x401076:	call   0x4005a0 <time@plt>
   0x40107b:	mov    rdx,rax
   0x40107e:	mov    eax,DWORD PTR [rbp-0x8]
   0x401081:	cdqe   
   0x401083:	sub    rdx,rax
   0x401086:	mov    rax,rdx
   0x401089:	cmp    rax,0x2
   0x40108d:	jle    0x4010a0
   0x40108f:	mov    edi,0x401240
   0x401094:	call   0x400540 <puts@plt>
   0x401099:	mov    eax,0xffffffff
   0x40109e:	jmp    0x40110d
   0x4010a0:	cmp    DWORD PTR [rbp-0x1c],0x7   <=== Fifth compare
   0x4010a4:	jne    0x4010eb
   0x4010a6:	mov    edi,0x0
   0x4010ab:	call   0x4005a0 <time@plt>
   0x4010b0:	mov    rdx,rax
   0x4010b3:	mov    eax,DWORD PTR [rbp-0x8]
   0x4010b6:	cdqe   
   0x4010b8:	sub    rdx,rax
   0x4010bb:	mov    rax,rdx
   0x4010be:	cmp    rax,0x2
   0x4010c2:	jle    0x4010d5
   0x4010c4:	mov    edi,0x401240
   0x4010c9:	call   0x400540 <puts@plt>
   0x4010ce:	mov    eax,0xffffffff
   0x4010d3:	jmp    0x40110d
   0x4010d5:	mov    edi,0x401250
   0x4010da:	call   0x400540 <puts@plt>
   0x4010df:	call   0x4006b6
   0x4010e4:	mov    eax,0x0
   0x4010e9:	jmp    0x40110d
   0x4010eb:	jmp    0x4010f4
   0x4010ed:	jmp    0x4010f4
   0x4010ef:	jmp    0x4010f4
   0x4010f1:	jmp    0x4010f4
   0x4010f3:	nop
   0x4010f4:	mov    edi,0x40127e
   0x4010f9:	call   0x400540 <puts@plt>
   0x4010fe:	mov    edi,0x40129a
   0x401103:	call   0x400540 <puts@plt>
   0x401108:	mov    eax,0xffffffff
   0x40110d:	leave  
   0x40110e:	ret       
{% endhighlight %}

Pretty easy, if the compare fails it jump to 0x4010f3 which prints the fail message and exit.
Well, let's patch it. I used edb, all we have to do is find the cmp and patch the JNE instruction with NOPs after it, as shown on the screenshot.
![image]({{site.url}}/assets/ScreenShot20150512613.png)

After we are done patching all 5 JNE with NOPs we can dump the modified binary as shown below.
![image]({{site.url}}/assets/ScreenShot20150512616.png)

Let's test it out...

{% highlight bash %}
$ chmod +x keylead_patched
$ ./keylead_patched
hi all ----------------------
Welcome to dice game!
You have to roll 5 dices and get 3, 1, 3, 3, 7 in order.
Press enter to roll.

You rolled 6, 5, 6, 5, 5.
You rolled as I said! I'll give you the flag.
ASIS{1fc1089e328eaf737c882ca0b10fcfe6}
$
{% endhighlight %}

Great it works ! However let's take a look at another functionality, which might be the reason why this challenge is rated 150 for such an easy task...
If we go back to the initial call to time at 0x400ebc, we see that the result is stored in rbp-0x8.

{% highlight bash %}
   0x400ebc:	call   0x4005a0 <time@plt>
   0x400ec1:	mov    DWORD PTR [rbp-0x8],eax
{% endhighlight %}

Now if we pay attention, after each dice compare, there is another call to time the result is subtracted from rbp-0x8 which is the result of the initial call to time and compared to 0x2.

{% highlight bash %}
   0x400fb7:	cmp    DWORD PTR [rbp-0xc],0x3     <==== First compare
   0x400fbb:	jne    0x4010f3
   0x400fc1:	mov    edi,0x0
   0x400fc6:	call   0x4005a0 <time@plt>   <--- time(null) again
   0x400fcb:	mov    rdx,rax
   0x400fce:	mov    eax,DWORD PTR [rbp-0x8]
   0x400fd1:	cdqe   
   0x400fd3:	sub    rdx,rax   <--- initial result of time() - the result of the above time()
   0x400fd6:	mov    rax,rdx
   0x400fd9:	cmp    rax,0x2  <-- result of above time() - time() is compared to 2.
   0x400fdd:	jle    0x400ff3   <--- if result < 2, jump 0x400ff3 right here | which is past the puts call.
   0x400fdf:	mov    edi,0x401240                                            |
   0x400fe4:	call   0x400540 <puts@plt>                                     |
   0x400fe9:	mov    eax,0xffffffff                                          |
   0x400fee:	jmp    0x40110d                                                |
   0x400ff3:	cmp    DWORD PTR [rbp-0x10],0x1 <-------------------------------
{% endhighlight %}

Let's see what the puts call is.

{% highlight bash %}
   0x400fdf:	mov    edi,0x401240         
   0x400fe4:	call   0x400540 <puts@plt>  
   0x400fe9:	mov    eax,0xffffffff          
   0x400fee:	jmp    0x40110d
(gdb) x/s 0x401240
0x401240:	 "No cheat!"
(gdb) x/10i 0x40110d
   0x40110d:	leave  
   0x40110e:	ret
{% endhighlight %}

So, if (the time() - time()) > 2, print "No cheat!" and exit. Looks like this is a little bit of anti-debugging :).
And this is implemented after each dice compare. Well, we don't care about it since we patched it and executed the patched binary outside the debugger
but I hope somebody learned something.

Thanks for reading.

## Links

* <http://www.asis-ctf.ir/challenges/>

