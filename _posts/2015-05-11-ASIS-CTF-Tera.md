---
layout: post
title: ASIS 2015 CTF Tera Reverse Engineering 100
category: Reverse Engineering
tags: RE ASIS
---

**Points:** 100
**Solves:** 58
**Category:** Reverse Engineering
**Description:**

> Be patient and find the flag in [this]({{site.url}}/assets/tera_85021482a68d6ed21892ea99b84f13f3) file.

## Write-up

	# file tera 
	tera: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, BuildID[sha1]=0x9629b13ca5a7969979a1e01bd0f061eb6bdf0726, stripped

Let's take a look at the main function.

{% highlight bash %}
(gdb) x/250i 0x400f19
   0x400f19:	push   rbp
   0x400f1a:	mov    rbp,rsp
   0x400f1d:	push   r14
   0x400f1f:	push   r13
   0x400f21:	push   r12
   0x400f23:	push   rbx
   0x400f24:	sub    rsp,0x2330
{% endhighlight %}

Function prolog

{% highlight bash %}
   0x400f2b:	movabs rax,0x1f40001809e0
   0x400f35:	mov    QWORD PTR [rbp-0x38],rax
   0x400f39:	lea    rax,[rbp-0x1c0]
   0x400f40:	mov    esi,0x401480
   0x400f45:	mov    edx,0x26
   0x400f4a:	mov    rdi,rax
   0x400f4d:	mov    rcx,rdx
   0x400f50:	rep movs QWORD PTR es:[rdi],QWORD PTR ds:[rsi]
   0x400f53:	mov    DWORD PTR [rbp-0x3c],0x26
   0x400f5a:	lea    rax,[rbp-0x250]
   0x400f61:	mov    edx,0x4015c0
   0x400f66:	mov    ecx,0x10
   0x400f6b:	mov    rdi,rax
   0x400f6e:	mov    rsi,rdx
   0x400f71:	rep movs QWORD PTR es:[rdi],QWORD PTR ds:[rsi]
   0x400f74:	mov    rdx,rsi
   0x400f77:	mov    rax,rdi
   0x400f7a:	movzx  ecx,WORD PTR [rdx]
   0x400f7d:	mov    WORD PTR [rax],cx
   0x400f80:	lea    rax,[rax+0x2]
   0x400f84:	lea    rdx,[rdx+0x2]
   0x400f88:	movzx  ecx,BYTE PTR [rdx]
   0x400f8b:	mov    BYTE PTR [rax],cl
   0x400f8d:	lea    rax,[rax+0x1]
   0x400f91:	lea    rdx,[rdx+0x1]
   0x400f95:	mov    rax,QWORD PTR [rip+0x200fb4]        # 0x601f50 <stdout>
   0x400f9c:	mov    esi,0x0
   0x400fa1:	mov    rdi,rax
   0x400fa4:	call   0x400ad0 <setbuf@plt>
   0x400fa9:	mov    DWORD PTR [rbp-0x24],0x0
   0x400fb0:	jmp    0x400fd3
   0x400fb2:	mov    eax,DWORD PTR [rbp-0x24]
   0x400fb5:	add    eax,eax
   0x400fb7:	cdqe   
   0x400fb9:	movzx  eax,BYTE PTR [rbp+rax*1-0x250]
   0x400fc1:	mov    edx,eax
   0x400fc3:	mov    eax,DWORD PTR [rbp-0x24]
   0x400fc6:	cdqe   
   0x400fc8:	mov    BYTE PTR [rbp+rax*1-0x2a0],dl
   0x400fcf:	add    DWORD PTR [rbp-0x24],0x1
   0x400fd3:	cmp    DWORD PTR [rbp-0x24],0x40
   0x400fd7:	jle    0x400fb2
   0x400fd9:	lea    rdx,[rbp-0x12a0]
   0x400fe0:	mov    eax,0x0
   0x400fe5:	mov    ecx,0x200
   0x400fea:	mov    rdi,rdx
   0x400fed:	rep stos QWORD PTR es:[rdi],rax
   0x400ff0:	mov    BYTE PTR [rbp-0x129f],0x2f
   0x400ff7:	mov    BYTE PTR [rbp-0x129d],0x74
   0x400ffe:	mov    BYTE PTR [rbp-0x129b],0x6d
   0x401005:	mov    BYTE PTR [rbp-0x1299],0x70
   0x40100c:	mov    BYTE PTR [rbp-0x1297],0x2f
   0x401013:	mov    BYTE PTR [rbp-0x1295],0x2e
   0x40101a:	mov    BYTE PTR [rbp-0x1293],0x74
   0x401021:	mov    BYTE PTR [rbp-0x1291],0x65
   0x401028:	mov    BYTE PTR [rbp-0x128f],0x72
   0x40102f:	mov    BYTE PTR [rbp-0x128d],0x61
   0x401036:	mov    BYTE PTR [rbp-0x128b],0xa
   0x40103d:	mov    DWORD PTR [rbp-0x28],0x0
   0x401044:	jmp    0x401068
   0x401046:	mov    eax,DWORD PTR [rbp-0x28]
   0x401049:	add    eax,eax
   0x40104b:	add    eax,0x1
   0x40104e:	cdqe   
   0x401050:	movzx  edx,BYTE PTR [rbp+rax*1-0x12a0]
   0x401058:	mov    eax,DWORD PTR [rbp-0x28]
   0x40105b:	cdqe   
   0x40105d:	mov    BYTE PTR [rbp+rax*1-0x22a0],dl
   0x401064:	add    DWORD PTR [rbp-0x28],0x1
   0x401068:	cmp    DWORD PTR [rbp-0x28],0x9
   0x40106c:	jle    0x401046
   0x40106e:	mov    BYTE PTR [rbp-0x2296],0x0
   0x401075:	call   0x400b30 <curl_easy_init@plt>
{% endhighlight %}

It looks like it uses libcurl to download a file from somewhere.
We can see the file it downloads as argument of libcurl in RDI register.

{% highlight bash %}
(gdb) x/s $rdi
0x7fffffffe0e0:	 "http://darksky.slac.stanford.edu/simulations/ds14_a/ds14_a_1.0000"
(gdb) 
{% endhighlight %}

{% highlight bash %}
   0x40107a:	mov    QWORD PTR [rbp-0x48],rax
   0x40107e:	cmp    QWORD PTR [rbp-0x48],0x0
   0x401083:	je     0x4012a5
   0x401089:	mov    rax,rsp
   0x40108c:	mov    r12,rax
   0x40108f:	mov    edi,0x4013d8
   0x401094:	call   0x400a40 <puts@plt>
   0x401099:	lea    rax,[rbp-0x2340]
   0x4010a0:	mov    esi,0x401680
   0x4010a5:	mov    edx,0x13
   0x4010aa:	mov    rdi,rax
   0x4010ad:	mov    rcx,rdx
   0x4010b0:	rep movs QWORD PTR es:[rdi],QWORD PTR ds:[rsi]
   0x4010b3:	lea    rax,[rbp-0x22a0]
   0x4010ba:	mov    esi,0x4013fa
   0x4010bf:	mov    rdi,rax
   0x4010c2:	call   0x400a80 <fopen@plt>
{% endhighlight %}

It puts the downloaded file in /tmp/.tera

{% highlight bash %}
(gdb) x/s 0x4013fa
0x4013fa:	 "wb"
(gdb) x/s $rbp-0x22a0
0x7fffffffc0e0:	 "/tmp/.tera"
(gdb)
{% endhighlight %}
{% highlight bash %}
   0x4010c7:	mov    QWORD PTR [rbp-0x50],rax
   0x4010cb:	mov    rdx,QWORD PTR [rbp-0x48]
   0x4010cf:	lea    rax,[rbp-0x88]
   0x4010d6:	mov    rcx,rdx
   0x4010d9:	mov    edx,0x400d10
   0x4010de:	mov    esi,0x0
   0x4010e3:	mov    rdi,rax
   0x4010e6:	call   0x400aa0 <pthread_create@plt>
   0x4010eb:	mov    DWORD PTR [rbp-0x54],eax
   0x4010ee:	cmp    DWORD PTR [rbp-0x54],0x0
   0x4010f2:	je     0x40111f
   0x4010f4:	mov    rax,QWORD PTR [rip+0x200e45]        # 0x601f40 <stderr>
   0x4010fb:	mov    edx,DWORD PTR [rbp-0x54]
   0x4010fe:	mov    esi,0x401400
   0x401103:	mov    rdi,rax
   0x401106:	mov    eax,0x0
   0x40110b:	call   0x400b40 <fprintf@plt>
   0x401110:	mov    ebx,0x0
   0x401115:	mov    eax,0x0
   0x40111a:	jmp    0x40129b
   0x40111f:	mov    DWORD PTR [rbp-0x58],0x2712
   0x401126:	mov    ecx,DWORD PTR [rbp-0x58]
   0x401129:	lea    rdx,[rbp-0x2a0]
   0x401130:	mov    rax,QWORD PTR [rbp-0x48]
   0x401134:	mov    esi,ecx
   0x401136:	mov    rdi,rax
   0x401139:	mov    eax,0x0
   0x40113e:	call   0x400af0 <curl_easy_setopt@plt>
   0x401143:	mov    DWORD PTR [rbp-0x5c],0x4e2b
   0x40114a:	mov    ecx,DWORD PTR [rbp-0x5c]
   0x40114d:	mov    rax,QWORD PTR [rbp-0x48]
   0x401151:	mov    edx,0x400cd6
   0x401156:	mov    esi,ecx
   0x401158:	mov    rdi,rax
   0x40115b:	mov    eax,0x0
   0x401160:	call   0x400af0 <curl_easy_setopt@plt>
   0x401165:	mov    DWORD PTR [rbp-0x60],0x2711
   0x40116c:	mov    ecx,DWORD PTR [rbp-0x60]
   0x40116f:	mov    rdx,QWORD PTR [rbp-0x50]
   0x401173:	mov    rax,QWORD PTR [rbp-0x48]
   0x401177:	mov    esi,ecx
   0x401179:	mov    rdi,rax
   0x40117c:	mov    eax,0x0
   0x401181:	call   0x400af0 <curl_easy_setopt@plt>
   0x401186:	mov    rax,QWORD PTR [rbp-0x48]
   0x40118a:	mov    rdi,rax
   0x40118d:	call   0x400a60 <curl_easy_perform@plt>
   0x401192:	mov    DWORD PTR [rbp-0x64],eax
   0x401195:	mov    rax,QWORD PTR [rbp-0x48]
   0x401199:	mov    rdi,rax
   0x40119c:	call   0x400b10 <curl_easy_cleanup@plt>
   0x4011a1:	mov    rax,QWORD PTR [rbp-0x50]
   0x4011a5:	mov    rdi,rax
   0x4011a8:	call   0x400b00 <fclose@plt>
{% endhighlight %}

We don't really care about the above code. It's just some cleanup, file close and error checking.

{% highlight bash %}
   0x4011ad:	lea    rax,[rbp-0x22a0]
   0x4011b4:	mov    esi,0x4013c0
   0x4011b9:	mov    rdi,rax
   0x4011bc:	call   0x400a80 <fopen@plt>
   0x4011c1:	mov    QWORD PTR [rbp-0x70],rax
   0x4011c5:	mov    rax,QWORD PTR [rbp-0x38]
   0x4011c9:	lea    rdx,[rax-0x1]
   0x4011cd:	mov    QWORD PTR [rbp-0x78],rdx
   0x4011d1:	mov    rdx,rax
   0x4011d4:	mov    QWORD PTR [rbp-0x2350],rdx
   0x4011db:	mov    QWORD PTR [rbp-0x2348],0x0
   0x4011e6:	mov    rdx,rax
   0x4011e9:	mov    r13,rdx
   0x4011ec:	mov    r14d,0x0
   0x4011f2:	mov    rdx,rax
   0x4011f5:	mov    eax,0x10
   0x4011fa:	sub    rax,0x1
   0x4011fe:	add    rax,rdx
   0x401201:	mov    esi,0x10
   0x401206:	mov    edx,0x0
   0x40120b:	div    rsi
   0x40120e:	imul   rax,rax,0x10
   0x401212:	sub    rsp,rax
   0x401215:	mov    rax,rsp
   0x401218:	add    rax,0x0
   0x40121c:	mov    QWORD PTR [rbp-0x80],rax
   0x401220:	mov    rdx,QWORD PTR [rbp-0x38]
   0x401224:	mov    rax,QWORD PTR [rbp-0x80]
   0x401228:	mov    rcx,QWORD PTR [rbp-0x70]
   0x40122c:	mov    esi,0x1
   0x401231:	mov    rdi,rax
   0x401234:	call   0x400ae0 <fread@plt>
   0x401239:	mov    QWORD PTR [rbp-0x30],0x0
   0x401241:	jmp    0x40127f
   0x401243:	mov    rax,QWORD PTR [rbp-0x30]
   0x401247:	mov    rax,QWORD PTR [rbp+rax*8-0x1c0]
   0x40124f:	mov    rdx,QWORD PTR [rbp-0x80]
   0x401253:	movzx  eax,BYTE PTR [rdx+rax*1]
   0x401257:	mov    edx,eax
   0x401259:	mov    rax,QWORD PTR [rbp-0x30]
   0x40125d:	mov    eax,DWORD PTR [rbp+rax*4-0x2340]
   0x401264:	xor    eax,edx
   0x401266:	movsx  eax,al
   0x401269:	mov    esi,eax
   0x40126b:	mov    edi,0x40142a
   0x401270:	mov    eax,0x0
   0x401275:	call   0x400a10 <printf@plt>
   0x40127a:	add    QWORD PTR [rbp-0x30],0x1
   0x40127f:	mov    eax,DWORD PTR [rbp-0x3c]
   0x401282:	cdqe   
   0x401284:	cmp    rax,QWORD PTR [rbp-0x30]
   0x401288:	jg     0x401243
   0x40128a:	mov    rax,QWORD PTR [rbp-0x70]
   0x40128e:	mov    rdi,rax
   0x401291:	call   0x400b00 <fclose@plt>
{% endhighlight %}

This is where all the magic happens. I will go over the above code section in more details in a little bit.

{% highlight bash %}
   0x401296:	mov    eax,0x1
   0x40129b:	mov    rsp,r12
   0x40129e:	cmp    eax,0x1
   0x4012a1:	jne    0x4012b4
   0x4012a3:	jmp    0x4012af
   0x4012a5:	mov    edi,0x401430
   0x4012aa:	call   0x400a40 <puts@plt>
   0x4012af:	mov    ebx,0x0
   0x4012b4:	mov    eax,ebx
   0x4012b6:	lea    rsp,[rbp-0x20]
   0x4012ba:	pop    rbx
   0x4012bb:	pop    r12
   0x4012bd:	pop    r13
   0x4012bf:	pop    r14
   0x4012c1:	pop    rbp
   0x4012c2:	ret
{% endhighlight %}

...and the function epilog.

Ok, from the quick overview, it looks like the binary is downloading a file, puts it in /tmp/.tera, reads it and does something to the read bytes.
It then prints the result, closes the file and exits.

Looking at the file it downloads, it looks like it's a 31 TB file...
We know we don't have the disk space nor the ram to read this file.

> ![image]({{site.url}}/assets/ScreenShot2015-05-11.png)

Let's see what's the magic that it does with this file.

{% highlight bash %}
   0x4011ad:	lea    rax,[rbp-0x22a0]
   0x4011b4:	mov    esi,0x4013c0
   0x4011b9:	mov    rdi,rax
   0x4011bc:	call   0x400a80 <fopen@plt>
(gdb) x/s 0x4013c0
0x4013c0:	 "r"
(gdb) x/s $rbp-0x22a0
0x7fffffffc0e0:	 "/tmp/.tera"
(gdb)
   0x4011c1:	mov    QWORD PTR [rbp-0x70],rax
   0x4011c5:	mov    rax,QWORD PTR [rbp-0x38]
   0x4011c9:	lea    rdx,[rax-0x1]
   0x4011cd:	mov    QWORD PTR [rbp-0x78],rdx
   0x4011d1:	mov    rdx,rax
   0x4011d4:	mov    QWORD PTR [rbp-0x2350],rdx
   0x4011db:	mov    QWORD PTR [rbp-0x2348],0x0
   0x4011e6:	mov    rdx,rax
   0x4011e9:	mov    r13,rdx
   0x4011ec:	mov    r14d,0x0
   0x4011f2:	mov    rdx,rax
   0x4011f5:	mov    eax,0x10
   0x4011fa:	sub    rax,0x1
   0x4011fe:	add    rax,rdx
   0x401201:	mov    esi,0x10
   0x401206:	mov    edx,0x0
   0x40120b:	div    rsi
   0x40120e:	imul   rax,rax,0x10
   0x401212:	sub    rsp,rax
   0x401215:	mov    rax,rsp
   0x401218:	add    rax,0x0
   0x40121c:	mov    QWORD PTR [rbp-0x80],rax
   0x401220:	mov    rdx,QWORD PTR [rbp-0x38]
   0x401224:	mov    rax,QWORD PTR [rbp-0x80]
   0x401228:	mov    rcx,QWORD PTR [rbp-0x70]
   0x40122c:	mov    esi,0x1
   0x401231:	mov    rdi,rax
   0x401234:	call   0x400ae0 <fread@plt>
{% endhighlight %}
Ok, it opens the downloaded file and reads it.
{% highlight bash %}
   0x401239:	mov    QWORD PTR [rbp-0x30],0x0
   0x401241:	jmp    0x40127f
   0x401243:	mov    rax,QWORD PTR [rbp-0x30]   <------------
   0x401247:	mov    rax,QWORD PTR [rbp+rax*8-0x1c0] <------|------
   0x40124f:	mov    rdx,QWORD PTR [rbp-0x80]               |     | It takes 1 byte argument from offset 
   0x401253:	movzx  eax,BYTE PTR [rdx+rax*1]        <------|------
   0x401257:	mov    edx,eax                                |
   0x401259:	mov    rax,QWORD PTR [rbp-0x30]        <------|----- On these 2 lines takes another 1 byte offset
   0x40125d:	mov    eax,DWORD PTR [rbp+rax*4-0x2340]<------|-----
   0x401264:	xor    eax,edx        <=======================|=========== XORs the two bytes
   0x401266:	movsx  eax,al                                 |
   0x401269:	mov    esi,eax                                |
   0x40126b:	mov    edi,0x40142a   <=======================|====== Prints the result in single character format.
   0x401270:	mov    eax,0x0                                |       (gdb) x/s 0x40142a
   0x401275:	call   0x400a10 <printf@plt>                  |       0x40142a:	 "%c\n"
   0x40127a:	add    QWORD PTR [rbp-0x30],0x1               |
   0x40127f:	mov    eax,DWORD PTR [rbp-0x3c]               |
   0x401282:	cdqe                                          |
   0x401284:	cmp    rax,QWORD PTR [rbp-0x30]         <=====|===== Looks like it loops 38 times.
   0x401288:	jg     0x401243                   <------------
   0x40128a:	mov    rax,QWORD PTR [rbp-0x70]
   0x40128e:	mov    rdi,rax
   0x401291:	call   0x400b00 <fclose@plt>
{% endhighlight %}

If we inspect the memory regions we can get the following 38 offsets.

>4C89617CF4  
>0B4B5E95F83  
>0E4598D686B  
>136A62674EF  
>1837A65BEB7  
>19FA831467C  
>2A6202ACD01  
>4493F10645E  
>4CDCE6D65E4  
>5028EC8DE7E  
>56219504A56  
>5BD2D191DB8  
>72BD5D02592  
>73DEE6D04FE  
>0A25E5AFE320  
>0A73B464FB9E  
>0B6259F6E34B  
>0B9AA45094DC  
>0BC548E0EA39  
>0C7AC41ECC56  
>0C85F073FB8B  
>0C92536A9116  
>0D930BE6DABF  
>0E61B989DA40  
>0F37999CA268  
>0FB7C59B9D1F  
>1018D3A3939D  
>10202AED0369  
>10E8FB926CF3  
>113BC38EA065  
>13257504044F  
>14FB0612DC3C  
>16572370DA92  
>173D75634441  
>1B9D0F2D9374  
>1BA90DE42D8E  
>1BE9EF4C8F3E  
>1BFDA4B84E00  

We need to convert them from hex to decimal and use the value as an offset to extract 1 byte from the 31 TB file.
But how do we do that if we don't have the file ?

Well, luckily for us the web server uses Accept-Ranges HTTP response header. This means we can use the Range header
to extract data from any arbitrary offset. Here is a one-liner bash script to fetch the byte at the given offsets and
store it into a file bytes.txt.

{% highlight bash %}
$ for i in `cat offsets.txt` ; do curl http://darksky.slac.stanford.edu/simulations/ds14_a/ds14_a_1.0000 -H "Range: bytes=$(( 0x$i ))-$(( 0x$i ))" | xxd ; done >> bytes.txt
{% endhighlight %}

We have the bytes that needs to be XORed with the keys. We can get the 1 byte XOR keys from the second offset in the binary.

>f2  
>9a  
>83  
>12  
>39  
>45  
>e7  
>f4  
>6f  
>a1  
>06  
>e7  
>95  
>f3  
>90  
>f2  
>f0  
>6b  
>33  
>e3  
>a8  
>78  
>37  
>d5  
>44  
>39  
>61  
>8a  
>fb  
>22  
>fa  
>9e  
>e7  
>11  
>39  
>a6  
>f3  
>33  

Now let's make a quick python script to XOR each file extracted byte with the key byte.

{% highlight python %}
#!/usr/bin/env python

inbytes = open('bytes.txt', 'r')
inkeys = open('keys.txt', 'r')

byte_array = []
key_array = []

flag = []

for i in inbytes:
	byte_array.append(i.strip())

for x in inkeys:
	key_array.append(x.strip())

for byte in range(len(byte_array)):
	b = byte_array[byte]
	k = key_array[byte]
	flag.append(chr(int(b, 16) ^ int(k, 16)))

print ''.join(flag)
{% endhighlight %}

{% highlight bash %}
$python ./xor_tera.py 
ASIS{3149ad5d3629581b17279cc889222b93}
{% endhighlight %}

## Links

* <http://www.asis-ctf.ir/challenges/>

