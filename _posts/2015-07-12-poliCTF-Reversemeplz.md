---
layout: post
title: poliCTF 2015 Reversemeplz
category: CTF
tags: RE CTF poliCTF
---

# poliCTF 2015 Reversemeplz
**Points:** 200
**Solves:** 108
**Category:** Reverse
**Description:**

> Last month I was trying to simplify an algorithm.. and I found how to mess up a source really really bad. And then this challenge is born. Maybe is really simple or maybe is so hard that all of you will give up. Good luck!

[reversemeplz]({{site.url}}/assets/reversemeplz)

## Write-up

{% highlight bash linenos %}
$ file reversemeplz 
reversemeplz: ELF 32-bit LSB  executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, BuildID[sha1]=da884e304160351da7785e93dc168eecafe770ed, stripped
$ ./reversemeplz 
AAAAA
Wrong input.
$ 
{% endhighlight %}

# Main

![Main_reverseme]({{site.url}}/assets/Main_reverseme.png)

In main() we see just one input_processing_function and test eax, eax of the return value. Anything but 0 is going to lead us into the
printf "flag{"... Let's see what we have in that function.

![input_processing_function]({{site.url}}/assets/input_processing_function.png)

Here in the main loop between the function's prologue and 'xor eax, eax' followed by 'dec edi', we see that the characters
of our input are being compared one by one with > 0x60 and <= 0x7a. If we pull our ASCII table we see that this is the range of all
lowercase characters, so probably our input needs to be all lowercase. We can also see that it uses all characters one-by-one as
an input for the "obfuscated_function" and it stores the result at "mov	[ebp+esi+var_58], al]". Since it's 'al' register
we only care about low order byte of the return of the obfuscated_function. Let's not go into that function just yet and continue analysys.
The second loop from the "input_processing_function", we see that the stored values from the return of the "obfuscated_function",
with some subtraction are being compared to some static values.

![input_process_second_loop]({{site.url}}/assets/input_process_second_loop.png)

If the location of the stored return bytes from "obfuscated_function" start at "[ebp+eax+var_58]" with eax being our counter we see that
exactly 15 bytes will be compared and the 16th being a null terminator. We also see that the actual comparison is being worked on the 1 index byte - 0 index byte
followed by result - index 2 followed by result - index 3 or in other words   
solution[0] = input[1] - input[0]   
solution[1] = input[2] - input[1]   
solution[2] = input[3] - input[2]   
...

Now let's see the obfuscated_function.

![obfuscated_function]({{site.url}}/assets/obfuscated_function.png)

Wow ! I'm not even gonna bother with this function :P. Instead I made a simple test. What's a function ? It takes input and it returns a value, correct ?
So, I just made a test with having different input values for example 'aaaa', 'bbbb', 'cccc' and I noticed that the return value is always the same for the 'a''s, the same between the 'b''s and
the same between all 4 'c''s, next I entered as an input each of the alphabet characters and I got the following returns.

> a - 6e   
> b - 6f   
> c - 70   
> d - 71   
> e - 72   
> f - 73   
> g - 74   
> h - 75   
> i - 76   
> j - 77   
> k - 78   
> l - 79   
> m - 7a   
> n - 61  
> o - 62  
> p - 63  
> q - 64  
> r - 65  
> s - 66  
> t - 67  
> u - 68  
> v - 69  
> w - 6a  
> x - 6b  
> y - 6c  
> z - 6d  

Now let's see the values of the static bytes that our input is being compared against.

{% highlight bash linenos %}

(gdb) x/1bx $ebp+1*4-0x4c
0xbfffef50:	0xff
(gdb) x/1bx $ebp+2*4-0x4c
0xbfffef54:	0x11
(gdb) x/1bx $ebp+3*4-0x4c
0xbfffef58:	0xf5
(gdb) x/1bx $ebp+4*4-0x4c
0xbfffef5c:	0x03
(gdb) x/1bx $ebp+5*4-0x4c
0xbfffef60:	0xf8
(gdb) x/1bx $ebp+6*4-0x4c
0xbfffef64:	0x05
(gdb) x/1bx $ebp+7*4-0x4c
0xbfffef68:	0x0e
(gdb) x/1bx $ebp+8*4-0x4c
0xbfffef6c:	0xfd
(gdb) x/1bx $ebp+9*4-0x4c
0xbfffef70:	0x01
(gdb) x/1bx $ebp+10*4-0x4c
0xbfffef74:	0x06
(gdb) x/1bx $ebp+11*4-0x4c
0xbfffef78:	0xf5
(gdb) x/1bx $ebp+12*4-0x4c
0xbfffef7c:	0x06
(gdb) x/1bx $ebp+13*4-0x4c
0xbfffef80:	0xf8
(gdb) x/1bx $ebp+14*4-0x4c
0xbfffef84:	0xf6
(gdb) x/1bx $ebp+15*4-0x4c
0xbfffef88:	0x00
(gdb) 

{% endhighlight %}

Knowing that I started looking for the flag using something like the following:

{% highlight python %}
#!/usr/bin/env python

for z in range(97, 123):
	for x in range(97, 123):
		if x - z == -1:
			a = z
			b = x
			c = b + 17
			d = c + -11
			e = d + 3
			f = e + -8
			g = f + 5
			h = g + 0xe
			i = h + -3
			j = i + 1
			k = j + 6
			l = k + -11
			m = l + 6
			n = m + -8
			o = n + -10
			if (0x61 < a < 0x7b) and (0x61 < b < 0x7b) and (0x61 < c < 0x7b) and (0x61 < d < 0x7b) and (0x61 < e < 0x7b) and (0x61 < f < 0x7b) and (0x61 < g < 0x7b) and (0x61 < h < 0x7b) and (0x61 < i < 0x7b) and (0x61 < j < 0x7b) and (0x61 < k < 0x7b) and (0x61 < l < 0x7b) and (0x61 < m < 0x7b) and (0x61 < n < 0x7b) and (0x61 < o < 0x7b):
				print hex(a) + " " + hex(b) + " " + hex(c) + " " + hex(d) + " " + hex(e) + " " + hex(f) + " " + hex(g) + " " + hex(h) + " " + hex(i) + " " + hex(j) + " " + hex(k) + " " + hex(l) + " " + hex(m) + " " + hex(n) + " " + hex(o)
{% endhighlight %}

It produces the following output:

{% highlight bash linenos %}

$ python ./reverseplz.py 
0x63 0x62 0x73 0x68 0x6b 0x63 0x68 0x76 0x73 0x74 0x7a 0x6f 0x75 0x6d 0x63
$ 

{% endhighlight %}

Now I started converting the output values with my table up there gives us the following flag 'onetwotheflagyo'.
After that I thought the obfuscated_function was some sort of obfuscated substitution cipher but after a while I notice it was actually ROT13 :P.

## Links

* <http://polictf.it/>