---
layout: post
title: Flare-on Challenge 1
category: CTF
tags: RE CTF Flare-on FireEye
---

# Flare-on Challenge 1
**Points:**
**Solves:**
**Category:** Reverse
**Description:**

> It's simple: Analyze the [sample]({{site.url}}/assets/Challenge1.exe), find the key. Each key is an email address.

## Write-up

Let's first find out a little about the file. Opening the file with PEID does not show the compiler and language.
Luckily for us, Exeinfo shows "Microsoft Visual C# / Basic.NET" not packed.

> ![exeinfo]({{site.url}}/assets/flare-on-chal1-5.png)

Running the executable, we see it's presenting us with a Window Box, title - "Let's start with something easy!" and a button
saying "Decode!".

> ![flare-on-chal1-3]({{site.url}}/assets/flare-on-chal1-3.png)

Pressing the decode button, the picture changes and the title gets scrambled.

> ![flare-on-chal1-4]({{site.url}}/assets/flare-on-chal1-4.png)

Since this is compiled used .NET Framework, we can decompile the object and look around.
In the "XXXXXXXXXXXXXX" object we can find the Decode_Click function.

> ![flare-on-chal1-1]({{site.url}}/assets/flare-on-chal1-1.png)

Here we can see that there are two resources being used. The image resource "bob_roge" and "dat_secret".
We can also see the encoding function. Before we take advantage of that let's see the content of "dat_secret" resource.

> ![flare-on-chal1-2]({{site.url}}/assets/flare-on-chal1-2.png)

Converting the encoding function in Python and using it on a file with the content of the dat_secret resource, we get the key for this level.

{% highlight python linenos %}
#!/usr/bin/env python

import sys

infile = bytearray(open(sys.argv[1], 'r').read())

output = []

for num2 in infile:
	str = ((num2 >> 4) | ((num2 << 4) & 240)) ^ 0x29
	output.append(chr(str))

print ''.join(output)
{% endhighlight %}

{% highlight bash %}
# python decrypt.py dat_secret 
3rmahg3rd.b0b.d0ge@flare-on.com
# 
{% endhighlight %}