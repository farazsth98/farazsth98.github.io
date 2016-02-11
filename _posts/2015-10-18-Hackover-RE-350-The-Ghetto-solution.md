---
layout: post
title: Hackover CTF - RE 350
category: Reverse Engineering
tags: Hackover RE
comments: true
---

**Points:** 350
**Solves:** 11
**Category:** Reverse Engineering
**Description:**  

> I like to move it, move it  
> I like to move it, move it  
> I like to move it, move it  
> You like to move it  

> [move_it]({{site.url}}/assets/move_it)

# Write-Up

It's a 32bit ELF stripped binary which seems to be highly obfuscated. There's no main() function and everything happens in _start.
I won't be surprised if this was written in pure assembly.  

In the beginning we have 2 calls to sigaction().

![screen]({{site.url}}/assets/Screen Shot 2015-10-18 at 10.22.49 AM.png)

And at the end we have... nothing, or at least nothing that's going to cause a sort of exit.

![screen1]({{site.url}}/assets/Screen Shot 2015-10-18 at 10.24.06 AM.png)

Between the first instruction at 0x0804831c and the last instruction at 0x08069e0c we have 137968 bytes of assembly move instructions, no jumps, no calls, only moves.
We can also see that in the PLT we have printf(), time(), getc(), exit() and sigaction().

So basically what's happening here is that the author is using sigaction() for SIGSEGV (signal 11) and SIGILL (signal 4) to work as Exception Handlers.
On SIGSEGV or SIGILL execution the program will not seg fault and crash but it will be handled by separate set of instructions (like SEH on Windows :).

We could also look at the assembly of the Exception Handlers by examining the structure passed to sigaction, but let's just continue and call this The Ghetto Solution.

For the curious ones here is the sigaction struct that's passed to sigaction().

{% highlight bash %}
struct sigaction {
	void     (*sa_handler)(int);
	void     (*sa_sigaction)(int, siginfo_t *, void *);
	sigset_t   sa_mask;
	int        sa_flags;
	void     (*sa_restorer)(void);
};
{% endhighlight %}

The first object is the address of the signal handler.

# Solution

<script type="text/javascript" src="https://asciinema.org/a/28259.js" id="asciicast-28259" data-speed="2" async></script>

* [link to normal motion recording](https://asciinema.org/a/28259)
