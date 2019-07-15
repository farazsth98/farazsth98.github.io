---
layout: post
title: 	"PicoCTF 2018 - be-quick-or-be-dead-3 (Reversing)"
date:	2019-07-14 18:54:00 +0800
categories: writeups picoctf
---

* **Category:** reversing
* **Points:** 350

## Challenge

>As the song draws closer to the end, another executable be-quick-or-be-dead-3 suddenly pops up. This one requires even faster machines. Can you run it fast enough too? You can also find the executable in /problems/be-quick-or-be-dead-3_2_fc35b1f6832df902b8e2f724772d012f.

## Hints

>How do you speed up a very repetitive computation?

The challenge archive contained the following file.
```
be-quick-or-be-dead-3
```

## Solution

This was a simple reversing challenge that required knowledge of dynamic programming. Dynamic programming is mainly an optimization over just plain recursion. Wherever there is a recursive algorithm that has repeated function calls with the same inputs, we can optimize it using dynamic programming by only doing the call once, storing the value, and then using the stored value for every subsequent call. More information can be found [here](https://www.cs.cmu.edu/~avrim/451f09/lectures/lect1001.pdf).

Running file against the executable, we get the following.
```bash
» file be-quick-or-be-dead-3                  
be-quick-or-be-dead-3: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=2cec6b98d9025d8dfe4a9bcb1c46500914b0fa4f, not stripped
```

Attempting to just run the program gives us the following output.
```bash
» ./be-quick-or-be-dead-3                                                                        
Be Quick Or Be Dead 3
=====================

Calculating key...
You need a faster machine. Bye bye.
```

Let's fire up ghidra and see what the decompilation of the executable looks like. The main function is as follows.
```c
undefined8 main(void)
{
  header();
  set_timer();
  get_key();
  print_flag();
  return 0;
}
```

Looking at the code, `header()` simply outputs the "Be Quick Or Be Dead 3" message when the program is run. 

`set_timer()` sets a three second timer for the program to run for. If the program exceeds the three second timer, then it just exits with the error message shown above.

`get_key()` looked interesting. The code is shown below.
```c
void get_key(void)
{
  puts("Calculating key...");
  key = calculate_key();
  puts("Done calculating key");
  return;
}
```

Following through, below is `calculate_key()`.
```c
void calculate_key(void)
{
  calc(0x19965);
  return;
}
```

And then, `calc()`.
```c
ulong calc(uint uParm1)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint local_1c;
  
  if (uParm1 < 5) {
    local_1c = uParm1 * uParm1 + 0x2345;
  }
  else {
    iVar1 = calc((ulong)(uParm1 - 1));
    iVar2 = calc((ulong)(uParm1 - 2));
    iVar3 = calc((ulong)(uParm1 - 3));
    iVar4 = calc((ulong)(uParm1 - 4));
    iVar5 = calc((ulong)(uParm1 - 5));
    local_1c = iVar5 * 0x1234 + (iVar1 - iVar2) + (iVar3 - iVar4);
  }
  return (ulong)local_1c;
}
```

`calc()` looks very esoteric when set out that way. Reading the code and optimizing it, you get the following:
```c
ulong calc(uint i)
{
	uint final_value;

	if (i < 5) 
	{
		final_value = i*i + 0x2345;
	}
	else 
	{
		final_value = calc((ulong)(i-1)) - calc((ulong)(i-2)) + calc((ulong)(i-3)) -
			calc((ulong)(i-4)) + calc((ulong)(i-5))*0x1234;
	}

	return final_value
}
```

So it seems to be a recursive function that gets called with `calc(0x19965)` from `calculate_key()`. That is a huge number of recursions, and I don't know of any language that will actually run this function without reaching its maximum recursion depth limit.

The solution is to optimize it using dynamic programming. The idea is that we want to 'save' each calculation in memory, so that each time the function would recurse, it instead uses the saved value from memory, thus not only saving time (as the calculations are only done once), but also never reaching the maximum recursion depth limit.

I wrote up a quick python script that demonstrates this idea.
```python
def calc(key):
	v = [None] * (key+1)
	v[0] = 9029 # 0*0 + 0x2345
	v[1] = 9030 # 1*1 + 0x2345
	v[2] = 9033 # 2*2 + 0x2345
	v[3] = 9038 # 3*3 + 0x2345
	v[4] = 9045 # 4*4 + 0x2345

	# Loop until the value of key, storing all values along the way
	for i in range(5, key+1):
		v[i] = (v[i-5]*0x1234 + (v[i-1]-v[i-2]) + (v[i-3]-v[i-4]))
		v[i] = v[i] % (1 << 32) # The same as v[i] = (ulong) v[i]

	return v[key]

print hex(calc(0x19965))
```

Running the script gives us the calculated value.
```bash
» python calc.py                                                                                
0x9e22c98e
```

Now that we know the calculated value, we can use gdb to make `calculate_key()` return this value at runtime, instead of making the call to `calc()`. This is demonstrated below.
```shell
(gdb) handle SIGALRM ignore
Signal        Stop      Print   Pass to program Description
SIGALRM       No        No      No              Alarm clock
(gdb) disass calculate_key
Dump of assembler code for function calculate_key:
   0x0000000000400792 <+0>:     push   rbp
   0x0000000000400793 <+1>:     mov    rbp,rsp
   0x0000000000400796 <+4>:     mov    edi,0x19965
   0x000000000040079b <+9>:     call   0x400706 <calc>
   0x00000000004007a0 <+14>:    pop    rbp
   0x00000000004007a1 <+15>:    ret    
End of assembler dump.
(gdb) break *calculate_key+9
Breakpoint 1 at 0x40079b
(gdb) run
Starting program: /home/faithlesss/Documents/ctfs/picoctf2018/be-quick-or-be-dead-3/be-quick-or-be-dead-3 
Be Quick Or Be Dead 3
=====================

Calculating key...

Breakpoint 1, 0x000000000040079b in calculate_key ()
(gdb) set $eax = 0x9e22c98e
(gdb) jump *calculate_key+14
Continuing at 0x4007a0.
Done calculating key
Printing flag:
picoCTF{dynamic_pr0gramming_ftw_b5c45645}
[Inferior 1 (process 23499) exited normally]
(gdb) 

```

We first set the SIGALRM handler to ignore. This will cause the program to ignore any SIGALRM interrupts, which is what the `set_timer()` function was doing. We then break just at the call to the `calc()` function. Once the breakpoint is hit, we set `eax` to `0x9e22c98e`, then jump to the `pop rbp` instruction. This causes `calculate_key()` to skip the `calc()` call and return the value in `eax`.

Flag: `picoCTF{dynamic_pr0gramming_ftw_b5c45645}`
