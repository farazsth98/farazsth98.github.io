---
layout: post
title:  "picoCTF 2019: Ghost_Diary"
date:   2019-10-12 00:00:00 +0800
categories: pwn
tags: CSAW-Qualifiers-2019
---

A heap exploitation challenge on glibc 2.27. The only vulnerability is a single null byte overflow when editing the contents of a malloc'd chunk. I used that null byte overflow to call `malloc_consolidate()` and get overlapped chunks, followed by a libc leak. Then it was just a normal tcache poisoning attack to get a chunk onto `__free_hook`, overwrite it with a one gadget, then call `free()` to get a shell. The hardest part about this challenge is that its glibc 2.27, meaning the tcache is enabled. We get past that in a very novel (not really) way, as shown in the writeup.

### Challenge

* **Category:** pwn
* **Points:** 500
* **Solves:** 15

>Try writing in this [ghost diary](https://2019shell1.picoctf.com/static/2136859eaddb15400ec3328f017e1df8/ghostdiary). Its also found in /problems/ghost-diary_4_f7e6ee76ec07e6866ddc813917b94545 on the shell server.

### Solution

Before you read this writeup, I would highly suggest having some prior knowledge about how the heap works on linux. Linux uses an allocator called `ptmalloc2`, and here are some great resources to get you started:

* [ctf-wiki: Extremely detailed information (in Chinese). This one is my favorite, use google translate](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/introduction-zh/)
* [sploitfun: Overview of ptmalloc2](https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/)
* [dhavalkapil: Overview + some exploits](https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/malloc_chunk.html)
* [how2heap: Exploits from shellphish](https://github.com/shellphish/how2heap)
* [InfoSectBR: Some more writeups for some heap exploitation attacks](http://blog.infosectcbr.com.au/)

I will provide a brief overview of the heap further down, but I will still assume that the reader will be using these references to fully understand everything I say.

#### Reversing the binary

Let's start off by reverse engineering the binary. Running `checksec` and `file` on it shows us the following:
```sh
vagrant@ubuntu-bionic:/ctf/pwn-and-rev/picoctf-2019/ghost_diary$ file ghostdiary
ghostdiary: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=da28ccb1f0dd0767b00267e07886470347987ce2, stripped

vagrant@ubuntu-bionic:/ctf/pwn-and-rev/picoctf-2019/ghost_diary$ checksec ghostdiary
[*] '/ctf/pwn-and-rev/picoctf-2019/ghost_diary/ghostdiary'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
vagrant@ubuntu-bionic:/ctf/pwn-and-rev/picoctf-2019/ghost_diary$
```

So, we have a stripped, dynamically linked 64-bit binary here with all protections enabled. An explanation for each protection is given below:

* **Full RELRO**: The Global Offset Table (GOT) is read-only, meaning we won't be able to overwrite a function pointer there and hijack flow of execution easily.
* **Canary found**: There is a stack canary, so stack buffer overflows are out of the question unless we can somehow leak the canary.
* **NX enabled**: There is no memory region that is both writable and executable, meaning we can't inject shellcode into the program and have it execute the shellcode.
* **PIE enabled**: PIE stands for Position Independent Executable. It means that the base address of the binary is randomized each time we run it, meaning we can't use exploits such as ROP or ret2libc since we don't know any addresses at all without a leak.

So off the get go we can already see that this won't be an easy challenge. Fortunately for us, heap exploits don't care about any of these protections (most of the time at least).

The binary itself is very simple. You should be able to reverse engineer it yourself pretty easily. It has a global array of "pages" that can store 19 pages. Each page is a struct that contains a pointer to the page's content on the heap, as well as the size of the content. The struct looks something like the following:
```c
struct page
{
	char* content; // The actual content of the page
	int size; // The size of the content
};

struct page array_of_pages[19]; // Maximum of 19 pages allowed
```

We also have the following functionality

* `sub_B5D` is the "New page in diary" function. You are allowed to add either a one-sided page or a two-sided page. If you choose a one-sided page, you can allocate a chunk <= 0xf0 in size. If you choose a two-sided page, you can allocate a chunk in between 0x110 and 0x1e0 (inclusive). There is a limit of 19 pages imposed.
* `sub_CFB` is the "Talk with ghost" function. It lets you edit a page and put your own content into it. This function calls `sub_DA2` to read in user input for the content. This function (`sub_DA2`) has a single null byte overflow vulnerability in it.
* `sub_DBE` is the "Listen to ghost" function. It outputs the contents of a page.
* `sub_E69` is the "Burn the page" function. It frees a page and nulls out the pointer in the global array of pages.

The only vulnerability we have is a single null byte overflow in `sub_DA2`. The "Talk with ghost" function does something like the following:
```c
void talkWithGhost()
{
	int page_index;

	printf("Page: ");
	scanf("%d", &page_index);

	printf("Content: ");

	if (page_index <= 19 && global_pages_array[page_index] != NULL)
		sub_DA2(global_pages_array[page_index].content, global_pages_array[page_index].size);
}
```

`sub_DA2` does something like the following:
```c
void sub_DA2(char *chunk_ptr, int size)
{
	int num_of_bytes_read = 0, index_to_write_to = 0;
	char buf;

	if (size) // Ensure size isn't just 0
	{
		while (num_of_bytes_read != size) // Read until size is hit, no heap overflow here
		{
			if (read(0, &buf, 1) != 1) // Read a single byte each time
			{
				puts("read error");
				exit(-1);
			}

			if (buf == '\n') // Quit if the byte read in is a newline
				break;

			// Write to the current index and increment the num_of_bytes_read
			index_to_write_to = num_of_bytes_read++;
			chunk_ptr[index_to_write_to] = buf;
		}
		chunk_ptr[num_of_bytes_read] = 0; // Null byte overflow here when setting the final byte to '\0'
	}
}
```

The vulnerability is obvious now. If we read the maximum amount of bytes possible, then we will have a single null byte overflow that will overflow into (possibly) the metadata of the next chunk. How do we use this to our advantage?

You may immediately have an *idea* as to how this vulnerability could be used to our advantage, but it definitely requires a very in-depth knowledge of the heap to know how to exploit it. I'll provide a brief overview of the heap and its internals now.

#### Final exploit

Running the exploit now on the shell server gives us the flag:
```sh
Faith@pico-2019-shell1:/problems/ghost-diary_3_79b47a93e884f13bbc2640b2e8606676$ python /tmp/Faith/ghost_diary/exploit.py
[*] '/problems/ghost-diary_3_79b47a93e884f13bbc2640b2e8606676/ghostdiary'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './ghostdiary': pid 811337
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Libc base: 0x7f3d6dba5000
[*] one gadget: 0x7f3d6dbf4322
[*] free_hook: 0x7f3d6df928e8
[*] Switching to interactive mode
$ ls
flag.txt  ghostdiary  ghostdiary.c
$ cat flag.txt
picoCTF{nu11_byt3_Gh05T_6c9ca015}$
```
