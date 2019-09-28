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

You may immediately have an *idea* as to how this vulnerability could be used to our advantage, but it definitely requires a very in-depth knowledge of the heap to know how to exploit it. I'll take a quick detour now and provide a brief overview of the heap and its internals now. Experienced readers can skip this part and go straight into the "Exploitation" section.

I will also skip explaining any information that isn't required for this challenge, such as the concept of arenas amongst other things.

It will be assumed that the reader has prior knowledge of how stack buffer overflows work. I will use the following link for reference:

* [Understanding the glibc malloc](https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/)

#### Overview of the glibc heap

#### What is the heap?

The heap is, simply put, a memory region allotted to every program. This memory region can be dynamically allocated, meaning that a program can **request** and **release** memory from the heap whenever it requires. The heap is also a global memory space, meaning it isn't localized to a function like the stack is. This is mainly accomplished through the use of pointers to reference heap allocations.


#### How does a program request and release memory from the heap?

* **malloc**:

>A program may use `malloc(size_t n)` (and all its different versions such as `calloc` and `realloc`) to request a chunk of at least `n` bytes, or `NULL` if no space is available. If `n` is zero, malloc returns a minimum-sized chunk (0x10 bytes on most 32-bit systems, and either 0x18 or 0x20 bytes on 64-bit systems). In most systems, `size_t` is an unsigned type, so negative values of `n` will be interpreted as huge

* **free**:

>A program may use `free(void *p)` to release the chunk of memory pointed to by `p`. This has no effect if `p` is `NULL`. It can have very bad effects if `p` has already been freed, or if `p` is not a malloc'd chunk at all.

#### What does a chunk look like in memory?

A chunk in memory can be either free, or in-use. Chunks are stored in so-called "arenas". Each thread gets its own "arena" of chunks, and there is a special arena called the "main arena" which is the very first arena created by a program. This is also the only arena present in single-threaded programs.

A structure called the `malloc_chunk` (typedef'd as `mchunkptr`) is used by glibc to keep track of chunks, as follows:
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
            |             Forward pointer to next chunk in list             |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Back pointer to previous chunk in list            |
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

* **P (PREV_INUSE)**: Set to 0 when the previous chunk (not the chunk before it in its linked list, but the one before it in memory) is free. The size of that previous free chunk is stored before the size of this current chunk ***only if*** the previous chunk is free, otherwise the previous chunk can use that `prev_size` space as if it was its own. The very first allocated chunk will always have this bit set. If this bit is set to 1, we cannot determine the previous chunk's size.

* **M (IS_MMAPPED)**: The chunk has been obtained through `mmap`. The other two bits are correspondinly ignored if this bit is set to 1, because `mmapped` chunks are neither in an arena, nor adjacent to a free chunk.

* **A (NON_MAIN_ARENA)**: 0 for chunks in the main arena. Each thread spawned in a program receives its own arena, and for any chunks malloc'd in each of those threads, this bit is set to 1. The main arena is the arena that is always there prior to any new threads having been spawned in.

The most important thing to note here is that freed chunks remain on the heap. They aren't magically moved out of the heap into some other memory region. This means that given a vulnerability such as a heap overflow, we can overwrite those forward and back pointers and thus corrupt the free lists. This can be used to our advantage, and if done carefully, can lead to code execution.

The other thing to note is that with something like a double free vulnerability, a freed chunk's forward pointer would point to itself. We can also utilize this to our advantage, and we will do so in the exploit for this challenge.

#### Bins and Chunks

A `bin` is glibc's term for a free-list. It is a singly or doubly linked list of free chunks. Bins are differentiated based on the size of chunks that they contain. We have the following 5 bins in glibc 2.27:

1. Tcache bin (added with glibc 2.26)
2. Fast bin (not covered in this post, assumed knowledge)
3. Unsorted bin
4. Small bin (not covered in this post, assumed knowledge)
5. Large bin (not covered in this post, assumed knowledge)

For information regarding the three bins that are not covered, see [this](https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/bins_chunks.html).

#### Introduction to Tcache

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
  tcache_entry *entries[TCACHE_MAX_BINS]; // TCACHE_MAX_BINS is usually defined as 7
} tcache_perthread_struct;

static __thread char tcache_shutting_down = 0;

/* Used to maintain all free chunks that belong to this current thread's tcache bin.
 * This is stored on the very start of the heap, as soon as the first chunk gets malloc'd in a program
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

* The tcache bin is a singly linked list of free chunks. It is a LIFO structure. There are tcache bins created for each chunk size (0x20, 0x30, 0x40, ...), and each tcache bin has a maximum of 7 chunks that it can store. As is also evident from the comments above the two functions above, there are zero security checks performed when freeing or mallocing out of a tcache bin. This, coupled with the fact that a tcache bin of a specific size has a max limit of 7 chunks, is very important to us. Every other bin has security checks to ensure the integrity of itself as well as the chunks it stores, but the tcache does not.

* Each thread has 64 tcache bins, each holding chunks of the same size. The maximum size chunk that the final tcache bin will hold (on 64-bit systems) is 0x408 bytes.

* If there is a chunk in a tcache bin and a request is made for a chunk of the same size, then the tcache bin takes priority over all other bins (i.e if there is a chunk of the same size in any of the other bins, they are ignored as the tcache bin is given priority).

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
