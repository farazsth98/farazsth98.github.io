---
layout: post
title: Mental Snapshot - _int_free and unlink
category: [Exploitation, Misc]
tags: [Exploitation, Misc]
comments: true
---

## Summary

Yet another explanation of glibc's `free` and `unlink` mechanism and abusing them. I know there are many well documented articles and blog posts about the subject but I think until you take a moment and go through the source yourself, you will always feel like there's something missing. It also helped me greatly stepping through the code in gdb with the source listing. You can do that by downloading the sources of your version of glibc. Specify the source lookup directory in gdb with `directory <source dir>/malloc/` and breaking on `_int_free`.

## Free

Before thinking about exploitation, think about the implementation. Let's get familiar with how free works. The structure of a heap chunk is defined in malloc.c. Datatype `INTERNAL_SIZE_T` is 4 bytes on 32bit system and 8 bytes on 64bit system. The `prev_size` field contains the size in bytes of the previous chunk bordering the current chunk, ONLY if the previous chunk is free and not part of a fastbin list, since fastbins are sorted by size in the first place. The `size` field contains the current chunk's size with the 3 Least Significant Bits meaning:

* bit at position 1 - `PREV_INUSE` - Turned on if previous chunk is in USE.
* bit at position 2 - `IS_MMAPED`  - Turned on if chunk is allocated via mmap.
* bit at position 3 - `NON_MAIN_ARENA` - Turned on if the chunk belongs to thread arena.

FD and BK are the forward and backward pointers pointing to the previous and next chunks in a doubly linked list of free chunks.

{% highlight C %}
struct malloc_chunk {

  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* forward link -- used only if current chunk is free. */
  struct malloc_chunk* bk;         /* backward link -- used only if current chunk is free. */

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
{% endhighlight %}

The pointer returned by `malloc` to the user is pointing to `chunk->FD` which is the same address we supply to `free`. However, free internally calls to `_int_free` which takes as one of it's arguments the actual beginning of a chunk at `chunk->prev_size`. So throughout the rest of this blog post we will reference a chunk with `P`, not the address that's passed to the user by `malloc`.

{% highlight text %}

                             +----------------------+----------------------+
P chunk ptr ---------------> |      prev_size       |         size   |3|2|1|
                             +----------------------+----------------------+
ptr returned by malloc ----> |          FD          |          BK          |
                             +----------------------+----------------------+
                             |                                             |
                             |                                             |
                             |                                             |
                             +---------------------------------------------+

{% endhighlight %}

Finally we are at the source of free. I'm going to remove a bunch of code that doesn't concern us. The comments prefixed with `!` are my own, everything else is from malloc.c

{% highlight C %}

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

  const char *errstr = NULL;

  size = chunksize (p); // ! chunksize macro grabs the size from p->size

  // ... ! yanked check for size and alignment
  // ... 

  /*
    If eligible, place chunk on a fastbin so it can be found
    and used quickly in malloc.
  */

  if ((unsigned long)(size) <= (unsigned long)(get_max_fast ()))     // ! fastbin size is 0x80
    {
    /* !

    Yanked this whole section where it checks if the chunk can be placed in a fastbin
    If it's eligible for a fastbin the code will never reach the unlink macro because:

    * chunks are only single linked
    * chunks in fastbins don't contain prev_size field thus not unlinked
    * allocation of chunk in a fastbin is done in a LIFO manner
    * fastbins are sorted by size
    * neighboring free chunks are not consolidated

    gdb-peda$ p global_max_fast  // to check size of fastbin on your machine
    $1 = 0x80

    So, if p->size <= 0x80, place p in a fastbin of it's size and return

    */
    }

  /*
    Consolidate other non-mmapped chunks as they arrive.
  */

  else if (!chunk_is_mmapped(p)) {

    nextchunk = chunk_at_offset(p, size);   // ! nextchunk = P+P->size

    if (__glibc_unlikely (p == av->top))    // ! p can not be the top chunk (wilderness)
      {
    errstr = "double free or corruption (top)";
    goto errout;
      }
    /* Or whether the next chunk is beyond the boundaries of the arena.  */
    if (__builtin_expect (contiguous (av)
      && (char *) nextchunk                           // ! check if nextchunk
      >= ((char *) av->top + chunksize(av->top)), 0)) // ! is not >= top_chunk+top_chunk->size
      {
    errstr = "double free or corruption (out)";
    goto errout;
      }
    /* Or whether the block is actually not marked used.  */
    if (__glibc_unlikely (!prev_inuse(nextchunk)))  // ! nextchunk->PREV_INUSE
      {                                             // ! should not be 0
    errstr = "double free or corruption (!prev)";
    goto errout;
      }

    nextsize = chunksize(nextchunk);    // ! nextsize = nextchunk->size
    if (__builtin_expect (nextchunk->size <= 2 * SIZE_SZ, 0)
    || __builtin_expect (nextsize >= av->system_mem, 0))
      {
    errstr = "free(): invalid next size (normal)";
    goto errout;
      }

    // ! If all the error checks passed we reach the consolidate section
    // ! Check consolidate subsections in this blog post for more details

    // Yanked the whole consolidate section
  }

  /*
    If the chunk was allocated via mmap, release via munmap().
  */

  else {
    munmap_chunk (p);
  }
}

{% endhighlight %}

So, we simplified it to

{% highlight C %}
if (p->size <= 0x80){
    place chunk in fastbin
} else if (!p->IS_MMAPPED){
    consolidate
} else {
    unmap p
}
{% endhighlight %}

For consolidate we have to pass the following checks:

* P->size > 0x80
* P->IS_MMAPPED == 0
* P can not be the top chunk (wilderness). Top chunk's address is taken from the main_arena structure in libc's address space
* Nextchunk is calculated by adding P->size to P
* Nextchunk needs to have lower address than top_chunk+top_chunk->size
* Nextchunk->PREV_INUSE needs to be 1 otherwise it will throw a double free error
* Nextchunk->size needs to be valid heap chunk size

Ok, now that we have the required understanding of `free`, let's go through what happens when we free a chunk that's not eligible for fastbins. Basically we take that second branch and consolidate the chunk.

## Consolidate backwards

The heap is a dynamic data structure that contains contigious memory chunks. Some chunks are in use, some are not and the wilderness as the last chunk for future allocations. From the figure below, say we want to free `chunk 4`. Because `p->prev_inuse == 0` malloc is making 2 assumptions.
1. The previous chunk is `FREE`.
2. Because the previous chunk is `FREE` it will be part of a free list.

Next, the size variable holds the total length of the previous chunk and the current chunk. `p` is changed to `p - prevsize` which means that we have succesfully consolidated both chunks, the current and the previous and now the current `p` is this combined new chunk.

{% highlight C %}
    /* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = p->prev_size;
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      unlink(av, p, bck, fwd);
    }

{% endhighlight %}

![heap]({{site.url}}/assets/Screen Shot 2016-09-12 at 12.48.13 AM.png) 

## Unlink

Now that `p` has changed to `chunk 3`, the unlink macro will unlink `chunk 3` out of the free list and later add it to the unsorted bin.
With arguments `p` chunk to unlink, BK and FD a tempts for the corresponding pointers. The exploit mitigation check basically says, if `chunk 6->BK != chunk 3` or `chunk 1->FD != chunk 3` error out. But if the check is passed, overwrite `chunk 6->BK with chunk 1` and `chunk 1->FD with chunk 6`.

{% highlight C %}
/* Take a chunk off a bin list */
#define unlink(AV, P, BK, FD) {
    FD = P->fd;
    BK = P->bk;
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);
    else {
        FD->bk = BK;
        BK->fd = FD;
...
{% endhighlight %}

This results in `chunk 3` unlinked from the free list, consolidated with `chunk 4` and inserted in the `unsorted binlist`.

![unlinked]({{site.url}}/assets/Screen Shot 2016-09-12 at 2.59.44 PM.png)

## Exploitation

Let's think of the what happened. We freed `chunk 4` and this caused `chunk 3` to get unlinked ? This influenced the pointers of `chunk 1` and `chunk 6` !? And remember how the distance to `chunk 3` was calculated ? `chunk 4 - chunk 4->prev_size`, because it's looking for the previous bordering chunk, right? So now, what if we control the area around `chunk 4` that we are going to free and we set `chunk 4->prev_size` to `0`, this will cause `free` to think `chunk 3`'s address is right ON TOP of `chunk 4` `(chunk 4 == chunk 3)`.

![unlink2]({{site.url}}/assets/Screen Shot 2016-09-12 at 3.18.44 PM.png)

Since we control the buffer of `chunk 4` and `free` thinks it will run `unlink` on `chunk 3`, we actually control `chunk 3's FD and BK`. These values will be written to `FD->BK` and `BK->FD`. Again, we get to write `fake chunk 3->BK to fake chunk 3->FD->BK` and `fake chunk 3->BK to fake chunk 3->FD->BK` ONLY if the `target's address->FD or BK == fake chunk 3 (which is chunk 4, which is ptr we pass to free - INTERNAL_SIZE_T * 2)` 

## Extras

Since I'm sure this is super confusing (especially if you are reading it from a half-assed explanation like this) I'm going to do a general workflow for the required steps for the unlink to work.

1. Find target value to overwrite (obviously :)), let's call this value `TARGET`
2. We need to know the addresses on the heap
2. `&TARGET - INTERNAL_SIZE_T * 2` or `&TARGET - INTERNAL_SIZE_T * 3` needs to be stored at known location
* If it's `&TARGET - INTERNAL_SIZE_T * 2` this will be like `fake chunk 1` in our examples
* If it's `&TARGET - INTERNAL_SIZE_T * 3` this will be like `fake chunk 6` in our examples
3. `fake chunk 1->FD` needs to point to the chunk we are unlinking
4. `fake chunk 6->BK` needs to point to the chunk we are unlinking


### Consolidate forward

You understand why everything explain until now was about consolidating backwards ? Because the previous chunk bordering the chunk we are freeing is currently FREE (or at least we are making free to think that), so it just combined the two bordering chunks and unlinks the previous chunk. To consolidate forward we just have to make the `nextchunk` be free, free checks this by doing `(P + P->size (to find nextchunk) + nextchunk->size)->PREV_INUSE`, so it's like `nextchunk's nextchunk -> PREV_INUSE`. And remember if either the previous or the next chunks are free it needs to run unlink on them so they are not part of the free list anymore. Also, they both can be free ! In that case we will consolidate backwards AND forwards and run unlink on both.

For forward consolidate to take place in our examples, `chunk 5` had to be green (free :P).

* Thanks for reading, I hope I didn't confuse you more !



