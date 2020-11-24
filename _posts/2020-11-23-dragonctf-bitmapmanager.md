---
layout: post
title:  "Dragon CTF 2020 - BitmapManager"
date:   2020-11-23 5:00:00 +0800
categories: pwn
tags: DragonCTF-2020
---

# Introduction

Dragon CTF 2020 just finished this weekend. I played this CTF with team Perfect ⚔️ Guesser (collaboration between Super Guesser and Perfect Blue), and we got first place!

I worked on BitmapManager with [typeconfuser](https://twitter.com/typeconfuser), [RBTree](https://twitter.com/RBTree_), and [cts](https://twitter.com/gf_256) (and probably one or two others I'm forgetting about). It was a pretty unique challenge, and it felt really good to get first blood ~40 hours into the CTF! Thank you for such an amazing challenge [j00ru](https://twitter.com/j00ru)!

# The Challenge

* **Category**: pwn
* **Points**: 485
* **Difficulty**: hard
* **Solves**: 2

> Here's a software solution that meets all of your image management needs! It was written in C++ to achieve the highest levels of performance, but worry not, we have enabled some of the latest and greatest compiler options to ensure that memory corruption is not a concern.
>
> The service is running at bitmap-manager.hackable.software:4141. The flag is in the "flag.txt" file.
> 
> Files: [BitmapManager.exe](https://storage.googleapis.com/dragonctf-prod/bitmap-manager_d4e41d4efa7a18dd3c0ba9b4e86f466011bfc5613d92ad66e15046138eaff5a2/BitmapManager.exe)
> 
> **HINT**: Loading the flag in memory is half the battle. Now how can you get it out of there?

We're given a statically linked windows binary called `BitmapManager.exe`. This was my first time doing a pwn challenge on Windows (although as you'll find out, there is nothing Windows specific about it), so I had to download and set up a Windows VM to do some dynamic analysis.

The binary is basically a BMP loader. You're allowed to do a few things with it:

```
C:\Users\User\Downloads>.\BitmapManager.exe
[ASAN protection:    ON ]
[ASAN crash reports: OFF]
Supported options:
  list_builtins : List builtin bitmaps
  list          : List currently loaded bitmaps
  load_builtin  : Load a builtin bitmap
  load          : Load a bitmap from memory
  merge         : Merge two bitmaps into one
  dump          : Print out a bitmap
  unload        : Unload a bitmap
  help          : Print this message
  exit          : Exit program
Option:
```

I'm not 100% sure how Windows mitigations work, but what we did know at the beginning was that this binary had NX, ASAN, and UBSAN enabled. Also, there was ASLR, but ASLR on Windows is per boot so one leak would be all we need for library addresses.

The TL;DR of the options are:

1. `list_builtins` - checks `.\bitmaps\` for any `*.bmp` images. If they exist, it lists them along with their sizes.
2. `list` - self-explanatory
3. `load_builtin` - loads a BMP image from the `.\bitmaps\` directory.
4. `load` - loads a BMP image from stdin. You're allowed to provide a name, the size of the image in bytes, and then the raw bytes themselves (in hex).
5. `merge` - Takes two loaded BMP images and merges them into one (basically merges by width and then by height I think). You pick the bitmaps by ID.
6. `dump` - Dumps a loaded BMP image (basically prints a hexdump).
7. `unload` - Unloads a bitmap. This frees the buffer that was allocated for it.

It's important to note that both the `load` and the `load_builtin` functions parse the BMP image to ensure that its in a valid BMP format.

# Initial ideas

Initially, we weren't even trying to solve this challenge. I think sampriti had a brief look at it, but typeconfuser was offline, RBtree was solving crypto challenges, and I was doing `no-eeeeeeeeeeeemoji` (wasn't able to solve that one T_T). Around 8 or so hours into the CTF though, cts decided to start looking at this, and so I decided to tag along.

## This is one fat binary

We quickly realized that the binary was huge. Of course, it was statically linked, but even if it wasn't statically linked, there was a ton of code to reverse (and remember that we didn't have any symbols). 

cts has been doing some Windows fuzzing research at SSLab for a while now, so he decided to set up a harness to fuzz the `load` and `merge` functions for bugs. I on the other hand decided to take the brutal task of sitting down and reversing the functions to look for bugs.

## CTF mindset

Of course, knowing that this is a CTF, the most obvious function to reverse first is the `merge` function (`sub_140005c10`). BMP is an image file format, and loading / unloading an image into / from memory seems like the most normal thing ever, so the first thing I did was to start figuring out how this merge functionality worked.

Unfortunately, there were no bugs in this function (I read through it twice just to make sure I wasn't being stupid). So next, I decided to reverse the function that is used to validate the headers of an image that is being loaded (`sub_140002400`) and found the following buggy check at the end (symbols added by typeconfuser later on):

```c
// Only true if a compression method is set
if ( bmp_data->core_header.biCompression )
{
  // Does some stuff
}
else
{
  _asan_load2(&bmp_data->core_header.biBitCount);
  dw_bitCount = bmp_data->core_header.biBitCount;
  _asan_load4(&bmp_data->core_header.biWidth);
  qw_row_size = (((dw_bitCount * bmp_data->core_header.biWidth + 7i64) & 0xFFFFFFFFFFFFFFF8ui64) / 8 + 3) & 0xFFFFFFFFFFFFFFFCui64;
  _asan_load4(&bmp_data->core_header.biHeight);
  qw_total_size = bmp_data->core_header.biHeight * qw_row_size;
  _asan_load4(&bmp_data->core_header.biSizeImage);
  if ( qw_total_size != bmp_data->core_header.biSizeImage ) // [ 1 ]
  {
    asan_printf("Error: invalid image size\n");
    return 0;
  }
}
```

[Here's the BMP File Format Wikipedia page for reference](https://en.wikipedia.org/wiki/BMP_file_format). Basically, if a compression method is set in the BMP that you're loading, then it does some stuff. But if a compression method is ***NOT*** set, then it has a check to ensure that the `(width * bit_count) * height == image_size`.

So basically there seems to be a length(-style) check missing in one case, but not in the other. As you'll soon see, this bug (if it actually was even a bug) wasn't directly useful, but it did tell us one thing: another bug is probably going to manifest itself in the loader (and more likely in one of the decompression functions).

At this point, I had to go out (Saturday night and all), so I summarized what I found on discord, and left.

# Heap overflow

A few hours after I left, typeconfuser started working on this. Although I'm not sure exactly when this bug was found in its entirety, he found one thing in the RLE8 decompression function (`sub_140003820`, called when the image's compression method is set to 1):

```c
qw_cur_size = 0i64;
while ( qw_cur_size < qw_input_data_size )
{
  p_rep_count_byte = &p_input_data[qw_cur_size];
  p_rep_count_byte = &p_input_data[qw_cur_size];
  v11 = v20[(unsigned __int64)&p_input_data[qw_cur_size] >> 3];
  if ( v11 && ((unsigned __int8)p_rep_count_byte & 7) >= v11 )
    _asan_report_load1(p_rep_count_byte);
  b_rep_count = *p_rep_count_byte;
  qw_next_val_offset = qw_cur_size + 1;
  if ( (int)(unsigned __int8)*p_rep_count_byte <= 0 )
  {
    p_next_val = &p_input_data[qw_next_val_offset];
    v23 = &p_input_data[qw_next_val_offset];
    v13 = v20[(unsigned __int64)&p_input_data[qw_next_val_offset] >> 3];
    if ( v13 && ((unsigned __int8)v23 & 7) >= v13 )
      _asan_report_load1(v23);
    rle_flag = *p_next_val; // [ 1 ]
    qw_cur_size = qw_next_val_offset + 1;
    if ( *p_next_val )
    {
      if ( rle_flag == 1 )                    // END OF BITMAP
        return 1;
      if ( rle_flag == 2 )                    // DELTA
      {
        // ...
      }
      else
      {
        // [ 2 ]
        _asan_memcpy(&p_out_decompressed_data[qw_out_data_index], &p_input_data[qw_cur_size], rle_flag);
        qw_out_data_index += rle_flag;
        qw_cur_size += rle_flag;
        if ( rle_flag & 1 )
          ++qw_cur_size;
        if ( qw_cur_size > qw_input_data_size )
          return 0;
        qw_current_offset += rle_flag;
        if ( qw_current_offset > dw_width )   // that should check if it's above or EQUAL, but it doesn't so it's potentially an off-by-one
          return 0;
      }
    }
  // ...
  }

  return 1;
}
```

This function basically starts at `file_offset` bytes into the image (we control `file_offset` as its taken from the image) and starts reading a byte at a time. If the first byte it reads is a 0, then the next byte is read and stored in `rle_flag` at `[ 1 ]`. If `rle_flag` is neither 1 nor 2, it is later used as the length in the `memcpy` at `[ 2 ]`. Although `rle_flags` is a `uint8_t`, we control its value.

The real question is, **can we control the size of the buffer we're copying into**? The answer is yes. The caller of this decompression function allocates `p_out_decompressed_data` for us, and its size is basically `width * height` of the image, so we can allocate a buffer whose size is less than `rle_flags` and trigger this crash.

We didn't 100% know how to trigger this at the time (I was basically checking in on my phone every now and then to see his progress). Around about this time, cts woke up and saw that his fuzzer had found a few crashes in the loader. I'm not sure if one of them was triggering this bug, but him and typeconfuser worked together to create a `buggy.bmp` that triggered this bug. The following crash was posted on discord:

```
=================================================================
==7620==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x12ab25400080 at pc 0x7ff7dcfd024f bp 0x00ab6d4fdde0 sp 0x00ab6d4fddf8
WRITE of size 255 at 0x12ab25400080 thread T0
    #0 0x7ff7dcfd027f in _asan_memcpy+0x2bf (BitmapManager.exe+0x14003027f)
    #1 0x7ff7dcfa3cc5  (BitmapManager.exe+0x140003cc5)
    #2 0x7ff7dcfa439b  (BitmapManager.exe+0x14000439b)
    #3 0x7ff7dcfa58d1  (BitmapManager.exe+0x1400058d1)
    #4 0x7ff7dcfa7712  (BitmapManager.exe+0x140007712)
    #5 0x7ff7dcfeaf13 in operator delete[]+0x1613 (BitmapManager.exe+0x14004af13)
    #6 0x7fffaed27033 in BaseThreadInitThunk+0x13 (C:\Windows\System32\KERNEL32.DLL+0x180017033)
    #7 0x7fffb0bbcec0 in RtlUserThreadStart+0x20 (C:\Windows\SYSTEM32\ntdll.dll+0x18004cec0)

0x12ab25400080 is located 0 bytes to the right of 16-byte region [0x12ab25400070,0x12ab25400080)
allocated by thread T0 here:
    #0 0x7ff7dcfcfd21 in malloc+0x101 (BitmapManager.exe+0x14002fd21)
    #1 0x7ff7dcfa42dd  (BitmapManager.exe+0x1400042dd)
    #2 0x7ff7dcfa58d1  (BitmapManager.exe+0x1400058d1)
    #3 0x7ff7dcfa7712  (BitmapManager.exe+0x140007712)
    #4 0x7ff7dcfeaf13 in operator delete[]+0x1613 (BitmapManager.exe+0x14004af13)
    #5 0x7fffaed27033 in BaseThreadInitThunk+0x13 (C:\Windows\System32\KERNEL32.DLL+0x180017033)
    #6 0x7fffb0bbcec0 in RtlUserThreadStart+0x20 (C:\Windows\SYSTEM32\ntdll.dll+0x18004cec0)
```

# Okay but what about ASAN?

After this bug got found, everyone started looking for writeups of older CTF pwn challenges that had ASAN enabled. Unfortunately, it seemed that all of them were irrelevant. They either required some way to overwrite the shadow memory region to trick ASAN into thinking that some memory was (wrongfully) allowed to be accessed, or it was a use after free situation where ASAN could be bypassed through some tricks. 

This was the end of the night, so our US players decided to take a break, while EU / Asia Pacific players decided to go to bed.

# More auditing

When I woke up the next morning, the first thing I decided to do was audit for more bugs. There are four kinds of bugs that can be used to bypass ASAN ([have a read of the whitepaper](https://static.googleusercontent.com/media/research.google.com/en//pubs/archive/37752.pdf)):

1. **Arbitrary write** - An arbitrary write would let us overwrite the shadow memory region so that we can trick ASAN into not catching the heap overflow, but this is useless as it didn't seem like the Windows ASAN heap had any chunk metadata to overwrite.
2. **OOB R/W with controlled index** - If we can read / write out of bounds at a controlled index, we can bypass ASAN by just skipping past any bytes that we aren't supposed to access.
3. **Use after free** - We could utilize some of the tricks we saw in some writeups to bypass ASAN and use a dangling pointer in a use after free. Only problem was that the only allocations we control seemed to be purely data, no pointers or etc.
4. **Stack bugs** - ASAN is generally not that great when it comes to dealing with use after return / uninitialized stack variable usage style bugs. MemorySanitizer is good for those, but that wasn't enabled.

Knowing all of this, I started auditing again. I was mainly looking for the bugs mentioned above, but also integer signedness issues that could potentially let us control some array index. 

It didn't take me that long to find this other bug in the RLE8 decompression function (the same one with the heap overflow from above):

```c
qw_cur_size = 0i64;
while ( qw_cur_size < qw_input_data_size )
{
  p_rep_count_byte = &p_input_data[qw_cur_size];
  p_rep_count_byte = &p_input_data[qw_cur_size];
  v11 = v20[(unsigned __int64)&p_input_data[qw_cur_size] >> 3];
  if ( v11 && ((unsigned __int8)p_rep_count_byte & 7) >= v11 )
    _asan_report_load1(p_rep_count_byte);
  b_rep_count = *p_rep_count_byte;
  qw_next_val_offset = qw_cur_size + 1; // [ 1 ]
  if ( (int)(unsigned __int8)*p_rep_count_byte <= 0 )
  {
    p_next_val = &p_input_data[qw_next_val_offset]; // [ 2 ]
    v23 = &p_input_data[qw_next_val_offset];
    v13 = v20[(unsigned __int64)&p_input_data[qw_next_val_offset] >> 3];
    if ( v13 && ((unsigned __int8)v23 & 7) >= v13 )
      _asan_report_load1(v23);
    rle_flag = *p_next_val; // [ 3 ]
    // ...
  }
  // ...
}
```

Basically, `qw_cur_size` is a cursor that is used to iterate over `p_input_data` (which is a stack buffer containing the data of the image being decompressed). A byte is read at `p_input_data[qw_cur_size]`, and then `qw_next_val_offset` is set to `qw_cur_size + 1` at `[ 1 ]`. If the byte that was read is <= 0, then `p_next_val` is set to `&p_input_data[qw_next_val_offset]` at `[ 2 ]`.

The bug here is that `qw_cur_size` can potentially point to the very last byte in the `p_input_data` stack buffer. This is because when `p_input_data` is passed into this function, it doesn't actually point to the start of the data buffer. Instead, `p_input_data` is basically `&(data_buffer + image_file_offset)`. Since we control `image_file_offset`, we can have `p_input_data` point to the very last byte of the image.

If we do that, `qw_next_val_offset` is set to `qw_cur_size + 1` at `[ 1 ]`. When this happens, it will point one index out of bounds of the buffer. At `[ 2 ]`, `p_next_val` will the address of this index, and later put the byte at this index into `rle_flag` at `[ 3 ]`. This gives you an out of bounds off by one read primitive.

Initially when I saw this bug, I thought `p_input_data` was a heap buffer, and so thought this bug was pretty useless (what can you do with a heap OOB read? ASAN will catch it anyway). Of course I was wrong, as this was the one bug that kickstarted the exploit.

# A hint

I spent a few more hours auditing, but around ~33 hours into the CTF, I was ready to give up. There were no other bugs to be seen, and we couldn't come up with a way to bypass ASAN. typeconfuser thought that this challenge would have something to do with the C++ STL (reasoning being why else is the author using C++ on Windows for this anyway?), but we didn't go down that path.

After taking a break for a while, j00ru released a hint for the challenge ~38 hours into the CTF:

> **HINT:** Loading the flag in memory is half the battle. Now how can you get it out of there?

As soon as we saw the hint, we started discussing what it meant, and within ~25 minutes, we had a working idea put together (after some failed ideas of course).

# PoC

This part of our solve was honestly a great example of why it's so useful to work together (instead of working solo) when it comes to really hard challenges like this one.

## Primitive one

RBTree pointed out that if you try to load the flag file from `..\flag.txt` (challenge stated the flag was in the current directory, and there was no check against path traversal), then the bytes are read into a buffer on the stack. Of course, the function that validates the headers of the flag's data will fail, but the bytes will remain on the stack:

```c
if ( get_bmp_count(&g_bmp_array) <= 0x14 )
{
  asan_printf("Name: ");
  _asan_memcpy(bmp_name, "bitmaps\\", 9i64); // Check the bitmaps directory
  _asan_memset(&bmp_name[9], 0i64, 247i64);
  scanf("%240s", &bmp_name[8]);
  bmp_file_o = fopen(bmp_name, "rb"); // open file (assume we open ..\flag.txt)
  if ( bmp_file_o )
  {
    fseek(bmp_file_o, 0, 2);
    qw_bmp_size = ftell(bmp_file_o);
    fseek(bmp_file_o, 0, 0);
    if ( qw_bmp_size <= 0x1800 )
    {
      // Bytes are read into `bmp_data`, which is at `rbp-0x1888`
      bytes_did_read = fread(&bmp_data, 1i64, qw_bmp_size, bmp_file_o);
      if ( bytes_did_read == qw_bmp_size )
      {
        fclose(bmp_file_o);

        // This check fails, but the data is still on the stack afterwards in bmp_data
        if ( validate_header(&bmp_data, qw_bmp_size) )
          decode_bmp(&bmp_name[8], &bmp_data, qw_bmp_size);
      }
    }
  }
}
```

## Primitive two

Knowing this, next thing we had to figure out was whether there was any other function with an overlapping stack frame + a stack variable (whose data we can control) that overlaps the `bmp_data` variable. This had to be one of the menu functions as those were the only ones that would be in the same stack frame as the `load_builtin` function above.

I found that the `load` function was perfect for this:

```c
__int64 load_builtin()
{
  // ...
  bmp_data bmp_data; // [rsp+160h] [rbp-1888h]
  // ...
}

__int64 load()
{
  // ...
  char bmp_data[6400]; // [rsp+160h] [rbp-19A8h]
  // ...
}
```

As you can see, in `load_builtin`, the `bmp_data` variable is at `rbp-0x1888`. In `load`, the `bmp_data` array is at `rbp-0x19a8`. This means that if we load the flag through `load_builtin` first, we can then load an image through the `load_bitmap` function and have its size be exactly `0x19a8 - 0x1888 == 0x120` bytes (288 bytes). 

This will load our image into the stack, and have it be such that our image's stack data is perfect aligned with the start of the flag. Remember the off by one I found? This is where it will be used to leak the flag byte by byte. 

Okay, now how do we do that?

## Primitive three

typeconfuser pointed out that the `rle_flags` variable, when combined with ASAN, can be used as a crashing oracle to leak the flag one byte at a time. His initial method of doing this wasn't fully correct, but after I pointed out the off by one bug I found, he wrote up a perfect summary of what to do (right click and view image):

![1.png](/images/bitmapmanager/1.png)

The exploit basically uses this crashing oracle to leak the flag a byte at a time. In order to do it correctly, me and RBTree spent a while trying to come up with the perfectly crafted 288 byte image. In the end, it was RBTree who wrote the final exploit script. It's not easy to explain the exploit, but I'll do my best.

# The exploit

typeconfuser's summary states that we need to change the output buffer size each time and figure out when ASAN doesn't crash. Basically, in the RLE8 decompression function, if we get `rle_flags` set to the first byte of the flag (by using primitives one and two combined with the off by one), then the `memcpy` will use that flag byte as the length argument. 

Since we can control the size of the buffer that is being copied into, we can initially allocate a small sized buffer (which will surely cause an ASAN crash due to the overflow). Each time it crashes, we increase the size of the buffer by 1 and try again. As soon as the binary doesn't crash, we know that we got the size of the buffer ***just right***, which means the size of the buffer == the flag byte, meaning the flag byte was leaked!

Although this method would work, it's not completely ideal because of two reasons:

1. We'd have to dynamically modify the width and the height of the image every time (remember that the output buffer size is `width * height`). This means we'd have to ensure the header validation checks pass every time, which is annoying to write code for (it would also be extremely slow).
2. ASAN does not have byte level granularity. It has 8 byte granularity. This basically means that for every 8 bytes of actual memory, there is one byte of shadow memory that determines whether those 8 bytes are allowed to be accessed or not. If we try to increase the size of the buffer one at a time, then there can be some very unlucky cases where we'll have to guess between 2 to 8 possible ascii values for the flag byte that we're leaking, which is definitely not ideal.

Fortunately, RBTree found something else in the RLE8 decompression function:

```c
while ( qw_cur_size < qw_input_data_size )
{
  p_rep_count_byte = &p_input_data[qw_cur_size];
  p_rep_count_byte = &p_input_data[qw_cur_size];
  v11 = v20[&p_input_data[qw_cur_size] >> 3];
  if ( v11 && (p_rep_count_byte & 7) >= v11 )
    _asan_report_load1(p_rep_count_byte);
  b_rep_count = *p_rep_count_byte;
  qw_next_val_offset = qw_cur_size + 1;
  if ( *p_rep_count_byte <= 0 ) // [ 1 ]
  {
    // ...
  }
  else
  {
    if ( qw_next_val_offset + 1 > qw_input_data_size )
      return 0;
    p_byte_2_repeat = &p_input_data[qw_next_val_offset];
    p_byte_2_repeat = &p_input_data[qw_next_val_offset];
    v12 = v20[&p_input_data[qw_next_val_offset] >> 3];
    if ( v12 )
    {
      if ( (p_byte_2_repeat & 7) >= v12 )
        _asan_report_load1(p_byte_2_repeat);
    }
    qw_cur_size = qw_next_val_offset + 1;
    if ( dw_width - qw_current_offset < b_rep_count )
      return 0;
    
    // [ 2 ]
    _asan_memset(&p_out_decompressed_data[qw_out_data_index], *p_byte_2_repeat, b_rep_count);
    qw_out_data_index += b_rep_count;
    qw_current_offset += b_rep_count;
  }
}
```

If the condition at `[ 1 ]` is true, we can trigger the heap buffer overflow. However, if it is not true, then in the else condition, `b_rep_count` bytes in the output buffer are set to `p_byte_2_repeat` at `[ 2 ]`. After this, the `qw_out_data_index` variable is shifted forward by `b_rep_count` bytes.

Note that in this instance, we control both `p_byte_2_repeat` and `b_rep_count`. The exploit basically utilizes this in the following way (the steps are for leaking the first byte of the flag, but you just increment the size of your image to leak the remaining bytes):

1. Craft an image with `width = 128`, `height = 1`, and a total size of 288 bytes. The output buffer size is then 128 bytes (`width * height`).
2. Have the file offset set to `(image_size - 3)`, so that when the RLE8 decompression runs, it starts reading data from offset `(image_size - 3)`.
3. The first byte the RLE8 decompression function reads will be the `length` parameter of the `memset` from above. We set this to `128 - (byte_value_of_guessed_char)`. This will basically leave a space of `ord(guessed_char)` bytes in the output buffer.
    * Basically, if the character we're guessing is "A", then the decompression will memset `128 - 0x41` bytes of the output buffer and move the `qw_out_data_index` variable forward by that much.
4. The second byte the RLE8 function reads is the second parameter to `memset`. This can be anything since it doesn't matter. In the exploit, it is set to "A".
5. After the previous two steps, the while loop will repeat, and the decompression function will read a new byte. This byte will be the very last byte in the image. We set this byte to 0, as we now want the heap overflow to occur.
6. Next, since we're at the end of the image, this means that the next byte that is outside our image's data buffer is going to be the first character of the flag (due to primitives one and two). The off by one will read this byte into `rle_flags` (scroll up to check the function for reference).
7. Once it does this, it will do a `memcpy(&p_out_decompressed_data[qw_out_data_index], <some_src_buf>, rle_flags)`.

Now, remember that `p_out_decompressed_data` buffer only has `ord(guessed_char)` bytes of space left in it (the `qw_out_data_index` pointer was moved forward accordingly too). We basically have two possible situations:

1. If the ordinal value of the flag's first byte is greater than `ord(guessed_char)`, then a heap overflow will occur and ASAN will crash.
2. If the ordinal value of the flag's first byte is smaller than `ord(guessed_char)`, then we get a message saying decompression failed.

Using this as a crashing oracle, we can do a binary search over the possible character space to exhaust every byte until we guess just the right character for which no crash occurs.

# The end

[The final exploit script can be found here](https://gist.github.com/farazsth98/ace514498e5e5ac68c2bd7dc3ec2fdb8). It was a great challenge (might be the most unique one I've seen this year tbh), and I really hope to see more like this in other CTFs.

Now please send me a writeup for `no-eeeeeeeeeeeemoji` T_T
