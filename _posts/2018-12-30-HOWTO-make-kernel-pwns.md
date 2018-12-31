---
layout: post
title: HOWTO make kernel pwnables
category: [Exploitation]
tags: [Exploitation, kernel, qemu]
comments: true
hidden: false
---

## Summary

Basically we will build a minimal kernel to support initramfs, user permissions and custom modules. Than we will package Busybox in a cpio archive and script init and module installation. Then we will launch it with QEMU and containerize it as a xinetd service in docker (described [here](https://github.com/OpenToAllCTF/OTA-University/tree/master/challenge_templates/pwn)).

## Compile Kernel

This step is not required if you are targeting a standard kernel that you can grab from some distro. Most of the time however, we need to disable some exploit mitigations so we need to compile it ourselves. For this example I will use [4.20](https://www.kernel.org/). There are multiple tutorials online about how to compile a kernel. To make a minimal config use `allnoconfig` make configuration and enable the following options.

{% highlight bash %}
➜  kernel_pwn tar -zvf linux-4.20.tar.xz
➜  kernel_pwn cd linux-4.20
➜  linux-4.20 make allnoconfig
➜  linux-4.20 make menuconfig
{% endhighlight %}

```
64-bit kernel ---> yes
Enable loadable module support ---> yes
General setup ---> Initial RAM filesystem and RAM disk (initramfs/initrd) support ---> yes
General setup ---> Configure standard kernel features ---> Multiple users, groups and capabilities support ---> yes
General setup ---> Configure standard kernel features ---> Sysfs syscall support ---> yes
General setup ---> Configure standard kernel features ---> Enable support for printk ---> yes
General setup ---> Configure standard kernel features ---> Load all symbols for debugging/ksymoops ---> yes
General setup ---> Configure standard kernel features ---> Include all symbols in kallsyms ---> yes
Executable file formats / Emulations ---> Kernel support for ELF binaries ---> yes
Executable file formats / Emulations ---> Kernel support for scripts starting with #! ---> yes
Binary Emulations ---> IA32 Emulations ---> yes
Binary Emulations ---> IA32 a.out support ---> yes
Binary Emulations ---> IA32 ABI for 64-bit mode ---> yes
Device Drivers ---> Generic Driver Options ---> Maintain a devtmpfs filesystem to mount at /dev ---> yes
Device Drivers ---> Generic Driver Options ---> Automount devtmpfs at /dev, after the kernel mounted the rootfs ---> yes
Device Drivers ---> Character devices ---> Enable TTY ---> yes
Device Drivers ---> Character devices ---> Serial drivers ---> 8250/16550 and compatible serial support ---> yes
Device Drivers ---> Character devices ---> Serial drivers ---> Console on 8250/16550 and compatible serial port ---> yes
File systems ---> Pseudo filesystems ---> /proc file system support ---> yes
File systems ---> Pseudo filesystems ---> sysfs file system support ---> yes
```

### Exploit Mitigations

Here is a list of exploit mitigations that might need to be disabled/enabled for your particular challenge.

* Ensure /proc/kallsyms is readable by non-root users
* Allocations at NULL to allow nullptr de-reference (DEFAULT_MMAP_MIN_ADDR=0)
* SMAP (Superuser Mode Access Prevention) to allow kernel space code accessing and executing user-space data directly
* KASLR (RANDOMIZE_BASE) to ensure the kernel is mapped at the same address after every reboot
* Stack Protector buffer overflow detection to disable/enable stack canaries

To easily find where these options are in the menuconfig you can use the search `/` just like in vim. If multiple results are found you can select the right one by pressing the number assigned to it (1/2/3/4/5...).

Now let's build and test it with the following `start.sh` script.

{% highlight bash %}
➜  linux-4.20 make
...
➜  linux-4.20 file vmlinux
vmlinux: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=d4660ac0baf52fcd4103114b16126afc745a0c5d, not stripped

➜  linux-4.20 file arch/x86_64/boot/bzImage
arch/x86_64/boot/bzImage: symbolic link to ../../x86/boot/bzImage

➜  linux-4.20 file arch/x86/boot/bzImage
arch/x86/boot/bzImage: Linux kernel x86 boot executable bzImage, version 4.20.0 (vagrant@vagrant) #2 Sun Dec 30 22:53:48 UTC 2018, RO-rootFS, swap_dev 0x1, Normal VGA

➜  linux-4.20 cp arch/x86/boot/bzImage ..
➜  linux-4.20 cd ..
➜  kernel_pwn ls
bzImage  linux-4.20  start.sh
➜  kernel_pwn cat start.sh
#!/bin/sh

qemu-system-x86_64 \
	-m 64 \
	-kernel bzImage \
	-nographic \
	-append "console=ttyS0 quiet" \
	-monitor /dev/null

➜  kernel_pwn ./start.sh
warning: TCG doesn't support requested feature: CPUID.01H:ECX.vmx [bit 5]
Spectre V2 : Spectre mitigation: kernel not compiled with retpoline; no mitigation available!
Kernel panic - not syncing: No working init found.  Try passing init= option to kernel. See Linux Documentation/admin-guide/init.rst for guidance.
Kernel Offset: disabled
---[ end Kernel panic - not syncing: No working init found.  Try passing init= option to kernel. See Linux Documentation/admin-guide/init.rst for guidance. ]---
{% endhighlight %}

Seems like it's booting fine but unable to start the init process (PID 1). Since we enabled initramfs and #! scripts support, let's create `/init` bash script that would mount the appropriate Pseudo Filesystems and drop us into a shell.

## Initramfs

To be able to execute a bash script we need to install bash itself as well the other bin/sbin utils. Busybox is the perfect collection of statically compiled utils for this job. You can compile it yourself or like me you can download the precompiled binary from [here](https://busybox.net/downloads/binaries/)

{% highlight bash %}
➜  kernel_pwn mkdir initramfs
➜  kernel_pwn cd initramfs
➜  initramfs wget https://busybox.net/downloads/binaries/1.21.1/busybox-x86_64
--2018-12-30 23:16:34--  https://busybox.net/downloads/binaries/1.21.1/busybox-x86_64
Resolving busybox.net (busybox.net)... 140.211.167.122
Connecting to busybox.net (busybox.net)|140.211.167.122|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 973200 (950K)
Saving to: ‘busybox-x86_64’

busybox-x86_64            100%[==================================>] 950.39K  1.39MB/s    in 0.7s

2018-12-30 23:16:35 (1.39 MB/s) - ‘busybox-x86_64’ saved [973200/973200]

➜  initramfs mkdir bin
➜  initramfs mv busybox-x86_64 bin/busybox
➜  initramfs cd bin
➜  bin chmod +x busybox
➜  bin ./busybox --install .
➜  bin chmod 755 -R .
{% endhighlight %}

We can get an example `init` script from our own linux distro and cherry-pick the commands we need.

{% highlight bash %}
➜  kernel_pwn cd tmp
➜  tmp file /boot/initrd.img-4.10.0-19-generic
/boot/initrd.img-4.10.0-19-generic: gzip compressed data, last modified: Sun Dec  2 18:41:43 2018, from Unix
➜  tmp cp /boot/initrd.img-4.10.0-19-generic .
➜  tmp mv initrd.img-4.10.0-19-generic initrd.img-4.10.0-19-generic.gz
➜  tmp gunzip initrd.img-4.10.0-19-generic.gz
➜  tmp file initrd.img-4.10.0-19-generic
initrd.img-4.10.0-19-generic: ASCII cpio archive (SVR4 with no CRC)
➜  tmp cpio -i < initrd.img-4.10.0-19-generic
211566 blocks
➜  tmp l
total 104M
drwxrwxr-x 12 vagrant vagrant 4.0K Dec 30 23:25 .
drwxrwxr-x  5 vagrant vagrant 4.0K Dec 30 23:24 ..
drwxr-xr-x  2 vagrant vagrant 4.0K Dec 30 23:25 bin
drwxr-xr-x  3 vagrant vagrant 4.0K Dec 30 23:25 conf
drwxr-xr-x 10 vagrant vagrant 4.0K Dec 30 23:25 etc
-rwxr-xr-x  1 vagrant vagrant 6.6K Dec 30 23:25 init
-rw-r--r--  1 vagrant vagrant 104M Dec 30 23:24 initrd.img-4.10.0-19-generic
drwxr-xr-x  8 vagrant vagrant 4.0K Dec 30 23:25 lib
drwxr-xr-x  2 vagrant vagrant 4.0K Dec 30 23:25 lib64
drwxr-xr-x  2 vagrant vagrant 4.0K Dec 30 23:25 run
drwxr-xr-x  2 vagrant vagrant 4.0K Dec 30 23:25 sbin
drwxr-xr-x 10 vagrant vagrant 4.0K Dec 30 23:25 scripts
drwxr-xr-x  4 vagrant vagrant 4.0K Dec 30 23:25 usr
drwxr-xr-x  3 vagrant vagrant 4.0K Dec 30 23:25 var
➜  tmp cat init
#!/bin/sh
...
{% endhighlight %}

Here is what I'll use for this example

{% highlight bash %}
➜  initramfs ls -lha
total 32K
drwxrwxr-x 3 vagrant vagrant  12K Dec 30 23:38 .
drwxrwxr-x 5 vagrant vagrant 4.0K Dec 30 23:36 ..
drwxr-xr-x 2 vagrant vagrant  12K Dec 30 23:17 bin
-rwxr-xr-x 1 vagrant vagrant 1.4K Dec 30 23:38 init
➜  initramfs cat init
#!/bin/sh

export PATH=/bin

[ -d /dev ] || mkdir -m 0755 /dev
[ -d /sys ] || mkdir /sys
[ -d /proc ] || mkdir /proc
[ -d /tmp ] || mkdir /tmp
[ -d /run ] || mkdir /run
[ -d /root ] || mkdir /root
[ -d /etc ] || mkdir /etc
[ -d /home ] || mkdir /home

echo 'root:x:0:0:root:/root:/bin/sh' > /etc/passwd
echo 'root:x:0:' > /etc/group
chmod 644 /etc/passwd
chmod 644 /etc/group

adduser user --disabled-password

chown -R root:root /
chmod 700 -R /root
chown user:user /home/user
chmod 777 /home/user
chmod 755 /dev

mkdir -p /var/lock
mount -t sysfs -o nodev,noexec,nosuid sysfs /sys
mount -t proc -o nodev,noexec,nosuid proc /proc
ln -sf /proc/mounts /etc/mtab
mount -t devtmpfs -o nosuid,mode=0755 udev /dev
mkdir -p /dev/pts
mount -t devpts -o noexec,nosuid,gid=5,mode=0620 devpts /dev/pts || true
mount -t tmpfs -o "noexec,nosuid,size=10%,mode=0755" tmpfs /run

echo 0 > /proc/sys/kernel/kptr_restrict
echo 1 > /proc/sys/kernel/perf_event_paranoid

#modprobe lab10C
#chmod o+rw /dev/pwn

cat <<EOF


Boot took $(cut -d' ' -f1 /proc/uptime) seconds

        ___           ___           ___
       /\  \         /\  \         /\  \
      /::\  \        \:\  \       /::\  \
     /:/\:\  \        \:\  \     /:/\:\  \
    /:/  \:\  \       /::\  \   /::\~\:\  \
   /:/__/ \:\__\     /:/\:\__\ /:/\:\ \:\__\
   \:\  \ /:/  /    /:/  \/__/ \/__\:\/:/  /
    \:\  /:/  /    /:/  /           \::/  /
     \:\/:/  /     \/__/            /:/  /
      \::/  /                      /:/  /
       \/__/                       \/__/


EOF

exec su user
exec /bin/sh

➜  initramfs
{% endhighlight %}

Now let's compress it into a cpio format and test it out.

{% highlight bash %}
➜  initramfs find . | cpio -H newc -ov -F ../initramfs.cpio

{% endhighlight %}

Append the `-initrd` option to the qemu-system command line arguments.

{% highlight bash %}
➜  kernel_pwn cat start.sh
#!/bin/sh

qemu-system-x86_64 \
	-m 64 \
	-kernel bzImage \
	-nographic \
	-append "console=ttyS0 quiet" \
	-initrd initramfs.cpio \
	-monitor /dev/null \

➜  kernel_pwn
➜  kernel_pwn ./start.sh

Boot took 0.64 seconds

        ___           ___           ___
       /\  \         /\  \         /\  \
      /::\  \        \:\  \       /::\  \
     /:/\:\  \        \:\  \     /:/\:\  \
    /:/  \:\  \       /::\  \   /::\~\:\  \
   /:/__/ \:\__\     /:/\:\__\ /:/\:\ \:\__\
   \:\  \ /:/  /    /:/  \/__/ \/__\:\/:/  /
    \:\  /:/  /    /:/  /           \::/  /
     \:\/:/  /     \/__/            /:/  /
      \::/  /                      /:/  /
       \/__/                       \/__/


           Welcome to OTA-University
                   MBE lab10C

sh: can't access tty; job control turned off
/ $ id
uid=1000(user) gid=1000(user) groups=1000(user)
/ $
{% endhighlight %}

## Vulnerable Module

As you have figured out if you are paying attention to details (from the commented out modprobe command), I will package [MBE lab10C](https://raw.githubusercontent.com/RPISEC/MBE/master/src/lab10/lab10C.c) as an example vulnerable module.

{% highlight bash %}
➜  kernel_pwn cd initramfs
➜  initramfs mkdir -p lib/modules/4.20.0
➜  initramfs cd lib/modules/4.20.0
➜  4.20.0 wget https://raw.githubusercontent.com/RPISEC/MBE/master/src/lab10/lab10C.c
--2018-12-31 00:07:42--  https://raw.githubusercontent.com/RPISEC/MBE/master/src/lab10/lab10C.c
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 151.101.24.133
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|151.101.24.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2820 (2.8K) [text/plain]
Saving to: ‘lab10C.c’

lab10C.c                  100%[==================================>]   2.75K  --.-KB/s    in 0s

2018-12-31 00:07:42 (20.4 MB/s) - ‘lab10C.c’ saved [2820/2820]

➜  4.20.0
{% endhighlight %}

The module's destination folder needs to match the kernel version or modprobe won't be able to find the module. Let's compile it.

{% highlight bash %}

obj-m += lab10C.o

KDIR="/home/vagrant/kernel_pwn/linux-4.20/"

all:
		make -C $(KDIR) M=$(PWD) modules

clean:
		make -C $(KDIR) M=$(PWD) clean

{% endhighlight %}

Uncomment the `modprobe` commands from the `init` script and rebuild the cpio archive. We can confirm the module is loaded successfully.

{% highlight bash %}
➜  kernel_pwn ./start.sh

Boot took 0.62 seconds

        ___           ___           ___
       /\  \         /\  \         /\  \
      /::\  \        \:\  \       /::\  \
     /:/\:\  \        \:\  \     /:/\:\  \
    /:/  \:\  \       /::\  \   /::\~\:\  \
   /:/__/ \:\__\     /:/\:\__\ /:/\:\ \:\__\
   \:\  \ /:/  /    /:/  \/__/ \/__\:\/:/  /
    \:\  /:/  /    /:/  /           \::/  /
     \:\/:/  /     \/__/            /:/  /
      \::/  /                      /:/  /
       \/__/                       \/__/


sh: can't access tty; job control turned off
/ $ lsmod
lab10C 16384 - - Live 0xffffffffa0000000 (O)
/ $
{% endhighlight %}

Don't forget to clean up the directory where we build the module, this was just an example after all, I would normally not build there. You can place the flag in /root and ensure proper permissions are set, make sure you don't redistribute the initramfs with the real flag to your users. Now you can launch qemu-system-x86 from xinetd packaged in a docker container and your challenge is ready. Because xinetd won't terminate the connection when users close theirs (with ctrl+d for example) and your docker container doesnt end up with hundreds of stale qemu-system processes, prefix the `qemu-system-x86` command with the `timeout` utility as such.

{% highlight bash %}
➜  kernel_pwn cat start.sh
#!/bin/sh

timeout --foreground 300 qemu-system-x86_64 \
	-m 64 \
	-kernel bzImage \
	-initrd initramfs.cpio \
	-nographic \
	-append "console=ttyS0 noapic quiet" \
	-monitor /dev/null \

{% endhighlight %}

## References
> [Minimal linux with Busybox for Qemu](https://gist.github.com/chrisdone/02e165a0004be33734ac2334f215380e)