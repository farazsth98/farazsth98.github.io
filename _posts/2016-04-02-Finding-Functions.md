---
layout: post
title: Finding Function's Load Address
category: [Exploitation, Misc]
tags: [Exploitation, PoC]
comments: true
---

## Death by Pointer

The typical way of finding function addresses is by calculating the offset to the desired function from the address of another function in the same library that we have leaked. However, for this method to work effectively the gLibc's version of the remote server needs to be the same as ours. We can also find the remote version's of gLibc by leaking a few functions and searching in [libcdb.com](http://libcdb.com/) but sometimes this method fails.

## DynELF

If we have a function that allows us to leak memory at any given address we could use something like [DynELF](http://pwntools.readthedocs.org/en/latest/dynelf.html) using [pwntools](http://pwntools.readthedocs.org/en/latest/about.html) / [binjitsu](https://github.com/binjitsu/binjitsu). As described in the documentation, DynELF uses 2 main techniques. First it finds the base address of gLibc and second it parses through all of the symbols using the [Symbol Table Section](https://docs.oracle.com/cd/E19683-01/817-3677/6mj8mbtc9/index.html#chapter6-79797) and the [String Table Section](https://docs.oracle.com/cd/E19683-01/817-3677/6mj8mbtc9/index.html#chapter6-73709) until it finds the symbol of the function we are looking for.  

There are just a few details that I would like to put together, which are the real reason for this blog post :).

## Finding GNU C Library's Base Address

To find the base address of gLibc we first need to grab an address inside the gLibc's address space. We can do that by looking into the binary's Global Offset Table for an already resolved address. Next we can parse through that address space using the leak with decrements of the memory page size (0x1000) until we find the `\x7fELF` magic constant indicating the base load address. Here is example code to do that:

{% highlight python %}
# leak func returns n number of bytes from given address
def findLibcBase(ptr):
   ptr &= 0xfffffffffffff000
   while leak(ptr, 4) != "\x7fELF":
      ptr -= 0x1000
   return ptr
{% endhighlight %}

## Finding the [Program Header](https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-83432.html#scrolltoc)

The Program Header contains an array of structures `Elf32_Phdr/Elf64_Phdr`, each structure holds information about existing segments in the binary. 

To find where the Program Header begins, it's simple as looking at offset 0x1c for 32bit binary or 0x20 for 64bit binary in the ELF header (module's base address).

The `Elf32_Phdr` structure contains the following elements:

{% highlight text %}
typedef struct {
        Elf32_Word      p_type;
        Elf32_Off       p_offset;
        Elf32_Addr      p_vaddr;
        Elf32_Addr      p_paddr;
        Elf32_Word      p_filesz;
        Elf32_Word      p_memsz;
        Elf32_Word      p_flags;
        Elf32_Word      p_align;
} Elf32_Phdr;
{% endhighlight %}

Example code to find the beginning of the Program Header:

{% highlight python %}
# addr argument is the module's base address or rather the beginning of ELF Header
def findPhdr(addr):
   if bits == 32:
      e_phoff = u32(leak(addr + 0x1c, wordSz).ljust(4, '\0'))
   else:
      e_phoff = u64(leak(addr + 0x20, wordSz).ljust(8, '\0'))
   return e_phoff + addr
{% endhighlight %}

## Finding the [DYNAMIC](https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-42444.html) Section

Our next goal is to identify the Elf32_Phdr structure specific for the DYNAMIC Section. We can do this by parsing throught all of the Program Header structures until we find the element `Elf32_Phdr->p_type == 2`. Once we find it, the element `Elf32_Phdr->p_vaddr` contains the virtual load address of the DYNAMIC Section.

Example code to find the DYNAMIC Section:

{% highlight python %}
def findDynamic(Elf32_Phdr, bitSz):
   if bitSz == 32:
      i = -32
      p_type = 0
      while p_type != 2:
         i += 32
         p_type = u32(leak(Elf32_Phdr + i, wordSz).ljust(4, '\0'))
      return u32(leak(Elf32_Phdr + i + 8, wordSz).ljust(4, '\0'))    # + PIE
   else:
      i = -56
      p_type = 0
      while p_type != 2:
         i += 56
         p_type = u64(leak(Elf32_Phdr + i, hwordSz).ljust(8, '\0'))
      return u64(leak(Elf32_Phdr + i + 16, wordSz).ljust(8, '\0'))   # + PIE
{% endhighlight %}

For PIE (Possition Independent Executable) binaries, at `Elf32_Phdr->p_vaddr` there's gonna be an offset from the module's base address. For non-PIE binaries there's gonna be a virtual load address.

The DYNAMIC Section contains an array of `Elf32_Dyn/Elf64_Dyn` structures. Each structure contains information about section tables participating in the dynamic linking process. Some of them include `DT_GOTPLT`, `DT_HASH`, `DT_STRTAB`, `DT_SYMTAB`, `DT_DEBUG` any many [more](https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-42444.html).

The dynamic section tables we are interested in are [DT_SYMTAB](http://docs.oracle.com/cd/E19253-01/817-1984/chapter6-79797/index.html) aka Symbol Table and [DT_STRTAB](http://docs.oracle.com/cd/E19253-01/817-1984/chapter6-73709/index.html) aka String Table.

## Finding the [DT_SYMTAB](http://docs.oracle.com/cd/E19253-01/817-1984/chapter6-79797/index.html) and [DT_STRTAB](http://docs.oracle.com/cd/E19253-01/817-1984/chapter6-73709/index.html)

The Symbol Table contains an array of `Elf32_Sym/Elf64_Sym` structures. There is a structure for each symbol/function we want to locate. The load address of the functions can be found in `Elf32_Sym->st_value` element. The `Elf32_Sym->st_name` element holds an offset in the `DT_STRTAB` which is where the string for the symbol in question is located.

Example code of finding `DT_STRTAB` and `DT_SYMTAB`:

{% highlight python %}
def findDynTable(Elf32_Dyn, table, bitSz):
   p_val = 0
   if bitSz == 32:
      i = -8
      while p_val != table:
         i += 8
         p_val = u32(leak(Elf32_Dyn + i, wordSz).ljust(4, '\0'))
      return u32(leak(Elf32_Dyn + i + 4, wordSz).ljust(4, '\0'))
   else:
      i = -16
      while p_val != table:
         i += 16
         p_val = u64(leak(Elf32_Dyn + i, wordSz).ljust(8, '\0'))
      return u64(leak(Elf32_Dyn + i + 8, wordSz).ljust(8, '\0'))

DT_STRTAB = findDynTable(libcDynamic, 5, bits)

DT_SYMTAB = findDynTable(libcDynamic, 6, bits)

{% endhighlight %}

## Finding Function Addresses

To find the target symbol table we parse through each `Elf32_Sym->st_name` until `DT_STRTAB[Elf32_Sym->st_name] == target_symbol`.
Once the above proves True we have found the target `Elf32_Sym` struct, now we just look in the `Elf32_Sym->st_value` element to get the load address of the target symbol.

Example snippet:

{% highlight python %}
def findSymbol(strtab, symtab, symbol, bitSz):
   if bitSz == 32:
      i = -16
      while True:
         i += 16
         st_name = u32(leak(symtab + i, 2).ljust(4, '\0'))
         if leak( strtab + st_name, len(symbol)+1 ).lower() == (symbol.lower() + '\0'):
            return u32(leak(symtab + i + 4, 4).ljust(4, '\0'))
   else:
      i = -24
      while True:
         i += 24
         st_name = u64(leak(symtab + i, 4).ljust(8, '\0'))
         if leak( strtab + st_name, len(symbol)).lower() == (symbol.lower()):
            return u64(leak(symtab + i + 8, 8).ljust(8, '\0'))
{% endhighlight %}

## Finalized Example

Here we are gonna read from `/proc/<pid>/mem` simulating a leak function. Using the above example let's see how it finds the address of `system`.

{% highlight python %}
#!/usr/bin/env python

from pwn import *
import sys, os

wordSz = 4
hwordSz = 2
bits = 32
PIE = 0

def leak(address, size):
   with open('/proc/%s/mem' % pid) as mem:
      mem.seek(address)
      return mem.read(size)

def findModuleBase(pid, mem):
   name = os.readlink('/proc/%s/exe' % pid)
   with open('/proc/%s/maps' % pid) as maps: 
      for line in maps:
         if name in line:
            addr = int(line.split('-')[0], 16)
            mem.seek(addr)
            if mem.read(4) == "\x7fELF":
               bitFormat = u8(leak(addr + 4, 1))
               if bitFormat == 2:
                  global wordSz
                  global hwordSz
                  global bits
                  wordSz = 8
                  hwordSz = 4
                  bits = 64
               return addr
   log.failure("Module's base address not found.")
   sys.exit(1)

def findIfPIE(addr):
   e_type = u8(leak(addr + 0x10, 1))
   if e_type == 3:
      return addr
   else:
      return 0

def findPhdr(addr):
   if bits == 32:
      e_phoff = u32(leak(addr + 0x1c, wordSz).ljust(4, '\0'))
   else:
      e_phoff = u64(leak(addr + 0x20, wordSz).ljust(8, '\0'))
   return e_phoff + addr

def findDynamic(Elf32_Phdr, moduleBase, bitSz):
   if bitSz == 32:
      i = -32
      p_type = 0
      while p_type != 2:
         i += 32
         p_type = u32(leak(Elf32_Phdr + i, wordSz).ljust(4, '\0'))
      return u32(leak(Elf32_Phdr + i + 8, wordSz).ljust(4, '\0')) + PIE
   else:
      i = -56
      p_type = 0
      while p_type != 2:
         i += 56
         p_type = u64(leak(Elf32_Phdr + i, hwordSz).ljust(8, '\0'))
      return u64(leak(Elf32_Phdr + i + 16, wordSz).ljust(8, '\0')) + PIE

def findDynTable(Elf32_Dyn, table, bitSz):
   p_val = 0
   if bitSz == 32:
      i = -8
      while p_val != table:
         i += 8
         p_val = u32(leak(Elf32_Dyn + i, wordSz).ljust(4, '\0'))
      return u32(leak(Elf32_Dyn + i + 4, wordSz).ljust(4, '\0'))
   else:
      i = -16
      while p_val != table:
         i += 16
         p_val = u64(leak(Elf32_Dyn + i, wordSz).ljust(8, '\0'))
      return u64(leak(Elf32_Dyn + i + 8, wordSz).ljust(8, '\0'))

def getPtr(addr, bitSz):
   with open('/proc/%s/maps' % sys.argv[1]) as maps: 
      for line in maps:
         if 'libc-' in line and 'r-x' in line:
            libc = line.split(' ')[0].split('-')
   i = 3
   while True:
      if bitSz == 32:
         gotPtr = u32(leak(addr + i*4, wordSz).ljust(4, '\0'))
      else:
         gotPtr = u64(leak(addr + i*8, wordSz).ljust(8, '\0'))
      if (gotPtr > int(libc[0], 16)) and (gotPtr < int(libc[1], 16)):
         return gotPtr
      else:
         i += 1
         continue

def findLibcBase(ptr):
   ptr &= 0xfffffffffffff000
   while leak(ptr, 4) != "\x7fELF":
      ptr -= 0x1000
   return ptr

def findSymbol(strtab, symtab, symbol, bitSz):
   if bitSz == 32:
      i = -16
      while True:
         i += 16
         st_name = u32(leak(symtab + i, 2).ljust(4, '\0'))
         if leak( strtab + st_name, len(symbol)+1 ).lower() == (symbol.lower() + '\0'):
            return u32(leak(symtab + i + 4, 4).ljust(4, '\0'))
   else:
      i = -24
      while True:
         i += 24
         st_name = u64(leak(symtab + i, 4).ljust(8, '\0'))
         if leak( strtab + st_name, len(symbol)).lower() == (symbol.lower()):
            return u64(leak(symtab + i + 8, 8).ljust(8, '\0'))

def lookup(pid, symbol):
   with open('/proc/%s/mem' % pid) as mem:
      moduleBase = findModuleBase(pid, mem)
   log.info("Module's base address:................. " + hex(moduleBase))

   global PIE
   PIE = findIfPIE(moduleBase)
   if PIE:
      log.info("Binary is PIE enabled.")
   else:
      log.info("Binary is not PIE enabled.")

   modulePhdr = findPhdr(moduleBase)
   log.info("Module's Program Header:............... " + hex(modulePhdr))

   moduleDynamic = findDynamic(modulePhdr, moduleBase, bits) 
   log.info("Module's _DYNAMIC Section:............. " + hex(moduleDynamic))

   moduleGot = findDynTable(moduleDynamic, 3, bits)
   log.info("Module's GOT:.......................... " + hex(moduleGot))

   libcPtr = getPtr(moduleGot, bits)
   log.info("Pointer from GOT to a function in libc: " + hex(libcPtr))

   libcBase = findLibcBase(libcPtr)
   log.info("Libc's base address:................... " + hex(libcBase))

   libcPhdr = findPhdr(libcBase)
   log.info("Libc's Program Header:................. " + hex(libcPhdr))

   PIE = findIfPIE(libcBase)
   libcDynamic = findDynamic(libcPhdr, libcBase, bits)
   log.info("Libc's _DYNAMIC Section:............... " + hex(libcDynamic))

   libcStrtab = findDynTable(libcDynamic, 5, bits)
   log.info("Libc's DT_STRTAB Table:................ " + hex(libcStrtab))

   libcSymtab = findDynTable(libcDynamic, 6, bits)
   log.info("Libc's DT_SYMTAB Table:................ " + hex(libcSymtab))

   symbolAddr = findSymbol(libcStrtab, libcSymtab, symbol, bits)
   log.success("%s loaded at address:.............. %s" % (symbol, hex(symbolAddr + libcBase)))


if __name__ == "__main__":
   log.info("Manual usage of pwnlib.dynelf")
   if len(sys.argv) == 3:
      pid = sys.argv[1]
      symbol = sys.argv[2]
      lookup(pid, symbol)
   else:
      log.failure("Usage: %s PID SYMBOL" % sys.argv[0])

{% endhighlight %}
Example output:
{% highlight text %}
➜  ~ python ./DynELF_manual.py 29530 system
[*] Manual usage of pwnlib.dynelf
[*] Module's base address:................. 0x400000
[*] Binary is not PIE enabled.
[*] Module's Program Header:............... 0x400040
[*] Module's _DYNAMIC Section:............. 0x602e08
[*] Module's GOT:.......................... 0x603000
[*] Pointer from GOT to a function in libc: 0x7ffff743ddd0
[*] Libc's base address:................... 0x7ffff741c000
[*] Libc's Program Header:................. 0x7ffff741c040
[*] Libc's _DYNAMIC Section:............... 0x7ffff77d9ba0
[*] Libc's DT_STRTAB Table:................ 0x7ffff742cd78
[*] Libc's DT_SYMTAB Table:................ 0x7ffff741fd28
[+] system loaded at address:.............. 0x7ffff7462640
➜  ~
{% endhighlight %}

## [Link_map](http://www.tldp.org/LDP/LG/issue85/sandeep.html) structure

Another method of finding the DYNAMIC Segment is using the link_map structure.
Link_map is the dynamic linker's internal structure with which it keeps track of loaded libraries and symbols within libraries.

{% highlight C %}
struct link_map
{
   ElfW(Addr) l_addr;                  /* Difference between the address in the ELF
                                       file and the addresses in memory.  */
   char *l_name;                       /* Absolute file name object was found in.  */
   ElfW(Dyn) *l_ld;                    /* Dynamic section of the shared object.  */
   struct link_map *l_next, *l_prev;   /* Chain of loaded objects.  */
};
{% endhighlight %}

A small explanation for the fields:

* l_addr: Base address where shared object is loaded. This value can also be found from /proc/<pid>/maps
* l_name: pointer to library name in string table  
* l_ld : pointer to dynamic (DT_*) sections of shared lib  
* l_next: pointer to next link_map node  
* l_prev: pointer to previous link_map node  

We can find the link_map structure located on the index [1] slot in the GOT array.

![link_map]({{site.url}}/assets/Screen_Shot_2016-03-29_at_11_07_56_PM.jpg)

At runtime this index will be populated by the runtime linker as we can see here.

{% highlight text %}
gdb-peda$ x/4wx 0x804b000
0x804b000:  0x0804af14  0xf7ffd938  0xf7ff04f0  0x080484c6
gdb-peda$                   ^^^
{% endhighlight %}

`GOT[0]` is a the address of the module's DYNAMIC section. `GOT[1]` is the virtual load address of the link_map, `GOT[2]` is the address for the runtime resolver function (which we will cover next).

So, if we walk the linked list until `link_map->l_name` contains the full path to the loaded gLibc library we can find the gLibc's DYNAMIC section in `link_map->l_ld` element and gLibc's base address in `link_map->l_addr`.

{% highlight text %}
gdb-peda$ x/4wx 0x804b000
0x804b000:  0x0804af14  0xf7ffd938  0xf7ff04f0  0x080484c6
gdb-peda$ x/4wx 0xf7ffd938
0xf7ffd938: 0x00000000  0xf7ffdc24  0x0804af14  0xf7ffdc28
gdb-peda$ x/4wx 0xf7ffdc28
0xf7ffdc28: 0xf7fdd000  0xf7ffde94  0xf7fdb350  0xf7fda858
gdb-peda$ x/4wx 0xf7fda858
0xf7fda858: 0xf7e1e000  0xf7fda838  0xf7fc7da8  0xf7ffd55c
gdb-peda$ x/s 0xf7fda838
0xf7fda838: "/lib/i386-linux-gnu/libc.so.6"
gdb-peda$ vmmap libc
Start      End        Perm Name
0xf7e1e000 0xf7fc6000 r-xp /lib/i386-linux-gnu/libc-2.19.so
0xf7fc6000 0xf7fc8000 r--p /lib/i386-linux-gnu/libc-2.19.so
0xf7fc8000 0xf7fc9000 rw-p /lib/i386-linux-gnu/libc-2.19.so
gdb-peda$
{% endhighlight %}

In the above snippet we can verify after traversing 3 link_map structures we found libc's link_map with base found at `link_map->l_addr == 0xf7e1e000`, DYNAMIC section found at `link_map->l_ld == 0xf7fc7da8` and the loaded module's full path `link_map->l_name == "/lib/i386-linux-gnu/libc.so.6"`

In `FULL RELRO` enabled binaries the link_map looks like it's not in the GOT anymore, but thanks to [this stackoverflow post](http://reverseengineering.stackexchange.com/questions/6525/elf-link-map-when-linked-as-relro) I learned we can find it in the `DT_DEBUG` table located from the DYNAMIC Segment.

## TODO: Using the [dl-resolve](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-di-frederico.pdf)
<!---
`dl-resolve()` is a function from the runtime linker's `ld-x.xx.so` library used to populate GOT entries. A pointer to this function is stored in GOT@ index 2.

![dl-resolve]({{site.url}}/assets/Screen_Shot_2016-03-29_at_11_07_42_PM.jpg)

The function takes 2 arguments, first argument is a link_map object and the second argument is reloc_index. reloc_index is the index structure Elf32_Rel in the `JMPREL` Segment. The JMPREL segment holds structure array of Elf32_Rel structures. 

{% highlight C %}
typedef struct
{
   Elf32_Addr    r_offset;       /* Address */
   Elf32_Word    r_info;         /* Relocation type and symbol index */
} Elf32_Rel;
{% endhighlight %}

The first element `r_offset` in this structure is the absolute address in the GOT where the dl_resolve will save the resolved function's address. The second element `r_info` is -->