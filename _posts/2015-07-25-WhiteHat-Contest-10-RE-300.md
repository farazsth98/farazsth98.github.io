---
layout: post
title: WhiteHat CTF Contest 10 RE-300
category: Reverse Engineering
tags: RE WhiteHat
---

**Points:** 300
**Solves:** 17
**Category:** Reverse
**Description:**

> Flag = WhiteHat{SHA1(key)}  
> The key is a string that has meaning

[re300]({{site.url}}/assets/re300_7cb9f7846b7425cb6532fd55fb4b6b76.zip)

![screen]({{site.url}}/assets/Screen Shot 2015-07-25 at 5.17.59 PM.png)

## Write-up

Not packed, Visual C++ 32bit executable... By using OllyDbg with HideOD and OllyAdvanced plugins we can overcome all anti-debugging techniques
used in this binary. I only saw 2 calls to IsDebuggerPresent which was called at least 4 times and some manual checks which I didn't spend too much time
investigating. I also skipped a large portion of the binary because of the methods I used, I was more concerned about finding the comparison
function rather than in-depth analysis.

Just by starting the binary we see that it's asking us for password. Upon submission if wrong, it displays a MessageBox with title "Reverse Me"
and text "try again".

![screen1]({{site.url}}/assets/Screen Shot 2015-07-25 at 5.29.20 PM.png)

The way I solved with OllyDbg was to first place a BreakPoint on every call to MessageBoxA. Now the application executes, because of the plugins
we automatically overcome any anti-debugging tricks used. Now let's input a password and click on "Check", the binary breaks here.

![screen2]({{site.url}}/assets/Screen Shot 2015-07-25 at 6.03.55 PM.png)

I placed a couple of BreakPoints around the call, restarted the application and started looking inside and around those calls but the decision
for the "try again." was already made.

The next thing I did was to see the stack. The stack noticeably had the "try again" string pushed a few times.

![screen3]({{site.url}}/assets/Screen Shot 2015-07-25 at 6.23.47 PM.png)

Here I followed the return address 0x00401998, which was the last address before the decision of the "BadBoy" / "GoodBoy" for the MessageBox.

![screen4]({{site.url}}/assets/Screen Shot 2015-07-25 at 6.30.28 PM.png)

Here, I placed a couple of breakpoints on the conditional jump and the functions before it. Now I restarted the application again and I saw that
the "try again" message is pushed to the stack at address 0x00401986, this means that the decision is made by the 'JG' condition at 0x00401984.
So let's go to call 0x0040C299 and see how EAX is set.

![screen5]({{site.url}}/assets/Screen Shot 2015-07-25 at 6.39.11 PM.png)

Nice, here it looks like GetWindowTextA retrieves our input and 0x0040561F decides on the return of EAX.

![screen6]({{site.url}}/assets/Screen Shot 2015-07-25 at 6.43.43 PM.png)

With a few single-steps we end up at the above first input parsing function. It just looks like it stores the length of our input in EAX.
If you remember the conditional jump was "JG" and the compare "CMP EAX, 32", meaning our input length needs to be greater than 50 characters.
Let's restart our binary and input more than 50 chars and break on the compare.

![screen7]({{site.url}}/assets/Screen Shot 2015-07-25 at 6.53.20 PM.png)

It looks like the jump send us to another length compare. This time it's "JGE" for compare "CMP EAX, 64". So our input needs to be more than 50 chars
and less than 100 chars. Anyway, after some single stepping and stepping over the main decision making function was at my BreakPoint at 0x00401A2B.

![screen8]({{site.url}}/assets/Screen Shot 2015-07-25 at 7.27.26 PM.png)

First let's see what we need in our EAX value once we return from 0x00401080. We have "test EAX, EAX" and "JNZ 0x00401A63", I already tested it and
saw that if the JUMP to 0x00401A63 is not taken, the "try again" message is pushed to the stack, meaning we need to return 1 in EAX in the function
from the above screenshot.

In this function, we have some static bytes pushed to the stack, followed by some comparison of our input-processing algorithm and those bytes.
If all 20 compared bytes are equal, the jump to 0x0040114D is not taken and CL gets set to 1 then transfered to EAX.

The key input-processing function is basically checking if our input[1] + input[0] == 0xDF (the first byte). It will than take input[2] + input[1] == 0xD2,
followed by input[3] + input[2] == 0xDE and so on...

Since the local time was 05:00 am I wasn't really thinking how to properly script this, so I just copied and pasted a bunch of times a loop which
would give me the possible solution for each byte.

{% highlight python linenos %}
#!/usr/bin/env python

for a in range(33, 126):
    final = ['#'] * 20
    for b in range(33, 127):
        if a + b == 0xdf:
            final[0] = chr(a)
            final[1] = chr(b)
            for c in range(33,127):
               if (ord(final[1]) + c) == 0xd2:
                    final[2] = chr(c)
            	     for d in range(33,127):
                          if (ord(final[2]) + d) == 0xde:
                                final[3] = chr(d)
                                for e in range(33,127):
                                    if (ord(final[3]) + e) == 0xa7:
                                        final[4] = chr(e)
                                        for f in range(33,127):
                                            if (ord(final[4]) + f) == 0x9b:
                                                final[5] = chr(f)
                                                for g in range(33,127):
                                                    if (ord(final[5]) + g) == 0x9c:
                                                        final[6] = chr(g)
                                                        for h in range(33,127):
                                                            if (ord(final[6]) + h) == 0xA8:
                                                                final[7] = chr(h)
                                                                for i in range(33,127):
                                                                    if (ord(final[7]) + i) == 0xA6:
                                                                        final[8] = chr(i)
                                                                        for j in range(33,127):
                                                                            if (ord(final[8]) + j) == 0x62:
                                                                                final[9] = chr(j)
                                                                                for k in range(32,127):
                                                                                    if (ord(final[9]) + k) == 0x61:
                                                                                        final[10] = chr(k)
                                                                                        for l in range(32,127):
                                                                                            if (ord(final[10]) + l) == 0x66:
                                                                                                final[11] = chr(l)
                                                                                                for m in range(32,127):
                                                                                                    if (ord(final[11]) + m) == 0x56:
                                                                                                        final[12] = chr(m)
                                                                                                        for n in range(33,127):
                                                                                                            if (ord(final[12]) + n) == 0x55:
                                                                                                                final[13] = chr(n)
                                                                                                                for o in range(33,127):
                                                                                                                    if (ord(final[13]) + o) == 0xA1:
                                                                                                                        final[14] = chr(o)
                                                                                                                        for p in range(33,126):
                                                                                                                            if (ord(final[14]) + p) == 0xA1:
                                                                                                                                final[15] = chr(p)
                                                                                                                                for q in range(33,126):
                                                                                                                                    if (ord(final[15]) + q) == 0xAE:
                                                                                                                                        final[16] = chr(q)
                                                                                                                                        for r in range(32,127):
                                                                                                                                            if (ord(final[16]) + r) == 0xE4:
                                                                                                                                                final[17] = chr(r)
                                                                                                                                                for s in range(32,127):
                                                                                                                                                    if (ord(final[17]) + s) == 0xD8:
                                                                                                                                                        final[18] = chr(s)
                                                                                                                                                        for t in range(32,127):
                                                                                                                                                            if (ord(final[18]) + t) == 0xD5:
                                                                                                                                                                final[19] = chr(t)
                                                                                                                                                                print ''.join(final)

{% endhighlight %}

Please no criticism :).  
The "script" "cough, cough, cough"... produced the following values.

{% highlight bash linenos %}
$ python ./brute.py 
viiu2i3u1106 5l5ykmh
whjt3h4t2015!4m4zjng
xgks4g5s3/24"3n3{iof
yflr5f6r4.33#2o2|hpe
zemq6e7q5-42$1p1}gqd
$ 
{% endhighlight %}

Since the hint from the challenge's description is to use a password that have a meaning, I'm guessing that "whjt3h4t2015!4m4zjng" is the right one.
Obviously, this is not the end of the challenge, so let's keep on stepping through the code.  

![screen9]({{site.url}}/assets/Screen Shot 2015-07-25 at 7.33.57 PM.png)

After the jump to 0x00401A63, we end up in function 0x00401160.

![screen10]({{site.url}}/assets/Screen Shot 2015-07-25 at 7.37.19 PM.png)

Looks familiar ? Yep, it's the same function just different bytes for the comparison.
After returning from function 0x00401160, we see the following:

![screen11]({{site.url}}/assets/Screen Shot 2015-07-25 at 7.39.45 PM.png)

So it's a JUMP to "BadBoy" if EAX == 0, followed by function 0x00401B90.
Let's step inside of it.

![screen12]({{site.url}}/assets/Screen Shot 2015-07-25 at 7.44.31 PM.png)

Ha! It's an anti-debugging technique by manually checking the BeingDebugged flag in PEB, it's exactly what IsDebuggerPresent() uses but
in this case they are manually extracting the value. Olly Advanced and HideOD can automatically change the value of the flag so
we don't have to worry about a thing here...

After this function we end up in function 0x00401230.

![screen13]({{site.url}}/assets/Screen Shot 2015-07-25 at 7.56.10 PM.png)

No surprise, it's the same check. Let's see what we have after it...

![screen14]({{site.url}}/assets/Screen Shot 2015-07-25 at 7.59.47 PM.png)

Well it looks like that's it... "congratulations" gets pushed to the stack and later displayed in the MessageBoxA.

Thanks to gaffe, and his solution using z3 theorem prover, we can say we have a better brute-forcer ;)

{% highlight python %}
#!/usr/bin/env python

import z3

# here are the lists of constraints. each constraint is expressed as the sum
# of the current character and the next character, represented in ascii.
#
# for example, in part1, the the first and second characters of the solution
# string have to be equal to 0xdf, the second and third characters have to be
# equal to 0xd2, and so on.
#
# the flag is 60 characters long, and it's split up into three 20-byte chunks.
# you can solve for each chunk in the same way, just with different
# constraints. I have a function solveChunk() that finds solutions for each
# 20-byte chunk separately.
part1 = [0xdf, 0xd2, 0xde, 0xa7, 0x9b, 0x9c, 0xa8, 0xa6, 0x62, 0x61, 0x66, 0x56, 0x55, 0xa1, 0xa1, 0xae, 0xe4, 0xd8, 0xd5]
part2 = [0x93, 0x9e, 0xe2, 0xa7, 0xa6, 0xe7, 0xb3, 0xb4, 0xe3, 0xea, 0xaf, 0x66, 0xaf, 0xdb, 0xc9, 0xe0, 0xa9, 0xaf, 0xaf]
part3 = [0xdb, 0x92, 0xa7, 0xa4, 0x93, 0x97, 0xa4, 0xe4, 0xe9, 0xe7, 0xa5, 0xa7, 0xdc, 0x9b, 0x99, 0xe2, 0xdb, 0x93, 0x9b]

# this function basically simplifies the process of solving the constraints and
# getting the possible solutions. I got it from this writeup of a PoliCtf RE
# challenge, which has more information about z3:
# http://v0ids3curity.blogspot.com/2015/07/polictf-re350-john-packer-pin-z3.html
def get_models(s):
  # from 0vercl0k's z3tools.py
  while s.check() == z3.sat:
    m = s.model()
    yield m
    s.add(z3.Or([sym() != m[sym] for sym in m.decls()]))

# this function uses z3 to find all of the possible 20-byte strings fitting the
# given constraints.
def solveChunk(constraintList):
  # create z3 solver object
  s = z3.Solver()

  # charList is a list of z3 bit vectors. we'll use the bit vectors to formally
  # define constraints for z3. later on, we'll also use these bit vectors to
  # determine possible solutions to our constraints.
  #
  # the names "char0 char1 char2 ..." are completely arbitrary. you can use
  # whatever names you want.                                                                                                                                                           #
  # the second argument tells z3 how big to make each bit vector. here, we're
  # telling it to make 8-bit vectors so that each one represents a single byte.
  charList = z3.BitVecs('char0 char1 char2 char3 char4 char5 char6 char7 char8 char9 char10 char11 char12 char13 char14 char15 char16 char17 char18 char19', 8)

  # require each byte to be in the ASCII range.
  for char in charList:
    s.add(z3.And(0x20 < char, char < 0x7f))

  # create z3 constraints out of the given list of constraints.
  for i in xrange(19):
    s.add(charList[i] + charList[i+1] == constraintList[i])

  # we have the constraints set up, so now we can find the solutions.
  for m in get_models(s):
    # print each possible solution as a string.
    string = "".join([chr(m[char].as_long()) for char in charList])
    print string

# solve for each chunk of the flag, 20 characters at a time.
print "part 1"
solveChunk(part1)
print "part 2"
solveChunk(part2)
print "part 3"
solveChunk(part3)

# solution: whjt3h4t2015!4m4zjngc0nt3st?un|33|_jv3|3|_3t0c4ptur3th3f|_4g
{% endhighlight %}



## Links

* <https://wargame.whitehat.vn>
