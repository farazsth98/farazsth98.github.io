---
layout: post
title: Flare-on Challenge 3
category: [Reverse Engineering]
tags: [RE, Flare-on]
---

**Points:**
**Solves:**
**Category:** Reverse Engineering
**Description:**

> It's simple: Analyze the [sample]({{site.url}}/assets/C3.zip), find the key. Each key is an email address.
> Password for any encrypted archives is 'malware'.

## Write-up

This time we have 32bit Windows executable. Viewing the Section names and IAT, it looks it's packed and only loading a single DLL (msvcrt.dll).
I used OllyDBG to debug the binary and see it's functionality. In the beginning we see the following instructions.
The first CALL to such_evi.004024D1 at address 0x004024CE it's a function that installs a SEH routine. We are not interested in it since an exception is never generated.
Continuing with the code we see controlfp(), __set_app_type() and __getmainargs() from msvcrt.dll which we are not interested in.
At address 0x0040252A, however there is a call to what seems to be the ModuleEntryPoint, let's go there.

{% highlight text %}
004024C0 >  55              PUSH EBP
004024C1    89E5            MOV EBP,ESP
004024C3    81EC 2C000000   SUB ESP,2C
004024C9    90              NOP
004024CA    8D45 E8         LEA EAX,DWORD PTR SS:[EBP-18]
004024CD    50              PUSH EAX
004024CE    E8 FE000000     CALL such_evi.004025D1
004024D3    83C4 04         ADD ESP,4
004024D6    B8 00000000     MOV EAX,0
004024DB    8945 D4         MOV DWORD PTR SS:[EBP-2C],EAX
004024DE    B8 00000300     MOV EAX,30000
004024E3    50              PUSH EAX
004024E4    B8 00000100     MOV EAX,10000                                           ; UNICODE "=::=::\"
004024E9    50              PUSH EAX
004024EA    E8 21010000     CALL <JMP.&msvcrt._controlfp>
004024EF    83C4 08         ADD ESP,8
004024F2    B8 01000000     MOV EAX,1
004024F7    50              PUSH EAX
004024F8    E8 1B010000     CALL <JMP.&msvcrt.__set_app_type>
004024FD    83C4 04         ADD ESP,4
00402500    8D45 D4         LEA EAX,DWORD PTR SS:[EBP-2C]
00402503    50              PUSH EAX
00402504    B8 00000000     MOV EAX,0
00402509    50              PUSH EAX
0040250A    8D45 DC         LEA EAX,DWORD PTR SS:[EBP-24]
0040250D    50              PUSH EAX
0040250E    8D45 E0         LEA EAX,DWORD PTR SS:[EBP-20]
00402511    50              PUSH EAX
00402512    8D45 E4         LEA EAX,DWORD PTR SS:[EBP-1C]
00402515    50              PUSH EAX
00402516    E8 05010000     CALL <JMP.&msvcrt.__getmainargs>
0040251B    83C4 14         ADD ESP,14
0040251E    8B45 DC         MOV EAX,DWORD PTR SS:[EBP-24]
00402521    50              PUSH EAX
00402522    8B45 E0         MOV EAX,DWORD PTR SS:[EBP-20]
00402525    50              PUSH EAX
00402526    8B45 E4         MOV EAX,DWORD PTR SS:[EBP-1C]
00402529    50              PUSH EAX
0040252A    E8 D1EAFFFF     CALL such_evi.00401000
{% endhighlight %}

Here we see a static shellcode being pushed to the stack. It's rather lengthy so I've omitted a big chunk of it.
Once the shellcode has been installed on the stack, execution is transfered to it via the CALL EAX instruction at the end.
I could of copied the shellcode to a separate file and do some static analysis but I've decided to keep this POST kind of short so let's continue debugging.
Place a BreakPoint at 0x0040249B and hit RUN.

{% highlight text %}
00401000  /$  55                   PUSH EBP
00401001  |.  89E5                 MOV EBP,ESP
00401003  |.  81EC 04020000        SUB ESP,204
00401009  |.  90                   NOP
0040100A  |.  B8 E8000000          MOV EAX,0E8
0040100F  |.  8885 FFFDFFFF        MOV BYTE PTR SS:[EBP-201],AL
00401015  |.  B8 00000000          MOV EAX,0
0040101A  |.  8885 00FEFFFF        MOV BYTE PTR SS:[EBP-200],AL
00401020  |.  B8 00000000          MOV EAX,0
00401025  |.  8885 01FEFFFF        MOV BYTE PTR SS:[EBP-1FF],AL
0040102B  |.  B8 00000000          MOV EAX,0
00401030  |.  8885 02FEFFFF        MOV BYTE PTR SS:[EBP-1FE],AL
00401036  |.  B8 00000000          MOV EAX,0
0040103B  |.  8885 03FEFFFF        MOV BYTE PTR SS:[EBP-1FD],AL
00401041  |.  B8 8B000000          MOV EAX,8B
00401046  |.  8885 04FEFFFF        MOV BYTE PTR SS:[EBP-1FC],AL
0040104C  |.  B8 34000000          MOV EAX,34
00401051  |.  8885 05FEFFFF        MOV BYTE PTR SS:[EBP-1FB],AL
00401057  |.  B8 24000000          MOV EAX,24
0040105C  |.  8885 06FEFFFF        MOV BYTE PTR SS:[EBP-1FA],AL
...
00402485  |.  B8 C9000000          MOV EAX,0C9
0040248A  |.  8845 FE              MOV BYTE PTR SS:[EBP-2],AL
0040248D  |.  B8 00000000          MOV EAX,0
00402492  |.  8845 FF              MOV BYTE PTR SS:[EBP-1],AL
00402495  |.  8D85 FFFDFFFF        LEA EAX,DWORD PTR SS:[EBP-201]
0040249B  |.  FFD0                 CALL EAX
{% endhighlight %}

Let the unpacking begin. What we see in the below snippet is that 0x1df number of bytes are going to be XORed with static hex key 0x66.
The XORed bytes are the ones where execution will jump to after this 'unpacking routine'. So, let's manually loop through this loop a few times and than place
a BreakPoint at 0x0012FD9B. The reason why we are manually stepping through this piece of code before placing a BreakPoint is so the BreakPoint does not get overwritten
by the initial XOR loop. I know that the first address to be XORed is past where the BP would be placed,
however this is how I like stepping through these loops and ensuring everything runs as expected.
The other solution would be to place a Hardware BreakPoint on execute on the same address...

{% highlight text  %}
0012FD7F    E8 00000000            CALL 0012FD84
0012FD84    8B3424                 MOV ESI,DWORD PTR SS:[ESP]
0012FD87    83C6 1C                ADD ESI,1C
0012FD8A    B9 DF010000            MOV ECX,1DF  <---- Counter bytes to be XORed
0012FD8F    83F9 00                CMP ECX,0
0012FD92    74 07                  JE SHORT 0012FD9B
0012FD94    8036 66                XOR BYTE PTR DS:[ESI],66  <---- XOR with key 0x66, ESI here is 0x0012FDA0 
0012FD97    46                     INC ESI
0012FD98    49                     DEC ECX
0012FD99  ^ EB F4                  JMP SHORT 0012FD8F
0012FD9B    E9 10000000            JMP 0012FDB0
0012FDA0    07                     POP ES      <------------ First byte to be XORed.
{% endhighlight %}

Here I've copied a snippet of the previous routine and the resulting instructions after the unpacking routine.
You see how the code has changed ? What used to be 0x07 at address 0x0012FDA0 is now 0x61, because 0x07 ^ 0x66 = 0x61.
The interesting part here is the jump at address 0x0012FD9B where we are currently.
The jump is going to transfer execution to 0x0012FDB0, however if you pay attention you will see that that address is in
the middle of the interpreted instructions and not at the start of another routine. This is a nice nifty anti-disassembly method.
You see how instruction IMUL at address 0x0012FDAC starts and ends at 0x0012FDB3 and it takes raw hex bytes "67:696E 73 68757300" ?
If execution is going to jump to 0x0012FDB0, this address starts at raw bytes "68757300", which is a PUSH (0x68).
Since we are using a debugger and not static analysis we can jump step there without much to worry about. However if you are
using static analysis, make sure to start disassembly from those instructions so the real code gets interpreted properly.

{% highlight text  %}
0012FD7F    E8 00000000            CALL 0012FD84
0012FD84    8B3424                 MOV ESI,DWORD PTR SS:[ESP]
0012FD87    83C6 1C                ADD ESI,1C
0012FD8A    B9 DF010000            MOV ECX,1DF
0012FD8F    83F9 00                CMP ECX,0
0012FD92    74 07                  JE SHORT 0012FD9B
0012FD94    8036 66                XOR BYTE PTR DS:[ESI],66
0012FD97    46                     INC ESI
0012FD98    49                     DEC ECX
0012FD99  ^ EB F4                  JMP SHORT 0012FD8F
0012FD9B    E9 10000000            JMP 0012FDB0            <-------- EIP
0012FDA0    61                     POPAD
0012FDA1    6E                     OUTS DX,BYTE PTR ES:[EDI]                               ; I/O command
0012FDA2    64:2073 6F             AND BYTE PTR FS:[EBX+6F],DH
0012FDA6    2069 74                AND BYTE PTR DS:[ECX+74],CH
0012FDA9    2062 65                AND BYTE PTR DS:[EDX+65],AH
0012FDAC    67:696E 73 68757300    IMUL EBP,DWORD PTR SS:[BP+73],737568
0012FDB4    0068 73                ADD BYTE PTR DS:[EAX+73],CH
0012FDB7    61                     POPAD
0012FDB8    75 72                  JNZ SHORT 0012FE2C
0012FDBA    68 6E6F7061            PUSH 61706F6E
0012FDBF    89E3                   MOV EBX,ESP
0012FDC1    E8 00000000            CALL 0012FDC6
{% endhighlight %}

As expected, the instruction jump took us to is a PUSH. Here is we have absolutely the same routine, except this time the key
is not a 1 byte 0x66 but the bytes being pushed to the stack at the beginning of the routine, 0x7375 0x72756173 and 0x61706F6E.
Remember those are little-endan, if we convert them to ASCII just for clarity we get the key "nopasaurus".
Again the first XOR address is past the second JMP at 0x0012FDF3, which is 0x09 and it will be XORed with the first byte of
"nopasaurus" which is 0x6E... and so on. Let's place a BreakPoint at 0x0012FDEE the same way as before.

{% highlight text  %}
0012FDB0 >  68 75730000            PUSH 7375
0012FDB5    68 73617572            PUSH 72756173
0012FDBA    68 6E6F7061            PUSH 61706F6E
0012FDBF    89E3                   MOV EBX,ESP
0012FDC1    E8 00000000            CALL 0012FDC6
0012FDC6    8B3424                 MOV ESI,DWORD PTR SS:[ESP]
0012FDC9    83C6 2D                ADD ESI,2D
0012FDCC    89F1                   MOV ECX,ESI
0012FDCE    81C1 8C010000          ADD ECX,18C
0012FDD4    89D8                   MOV EAX,EBX
0012FDD6    83C0 0A                ADD EAX,0A
0012FDD9    39D8                   CMP EAX,EBX
0012FDDB    75 05                  JNZ SHORT 0012FDE2
0012FDDD    89E3                   MOV EBX,ESP
0012FDDF    83C3 04                ADD EBX,4
0012FDE2    39CE                   CMP ESI,ECX
0012FDE4    74 08                  JE SHORT 0012FDEE
0012FDE6    8A13                   MOV DL,BYTE PTR DS:[EBX]
0012FDE8    3016                   XOR BYTE PTR DS:[ESI],DL
0012FDEA    43                     INC EBX
0012FDEB    46                     INC ESI
0012FDEC  ^ EB EB                  JMP SHORT 0012FDD9
0012FDEE    E9 31000000            JMP 0012FE24
0012FDF3    090A                   OR DWORD PTR DS:[EDX],ECX  <------- XOR start address
0012FDF5    04 41                  ADD AL,41
0012FDF7    010414                 ADD DWORD PTR SS:[ESP+EDX],EAX
0012FDFA    16                     PUSH SS
0012FDFB    0C 53                  OR AL,53
0012FDFD    1A00                   SBB AL,BYTE PTR DS:[EAX]
0012FDFF    50                     PUSH EAX
0012FE00    06                     PUSH ES
0012FE01    16                     PUSH SS
{% endhighlight %}

Just as before, JMP is going to jump in the middle of an instruction. We know how to deal like that...

{% highlight text  %}
0012FDEC  ^\EB EB                  JMP SHORT 0012FDD9
0012FDEE >  E9 31000000            JMP 0012FE24  <----- EIP
0012FDF3    67:65:74 20            JE SHORT 0012FE17                                       ; Superfluous prefix
0012FDF7    72 65                  JB SHORT 0012FE5E
0012FDF9    61                     POPAD
0012FDFA    64:79 20               JNS SHORT 0012FE1D                                      ; Superfluous prefix
0012FDFD    74 6F                  JE SHORT 0012FE6E
0012FDFF    2067 65                AND BYTE PTR DS:[EDI+65],AH
0012FE02    74 20                  JE SHORT 0012FE24
0012FE04    6E                     OUTS DX,BYTE PTR ES:[EDI]                               ; I/O command
0012FE05    6F                     OUTS DX,DWORD PTR ES:[EDI]                              ; I/O command
0012FE06    70 27                  JO SHORT 0012FE2F
0012FE08    65:                    PREFIX GS:                                              ; Superfluous prefix
0012FE09    64:2073 6F             AND BYTE PTR FS:[EBX+6F],DH
0012FE0D    206461 6D              AND BYTE PTR DS:[ECX+6D],AH
0012FE11    6E                     OUTS DX,BYTE PTR ES:[EDI]                               ; I/O command
0012FE12    2068 61                AND BYTE PTR DS:[EAX+61],CH
0012FE15    72 64                  JB SHORT 0012FE7B
0012FE17    2069 6E                AND BYTE PTR DS:[ECX+6E],CH
0012FE1A    207468 65              AND BYTE PTR DS:[EAX+EBP*2+65],DH
0012FE1E    2070 61                AND BYTE PTR DS:[EAX+61],DH
0012FE21    696E 74 E8000000       IMUL EBP,DWORD PTR DS:[ESI+74],0E8
0012FE28    008B 342483C6          ADD BYTE PTR DS:[EBX+C6832434],CL
0012FE2E    1E                     PUSH DS
0012FE2F    B9 38010000            MOV ECX,138
{% endhighlight %}

After we have transfered execution to address 0x0012FE24, we see the same XOR routine again. Well... almost the same :P
Now, we have XOR DWORD which means it will apply XOR to 4 bytes at a time with key 0x476C4F62.
Another thing I like to do is when seeing those XORing functions is to follow the address being XORed in the Olly's DUMP window
and watch for any interesting strings... Let's not asume that only execution instruction are being obfuscated but helpful resources as well.
Again manually go through the unpacking loop and then place a BreakPoint at 0x0012FE47 after the loop.

{% highlight text  %}
0012FE24 >  E8 00000000            CALL 0012FE29
0012FE29    8B3424                 MOV ESI,DWORD PTR SS:[ESP]
0012FE2C    83C6 1E                ADD ESI,1E
0012FE2F    B9 38010000            MOV ECX,138
0012FE34    83F9 00                CMP ECX,0
0012FE37    7E 0E                  JLE SHORT 0012FE47
0012FE39    8136 624F6C47          XOR DWORD PTR DS:[ESI],476C4F62
0012FE3F    83C6 04                ADD ESI,4
0012FE42    83E9 04                SUB ECX,4
0012FE45  ^ EB ED                  JMP SHORT 0012FE34
{% endhighlight %}

The unpacked routine decrypted the next XOR key, again this is applied byte by byte.
Also if we follow the data that's being decrypted in the DUMP window in Olly, we can see that the string
"such.5h311010101@flare-on.com" is revealed.

{% highlight text  %}
0012FE47 >  8D80 00000000          LEA EAX,DWORD PTR DS:[EAX]
0012FE4D    8D80 00000000          LEA EAX,DWORD PTR DS:[EAX]
0012FE53    90                     NOP
0012FE54    90                     NOP
0012FE55    90                     NOP
0012FE56    90                     NOP
0012FE57    68 723F213F            PUSH 3F213F72  <- Key "omg is it almost over ?!?"
0012FE5C    68 206F7665            PUSH 65766F20  <- 
0012FE61    68 6D6F7374            PUSH 74736F6D  <-
0012FE66    68 7420616C            PUSH 6C612074  <-
0012FE6B    68 69732069            PUSH 69207369  <-
0012FE70    68 6F6D6720            PUSH 20676D6F  <-
0012FE75    89E3                   MOV EBX,ESP
0012FE77    E8 00000000            CALL 0012FE7C
0012FE7C    8B3424                 MOV ESI,DWORD PTR SS:[ESP]
0012FE7F    83C6 2D                ADD ESI,2D
0012FE82    89F1                   MOV ECX,ESI
0012FE84    81C1 D6000000          ADD ECX,0D6
0012FE8A    89D8                   MOV EAX,EBX
0012FE8C    83C0 18                ADD EAX,18
0012FE8F    39D8                   CMP EAX,EBX
0012FE91    75 05                  JNZ SHORT 0012FE98
0012FE93    89E3                   MOV EBX,ESP
0012FE95    83C3 04                ADD EBX,4
0012FE98    39CE                   CMP ESI,ECX
0012FE9A    74 08                  JE SHORT 0012FEA4
0012FE9C    8A13                   MOV DL,BYTE PTR DS:[EBX]
0012FE9E    3016                   XOR BYTE PTR DS:[ESI],DL
0012FEA0    43                     INC EBX
0012FEA1    46                     INC ESI
0012FEA2  ^ EB EB                  JMP SHORT 0012FE8F
0012FEA4    E9 1D000000            JMP 0012FEC6
{% endhighlight %}

Since we have found the password, I will not go over the rest of the code. In a summary another XOR key "aaaaaand i'm spent" is applied on the
Stack data which decrypts, "BrokenByte" string. Than the binary looks for "FatalAppExitA" in kernel32.dll
which it uses to deliver the "BrokenByte" Exit pop-up message and Exits.

## Links

* <http://flare-on.com/>
