---
layout: post
title: Infosec Institute CTF2 Practical Web Hacking Level 11
category: Web
tags: CTF challenges
---

# ctf.infosecinstitute.com: Level 11
**Vulnerability** Bypassing blacklists
**Description:**

![screen]({{site.url}}/assets/Screen Shot 2015-07-17 at 7.00.47 PM.png)

## Write-up

For almost all levels I will be using Burpsuite. Burpsuite is an interception proxy that lets us modify the HTTP request
 / response by intercepting the data between the browser and the web server.
 
Blacklisting could be done by many variables, like IP address, User-Agent, Referer or a session token. So let's see our
request in Burp and possibly start playing with some values.

{% highlight http linenos %}
GET /ctf2/exercises/ex11.php HTTP/1.1
Host: ctf.infosecinstitute.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0 Iceweasel/31.6.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Cookie: welcome=no; PHPSESSID=gdc668pjmpah42hegt7sa7igc3
Connection: keep-alive
{% endhighlight %}

Aha! No need to play the guessing game with the values, right away we see Cookie name "welcome" with value of "no".
Let's modify "no" to "yes" and resume our request.

![screen2]({{site.url}}/assets/Screen Shot 2015-07-17 at 7.05.36 PM.png)



## Links

* <http://ctf.infosecinstitute.com/ctf2/exercises/ex11.php>
