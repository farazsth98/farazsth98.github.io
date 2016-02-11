---
layout: post
title: Infosec Institute CTF2 Practical Web Hacking Level 5
category: Web
tags: infosec
---

**Vulnerability** A7 Missing Function Level Access Control
**Description:**

![screen]({{site.url}}/assets/Screen Shot 2015-07-17 at 2.25.54 AM.png)

## Write-up

For almost all levels I will be using Burpsuite. Burpsuite is an interception proxy that lets us modify the HTTP request
 / response by intercepting the data between the browser and the web server.
 
Let's see the request in Burpsuite.

{% highlight text  %}
GET /ctf2/exercises/ex5.php HTTP/1.1
Host: ctf.infosecinstitute.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0 Iceweasel/31.6.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Cookie: PHPSESSID=gdc668pjmpah42hegt7sa7igc3
Connection: keep-alive
{% endhighlight %}

Hm, no special Cookies, no function parameters. Let's take a look at the source.

{% highlight text  %}
<p class="lead">You are not logged in. Please <a class="btn btn-sm btn-info" disabled href="login.html">login</a> to access this page.</p>
{% endhighlight %}

The button to login is disabled. Let's delete the 'disabled' attribute and maybe find something there.
Right-Click on the login button -> InspectElement. However the link is bogus, it returns 404 not found.

![screen1]({{site.url}}/assets/Screen Shot 2015-07-17 at 2.45.42 AM.png)

The instructions state that this page is only viewable by logged in users.
How can we simulate that we are coming from a page within an logged in account? Using the Referer HTTP header of course.
Lets refresh the page and modify the request using Burp.

![screen2]({{site.url}}/assets/Screen Shot 2015-07-17 at 2.48.34 AM.png)

Inserting Referer HTTP header with value "http://ctf.infosecinstitute.com/ctf2/exercises/login.html"
circumvents the Access Control that we are coming from a page that's already within a logged in account.

![screen3]({{site.url}}/assets/Screen Shot 2015-07-17 at 2.54.45 AM.png)

## Links

* <http://ctf.infosecinstitute.com/ctf2/exercises/ex5.php>
