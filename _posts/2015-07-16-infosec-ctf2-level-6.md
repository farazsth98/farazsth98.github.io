---
layout: post
title: Infosec Institute CTF2 Practical Web Hacking Level 6
category: Web
tags: CTF challenges
---

# ctf.infosecinstitute.com: Level 6
**Vulnerability** A8 Cross-Site Request Forgery (CSRF)
**Description:**

![screen]({{site.url}}/assets/Screen Shot 2015-07-17 at 3.04.05 AM.png)

## Write-up

For almost all levels I will be using Burpsuite. Burpsuite is an interception proxy that lets us modify the HTTP request
 / response by intercepting the data between the browser and the web server.
 
On this one we need to craft an HTML tag will cause users to perform an HTTP request upon loading the page.
The available tags we can use are b, em, p, i, u, s, img, a, abbr, cite and code.
Let's see which ones we can actually use to complete this task.

First I tried using an HTML5 OnEvent attribute to trigger an action like  
&lt;b onload="javascript:alert('XSS');"&gt;TEST&lt;/b&gt; but the page returned an error.

![screen1]({{site.url}}/assets/Screen Shot 2015-07-17 at 3.34.44 AM.png)

If there is no event handler, we can not use any On-Events and most of the available tags are useless.
The solution for me was to insert an img tag with source the desired HTTP request.

{% highlight html %}
<img src="http://site.com/bank.php?transferTo=555">
{% endhighlight %}

This is going to cause the browser to make an HTTP request to the URL in the src attribute as is.
I will not consider this as the most elegant solution since it leaves an error of the non-existent image load attempt.

![screen3]({{site.url}}/assets/Screen Shot 2015-07-17 at 3.41.15 AM.png)

## Links

* <http://ctf.infosecinstitute.com/ctf2/exercises/ex6.php>
