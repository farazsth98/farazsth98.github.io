---
layout: post
title: Infosec Institute CTF2 Practical Web Hacking Level 13
category: Web
tags: CTF challenges
---

# ctf.infosecinstitute.com: Level 13
**Vulnerability** A10 Unvalidated Redirects and Forwards
**Description:**

![screen]({{site.url}}/assets/Screen Shot 2015-07-17 at 7.33.48 PM.png)

## Write-up

For almost all levels I will be using Burpsuite. Burpsuite is an interception proxy that lets us modify the HTTP request
 / response by intercepting the data between the browser and the web server.
 
As stated in the description, it looks like level 13 is using a redirect function via URL parameter "redirect"
that send us to ex13-task.php. We can see that just by mouse-overing the Level13 link from the drop down menu.

![screen1]({{site.url}}/assets/Screen Shot 2015-07-17 at 7.42.34 PM.png)

Our goal is to make the function work with external domain.

If we try the following url we get "bad parameter" error.

{% highlight text %}
http://ctf.infosecinstitute.com/ctf2/exercises/ex13.php?redirect=wWw.google.com
{% endhighlight %}

If we try without the "www", we get redirected to page "google.com" on the same domain, since this page does not exist
we get a 404 Not Found response code.

![screen2]({{site.url}}/assets/Screen Shot 2015-07-17 at 7.49.25 PM.png)

We now know that there's a filter that blocks any argument contains "www" case-insensitive.

The next test would be to try using the protocol.

{% highlight text %}
http://ctf.infosecinstitute.com/ctf2/exercises/ex13.php?redirect=hTtP://google.com
{% endhighlight %}

Again we get the "bad parameter" error. Seems like there's another filter for "http" keyword case-insensitive.
If we try "ftp://" however, we do get redirected to google.com on port 21 (ftp).

{% highlight text %}
http://ctf.infosecinstitute.com/ctf2/exercises/ex13.php?redirect=ftp://google.com
{% endhighlight %}

Of course, we get Connection Timeout Error since there's no FTP server at google.com address.

![screen3]({{site.url}}/assets/Screen Shot 2015-07-17 at 7.58.37 PM.png)

If we use the following we get a redirect to the domain in our argument but this way we don't complete the level :(.

{% highlight text %}
http://ctf.infosecinstitute.com/ctf2/exercises/ex13.php?redirect=\\google.com
{% endhighlight %}

If we try the oposite slash however, the forward slash, the level marks as completed :).

{% highlight text %}
http://ctf.infosecinstitute.com/ctf2/exercises/ex13.php?redirect=//google.com
{% endhighlight %}

![screen4]({{site.url}}/assets/Screen Shot 2015-07-17 at 8.04.47 PM.png)

## Links

* <http://ctf.infosecinstitute.com/ctf2/exercises/ex13.php?redirect=ex13-task.php>
* <http://ctf.infosecinstitute.com/ctf2/exercises/ex13-task.php>
