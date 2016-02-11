---
layout: post
title: Infosec Institute CTF2 Practical Web Hacking Level 8
category: Web
tags: infosec
---

**Vulnerability** File Inclusion
**Description:**

![screen]({{site.url}}/assets/Screen Shot 2015-07-17 at 3.55.16 PM.png)

## Write-up

For almost all levels I will be using Burpsuite. Burpsuite is an interception proxy that lets us modify the HTTP request
 / response by intercepting the data between the browser and the web server.
 
The functionality of this web page allows us to upload a file. By embedding our file to the page, we need to check if
we can inject files other than images. Let's first try uploading a regular file.

File has been uploaded successfully.
![screen1]({{site.url}}/assets/Screen Shot 2015-07-17 at 4.10.16 PM.png)

Now let's try uploading a non-image file.
![screen2]({{site.url}}/assets/Screen Shot 2015-07-17 at 4.25.21 PM.png)

Seems like there's a restriction on the file extension, who knows maybe this is the same filter as in Level 4?
Time to see the request in Burpsuite.

![screen2]({{site.url}}/assets/Screen Shot 2015-07-17 at 4.35.04 PM.png)

Let's try applying the same trick as in Level 4.

![screen3]({{site.url}}/assets/Screen Shot 2015-07-17 at 4.37.58 PM.png)

Fair enough, it works ! Now let's change the content from being an image to some embedded JavaScript.

![screen4]({{site.url}}/assets/Screen Shot 2015-07-17 at 4.40.31 PM.png)

We also needed to change the filename since we can not overwrite files.

The only thing left to do is see how to display our newly uploaded file into the main web page.
Let's click on one of the "Editor's Choice" images, by doing so we see two things:  
1) The URL is using "attachment_id" parameter to load an image.  
2) The store directory is http://ctf.infosecinstitute.com/ctf2/ex8_assets/img/  

Let's browse and see if we can access our file. Upon visiting URL
{% highlight text %}
http://ctf.infosecinstitute.com/ctf2/ex8_assets/img/DDDD1.png.html
{% endhighlight %}
we are presented with the "Level Complete" message and a URL redirect to
{% highlight text %}
http://ctf.infosecinstitute.com/ctf2/exercises/ex8.php?file=DDDD1.png.html
{% endhighlight %}

![screen5]({{site.url}}/assets/Screen Shot 2015-07-17 at 4.47.17 PM.png)


## Links

* <http://ctf.infosecinstitute.com/ctf2/exercises/ex8.php>
