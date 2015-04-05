---
layout: post
title: Infosec Institute CTF Level 11
category: write-ups
tags: CTF challenges
---

# ctf.infosecinstitute.com: Level 11
**Bounty:** $110
**Description:**

> What another sound again???
> No it must not be a sound? But wait whaT?
> ![PHP-LOGO]({{site.url}}/assets/php-logo-virus.jpg)

## Write-up

Let's look for any embeded strings to the image. Lucky enough, using "strings" again, we find the flag.

{% highlight bash %}
$ strings php-logo-virus.jpg | grep flag
infosec_flagis_aHR0cDovL3d3dy5yb2xsZXJza2kuY28udWsvaW1hZ2VzYi9wb3dlcnNsaWRlX2xvZ29fbGFyZ2UuZ2lm
{% endhighlight %}

However, the last part of the flag looks encoded. It looks like it's base64 again, so let's decode it.

{% highlight bash %}
$ echo -n 'aHR0cDovL3d3dy5yb2xsZXJza2kuY28udWsvaW1hZ2VzYi9wb3dlcnNsaWRlX2xvZ29fbGFyZ2UuZ2lm' | base64 -d
http://www.rollerski.co.uk/imagesb/powerslide_logo_large.gif
{% endhighlight %}

Downloading the [gif]({{site.url}}/assets/powerslide_logo_large.gif) from the extracted link, and opening it, it display's  "powerslide". So the flag becomes:  
infosec_flagis_powerslide  

## Links

* <http://ctf.infosecinstitute.com/leveleleven.php>
