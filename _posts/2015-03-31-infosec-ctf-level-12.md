---
layout: post
title: Infosec Institute CTF Level 12
category: write-ups
tags: CTF challenges
---

# ctf.infosecinstitute.com: Level 12
**Bounty:** $120
**Description:**

> Dig deeper! ![image]({{site.url}}/assets/yoda.png)

## Write-up

The yoda image is a red herring. It did made me waste some time of my life :). So remembering that the image from Level 1 was pretty much the same, I decided to download both images and look for different bits.

{% highlight bash %}
$ diff yoda.png yoda_from_level_1.png
$
{% endhighlight %}

After confirming both images are identical, I knew the flag was not in the image, so it had to be somewhere else. Next I checked the source code from level 1 for differences.

{% highlight bash %}
$ curl http://ctf.infosecinstitute.com/levelone.php | head > levelone_source
$ curl http://ctf.infosecinstitute.com/leveltwelve.php | head > leveltwelve_source
$ diff leveltwelve_source levelone_source
0a1
> <!-- infosec_flagis_welcome -->
10d10
<     <link href="css/design.css" rel="stylesheet">
$
{% endhighlight %}

We see two differences. The first one is the flag in the HTML comment field from Level 1. However Level 2 seems to have additional CSS, css/design.css.
Let's see what's in there.

{% highlight bash %}
$ curl http://ctf.infosecinstitute.com/css/design.css
.thisloveis{
	color: #696e666f7365635f666c616769735f686579696d6e6f7461636f6c6f72;
$
{% endhighlight %}

Yep, we got it. Since the hex encoded strings is actually an "id selector" in CSS, decoding it we get the flag.

{% highlight bash %}
$ python -c 'print("\x69\x6e\x66\x6f\x73\x65\x63\x5f\x66\x6c\x61\x67\x69\x73\x5f\x68\x65\x79\x69\x6d\x6e\x6f\x74\x61\x63\x6f\x6c\x6f\x72")'
infosec_flagis_heyimnotacolor
{% endhighlight %}

## Links

* <http://ctf.infosecinstitute.com/leveltwelve.php>

