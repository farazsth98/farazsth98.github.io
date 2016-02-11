---
layout: post
title: Infosec Institute CTF Level 8
category: Web
tags: infosec
---

**Bounty:** $80
**Description:**

> Do you want to download the [app.exe]({{site.url}}/assets/app.exe) file?

## Write-up

Simply extracting any printable characters from the binary with "strings" does the trick for this one.

{% highlight bash %}
$ strings app.exe  | grep flagis
infosec_flagis_0x1a
{% endhighlight %}

## Links

* <http://ctf.infosecinstitute.com/leveleight.php>

