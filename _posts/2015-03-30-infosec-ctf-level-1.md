---
layout: post
title: Infosec Institute CTF Level 1
category: web
tags: infosec
---

**Bounty:** $10
**Description:**

> May the source be with you!

## Write-up

Simple enough, the flag is within a HTML comment tag in the source code.

{% highlight sh %}
$ curl http://ctf.infosecinstitute.com/levelone.php | grep flag  
<!-- infosec_flagis_welcome -->  
{% endhighlight %}

## Links

* <http://ctf.infosecinstitute.com/levelone.php>
