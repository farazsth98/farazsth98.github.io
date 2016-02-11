---
layout: post
title: Infosec Institute CTF Level 4
category: web
tags: infosec
---

**Bounty:** $40
**Description:**

> HTTP means Hypertext Transfer Protocol

## Write-up

Website sets the following HTTP Cookie:

{% highlight bash %}
$ curl -I http://ctf.infosecinstitute.com/levelfour.php
HTTP/1.1 200 OK
Date: Mon, 16 Mar 2015 04:10:59 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.6
Set-Cookie: fusrodah=vasbfrp_syntvf_jrybirpbbxvrf
Content-Type: text/html
{% endhighlight %}

If we decrypt it using a simple substitution cipher ROT13, we get the flag.

{% highlight bash %}
$ echo 'vasbfrp_syntvf_jrybirpbbxvrf' | tr '[abcdefghijklmnopqrstuvwxyz]' '[nopqrstuvwxyzabcdefghijklm]'
infosec_flagis_welovecookies
{% endhighlight bash %}

## Links

* <http://ctf.infosecinstitute.com/levelfour.php>
