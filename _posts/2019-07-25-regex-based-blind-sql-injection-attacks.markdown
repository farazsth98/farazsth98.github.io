---
layout: post
title: 	"Regex-based Blind SQL Injection Attacks"
date:	2019-07-25 01:53:00 +0800
categories: guides
---

# Introduction

I recently participated in PeaCTF and came across [a very well made web exploitation challenge](/writeups/peactf/2019/07/28/peactf-all-challenges.html#philips-and-over). It required participants to perform a blind SQL injection attack to retrieve an admin password and successfully login to get the flag. I think writing an actual guide explaining the basic concept behind a regex-based blind SQL injection attack would prove useful to a lot of people since most of the guides I've found don't really explain it in too much depth.

Disclaimer: All the following will follow MySQL syntax. This attack can be adapted to any type of SQL with a little bit of work.

# What is a Blind SQL Injection?

If you've done any introductory CTF web challenges, or any practice challenges on websites like wechall or hackerone, you will have come across SQL injections where a simple `'or 1=1 -- .` dumps information from the DB. This works because the output of the query is actually displayed on the page that you are on. A blind SQL injection is where an SQL injectable parameter/input still exists, however you don't actually get any output from the query itself.

# How does it work?

In cases like this, the only information you ***can*** get is that your query either succeeded (returned TRUE) or failed (returned FALSE). This type of injection is usually found in GET parameters in the url. A website that displays images using a GET parameter such as `www.mywebsite.com/image?id=1` is a prime target to test. If it is vulnerable to a blind SQL injection attack, the following will be true:

* `www.mywebsite.com/image?id=1` will return the image on the page
* `www.mywebsite.com/image?id=1 AND 1=1 -- .` will also return the image on the page
* `www.mywebsite.com/image?id=1 AND 1=2 -- .` will not return the image on the page

With a simple boolean injection, we can verify that the id parameter is injectable. From there on, you will need to  