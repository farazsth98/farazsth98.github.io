---
layout: post
title: Infosec Institute CTF2 Practical Web Hacking Level 2
category: Web
tags: infosec
---

**Vulnerability** A1 Injection
**Description:**

![screen]({{site.url}}/assets/Screen Shot 2015-07-16 at 11.21.37 PM.png)

## Write-up

For almost all levels I will be using Burpsuite. Burpsuite is an interception proxy that lets us modify the HTTP request
 / response by intercepting the data between the browser and the web server.
 
The requirements state that we need Apache info and PHP version, we can get that using 'phpinfo();' php function.
Let's see how we can inject php using this web calculator.  

First let's see how a regular HTTP request looks like by capturing it via Burp. Submit some numbers to the calculator, select an
operator and click on 'calculate'. Burp will capture your request and it should look like something like this:

![screen1]({{site.url}}/assets/Screen Shot 2015-07-16 at 11.29.52 PM.png)

We have 3 parameters, 'operand1', 'operator' and 'operand2', our injection point will be one of these parameters.
Because we don't want to be jumping back and forth between the browser and Burp, we can use Burp's Repeater feature.
Click on 'action' and select 'Send to Repeater', you will see the Repeater tab flash.

![screen2]({{site.url}}/assets/Screen Shot 2015-07-16 at 11.39.16 PM.png)

Now we can play around with different values. For successful injection, we need to use the 'operator' parameter by first closing
the php statement with semi-colon following our php code and close statement with another semi-colon.

![screen3]({{site.url}}/assets/Screen Shot 2015-07-16 at 11.43.32 PM.png)




## Links

* <http://ctf.infosecinstitute.com/ctf2/exercises/ex2.php>
