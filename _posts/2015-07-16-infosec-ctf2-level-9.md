---
layout: post
title: Infosec Institute CTF2 Practical Web Hacking Level 9
category: Web
tags: infosec
---

**Vulnerability** A2 Broken Authentication and Session Management
**Description:**

![screen]({{site.url}}/assets/Screen Shot 2015-07-17 at 4.54.55 PM.png)

## Write-up

For almost all levels I will be using Burpsuite. Burpsuite is an interception proxy that lets us modify the HTTP request
 / response by intercepting the data between the browser and the web server.
 
Since HTTP protocol is stateless, the main method of session management is via the Cookie HTTP header.
If our goal is session impersonation, like changing from user John Doe to user Mary Jane undoubtedly
it will encompass session hijacking.  

We can see the Cookies associated with our session for the ctf.infosecinstitute.com domain by Right-Click -> Inspect Element ->
Resources -> Cookies -> ctf.infosecinstitute.com. As expected we see 2 Cookies, one PHPSESSID that identifies us as a CTF competing user
and "user" that possibly identifies us within this level as "John Doe".

![screen1]({{site.url}}/assets/Screen Shot 2015-07-17 at 5.02.19 PM.png)

Let's refresh the page and capture the request in Burp. There we can use Burp's Decoder to see how are sessions managed by this
application.

![screen2]({{site.url}}/assets/Screen Shot 2015-07-17 at 5.04.29 PM.png)

As the screenshot shows, select the text you would want to use in the Decoder and select "Send to Decoder".
The Decoder tab will flash, navigate there and you will see the following.

![screen3]({{site.url}}/assets/Screen Shot 2015-07-17 at 5.09.10 PM.png)

Now we can Encode/Decode this piece of text using different methods as URL, Base64, HEX, HTML Entity and so on...
Since this is being URL Encoded by the browser, we need to first URL Decode it. Select "Decode as.." -> "URL".
You will see the text transform to "Sk9ITitET0U=".

One easy giveaway for encodings is the "=" or "==" pad at the end of the string, it usually is using base64 encoding.
Base64 encoding just as URL encoding is used to exchange non-printable characters between the exchanging parties.

Let's select "Decode as.." -> "Base64", we will see it decode without any issues to the string "JOHN+DOE".
Let's change that to "MARY+JANE" and base64 encode it, we should get the following string "TUFSWStKQU5F".

![screen4]({{site.url}}/assets/Screen Shot 2015-07-17 at 5.16.59 PM.png)

Now we can go back to our intercepted request in the Proxy tab and change the session's cookie with the newly produced base64
string.

![screen5]({{site.url}}/assets/Screen Shot 2015-07-17 at 5.19.04 PM.png)

All that's left to do is press the "Forward" button to send the request to the web server.
Going back to our browser, it looks like we successfully highjacked Mary Jane's session.

![screen6]({{site.url}}/assets/Screen Shot 2015-07-17 at 5.20.55 PM.png)

## Links

* <http://ctf.infosecinstitute.com/ctf2/exercises/ex9.php>
