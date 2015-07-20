---
layout: post
title: Infosec Institute CTF2 Practical Web Hacking Level 1
category: Web
tags: CTF challenges
---

# ctf.infosecinstitute.com: Level 1
**Vulnerability** A3 Cross-Site Scripting (XSS)
**Description:**

> People want you to store your favorite links here.
> However, you are not into that, you just want to do some XSS magic to the page.
> Add an alert with the message 'Ex1' to the page (My Sites:)
> ![screen]({{site.url}}/assets/Screen Shot 2015-07-16 at 10.13.34 PM.png)

## Write-up

For almost all levels I will be using Burpsuite. Burpsuite is an interception proxy that lets us modify the HTTP request
 / response by intercepting the data between the browser and the web server.
 
Let's try injecting the javascript "&lt;script&gt;alert('Ex1');&lt;/script&gt;" into one of the input fields.

![screen2]({{site.url}}/assets/Screen Shot 2015-07-16 at 10.25.53 PM.png)

It looks like we have some input validation. Since there was no data intercepted by Burp, we can deduct that the input
validation is done via HTML or javascript on the client side. Let's take a look at the source.

{% highlight html linenos %}
<input type="text" placeholder="Name of site" maxsize="10" class="form-control" pattern="[A-Za-z]+" required="" name="name">
<input class="form-control" placeholder="URL of site" type="url" required="" maxsize="15" name="url">
{% endhighlight %}

Both forms have some HTML input validation, the site-name input field has a pattern with allowed regex "[A-Za-z]+", maxsize of 10 characters.
URL field have type="url" and maxsize="15".   

Since all the data is on the client side, we can just simply delete all the validations. Let's try deleting the pattern and max size
from the site-name field first and resubmitting our payload (right-click on the site-name field, InspectElement and delete the pattern and maxsize attributes).

![screen3]({{site.url}}/assets/Screen Shot 2015-07-16 at 10.46.48 PM.png)

Ok, we were able to submit the payload however, there was no pop-up and there was no request intercepted by Burp.
This means that  
1) Since no request was intercepted with Burp, the functionality of the URL embedding to the page is via JavaScript
2) The <script>, less than and greater than signs were encoded to avoid syntax interpretation. This means we have input sanitization.

Let's go back to the source and look for JavaScript objects. Fair enough, we see the following .js file included in the page.

{% highlight javascript linenos %}
/**
 * Created by Ivan on 12.3.2015 Ð³..
 */
$(function() {
    var Exercises = {
        ex1: {

            initialize: function() {
                $("#messages").text("People want you to store your favorite links here. However, you are not into that, you just want to do some XSS magic to the page. Add an alert with the message 'Ex1' to the page (My Sites:)");
                var nativeAlert = window.alert;
                var lastAlert = null;
                window.alert = function(msg) {
                    nativeAlert(msg);
                    lastAlert = msg;
                }
                $("form.ex1").submit(function(evt) {
                    evt.preventDefault();
                    var siteName = $(".ex1 input[type='text']").val().trim().replace(/</g, "&lt;").replace(/>/g, "&gt;");
                    var siteURL = $(".ex1 input[type='url']").val().trim().replace(/</g, "&lt;").replace(/>/g, "&gt;");



                    $("<p class='lead'><span class='label label-success'>" + siteName + "</span>" + siteURL + "</p>").appendTo(".ex1.links-place");
                    if (testForScript("Ex1", [siteName, siteURL], lastAlert)) {

                        $("#messages").removeClass("alert-info").addClass("alert-success");
                        $("#messages").text("You made it to exercise 2. You will be redirected to it in 10 seconds.")
                        levelCompleted(1);



                    }




                })
            }
        }
    }

    Exercises.ex1.initialize();

})
//start it



function spitRegex(text) {
    return  new RegExp("<script>\\s*alert\\(['\"]{1}" + text + "['\"]{1}\\);*\\s*<\\/script>", "g");
}

function testForScript(patternText, variablesToCheck, lastAlert) {
    var regex = spitRegex(patternText);
    for (var i = 0; i < variablesToCheck.length; i++) {
        if (regex.test(variablesToCheck[i])) {
            if (lastAlert === patternText) {
                return true;


            }
        }
    }
    return false;
}
{% endhighlight %}

On line 18 and 19 we can see that <> signs are substituted with &amp;lt; and &amp;gt; which is the sanitation function.

Again, since JavaScript is executed by the browser, all the data is controlled by the user on the client-side.
Let's start the Browser Developer Tools and remove the sanitizing part (the selected javascript until trim()).

![screen4]({{site.url}}/assets/Screen Shot 2015-07-16 at 11.08.22 PM.png)

Now let's resubmit our JavaScript payload again.

![screen5]({{site.url}}/assets/Screen Shot 2015-07-16 at 11.15.00 PM.png)

And... level 1 complete.

![screen6]({{site.url}}/assets/Screen Shot 2015-07-16 at 11.15.13 PM.png)

## Links

* <http://ctf.infosecinstitute.com/ctf2/exercises/ex1.php>
