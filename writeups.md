---
layout: default
title: Writeups
permalink: /writeups/
---
<h1 id="post-title">CTF Writeups</h1>

<ul class="posts">
	{% for post in site.categories.writeups %}
    	{% if post.url %}
        	<li>
        		<h2><a href="{{ post.url }}">{{ post.title }} - {{ post.date | date_to_string }}</a></h2>
        	</li>
    	{% endif %}
  	{% endfor %}
</ul>