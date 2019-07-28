---
layout: default
title: Guides
permalink: /guides/
---
<h1 id="post-title">Guides</h1>

<ul class="posts">
	{% for post in site.categories.guides %}
    	{% if post.url %}
        	<li>
        		<h2><a href="{{ post.url }}">{{ post.title }} - {{ post.date | date_to_string }}</a></h2>
        	</li>
    	{% endif %}
  	{% endfor %}
</ul>