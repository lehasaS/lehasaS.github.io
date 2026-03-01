---
layout: page
title: Tags
permalink: /tags/
---

Browse posts by tag:

{% assign tags_sorted = site.tags | sort %}

<div class="tag-index">
  <ul>
    {% for tag in tags_sorted %}
      {% assign tag_name = tag[0] %}
      <li>
        <a href="#{{ tag_name | slugify }}">{{ tag_name }}</a>
        <small>({{ tag[1].size }})</small>
      </li>
    {% endfor %}
  </ul>

  {% for tag in tags_sorted %}
    {% assign tag_name = tag[0] %}
    <h2 id="{{ tag_name | slugify }}">{{ tag_name }}</h2>
    <ul>
      {% for post in tag[1] %}
        <li>
          <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
          <small>{{ post.date | date: "%Y-%m-%d" }}</small>
        </li>
      {% endfor %}
    </ul>
  {% endfor %}
</div>

