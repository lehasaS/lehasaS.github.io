---
layout: page
title: Series
permalink: /series/
---

Longer investigations sometimes need space to unfold. This page groups posts that share a `series` field in their front matter.

{% assign series_names = site.posts | where_exp: "p", "p.series" | map: "series" | uniq | sort %}

{% for name in series_names %}
  <h2 id="{{ name | slugify }}">{{ name }}</h2>
  {% assign series_posts = site.posts | where: "series", name | sort: "series_part" %}
  <ul>
    {% for post in series_posts %}
      <li>
        <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
        <small>{{ post.date | date: "%Y-%m-%d" }}</small>
      </li>
    {% endfor %}
  </ul>
{% endfor %}
