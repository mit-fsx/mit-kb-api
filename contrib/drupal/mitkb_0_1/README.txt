MIT KB DRUPAL MODULE  (proof of concept)
Jessica Reed, MIT Information Systems & Technology
Copyright 2014 Massachusetts Institute of Technology

This is a sample proof-of-concept module, designed to illustrate
one of many possible ways to integrate the KB API with a Drupal site.
Every effort is made to keep this file up to date, but in the event
of a conflict between this file and the API documentation, the latter
should be considered canonical.

See LICENSE.txt for license information.

WHAT IT DOES:

Installs an input filter which dynamically replaces the shortcode
"[mit-kb articleID]" with the contents of an MIT Knowledge Base article
in a public space.  The contents are formatted with standard tags (<h1>,
<strong>, <table>, etc.), and will respect your Drupal theme's CSS.

It will also replace the shortcode "[mit-kb-excerpt articleID]" with an
excerpt from the article, as bounded by the {excerpt} tag in the
article's markup.

Leverages the MIT KB API.  Documentation is available at:
http://kb.mit.edu/confluence/x/cVAYCQ

An API key is required.  You are encouraged to read the API
documentation in its entirety.  Experience with installing and
configuring community-developed Drupal modules is assumed.

HOW TO INSTALL:
1) Install this module through Administration > Modules
(see also:  https://www.drupal.org/documentation/install/modules-themes)
2) Enable the module Administration > Modules
3) Enable the filter "MIT-KB" in each text format you want to use, via
   Configuration > Text Formats 4) Follow the "MIT KB module settings"
   link in the administration menu, or visit
   YOURSITE/admin/settings/mitkb, and set your API key.

   Clearing your caches may be required to cause Drupal to render the
   module's menu and settings page.


TEXT FORMAT LIMITATIONS:
This will work out-of-the-box on pages with the text formats "Full HTML"
and "PHP Code"

If you want to use it in a page with the "Filtered HTML" text format,
you must add the following tags to the allowed HTML tags for that
format: <img><h1><h2><h3><h4><h5><h6><table><tr><td>

(To add tags, go to Configuration > Text Formats > Filtered HTML > configure >
Filter Settings >  Limit Allowed HTML Tags, then add the desired tags to the
"Allowed HTML Tags" field.  Then save your configuration.)

You can omit any tags you don't want rendered on your site, but they
will be treated as body text.  (ex: the table-related tags are needed
for tables and warning boxes)

HOW TO USE:
To display the full contents of an article on your page, enter shortcode:
[mit-kb articleID]

To display an excerpt from an article on your page, enter shortcode:
[mit-kb-excerpt articleID]

Where "articleID" is the numerical ID of the KB article you want to display.



SUGGESTED FUTURE ENHANCEMENTS:

* Add a filter tip and hook help, to give the user contextual help with
the filter and module from within Drupal

* Add a prepare callback, to make sure that other filters don't strip
the shortcode before it can be implemented.  (This proof of concept only
runs at the process stage)

* Allow the user to submit the short URL of the article, rather than the
  articleID

* Check for missing excerpts in valid KB articles.  Right now, the API
   returns a 404 error if either the articleID is bad, or if you request
   an excerpt, but there is no excerpt defined in the article.
