What is this?
-------------

``django-session-csrf`` is an alternative implementation of Django's CSRF
protection that does not use cookies. Instead, it maintains the CSRF token on
the server using Django's session backend. The csrf token must still be
included in all POST requests (either with `csrfmiddlewaretoken` in the form or
with the `X-CSRFTOKEN` header).

Why this replacement?
---------------------

The default Django CSRF protection provides adequate protection against CSRF attacks.
So there is no reason from security perspective to switch to this alternative.

I programmed this implementation because a external security assement agency found that
the default Django CSRF protection does not follow the OWASP 'Synchronizer Token Pattern'
recommendation:
https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29_Prevention_Cheat_Sheet

Following this OWASP recommendation was a security-requirement for one of our projects.

How does this implementation work?
-----------------------------------
When the '{{csrf_token}}' template tag is used in a template, a CSRF token is generated and appended
to a list of tokens stored in the session.
The '{{csrf_token}}' template tag adds a hidden input element to the form with the token value.
When the form is posted, a check is done on the server to see if the posted CSRF Token matches one
of the tokens on the list stored in the session.

If the server side check is succesful the used token is removed from the session. You
can override this with the setting 'CSRF_REMOVE_USED_TOKENS'.

The list of tokens stored in the session will store a maximum of 5 CSRF Tokens.
If a 6th CSRF Token is added, the oldest CSRF Token on the list will be removed.
You can customize the number of tokens to keep with the setting 'CSRF_NUMBER_OF_TOKENS_TO_KEEP'.

So at any time this CSRF implementation will accept the 5 unused latests issued CSRF
tokens for a particuliar session.
This is done to prevent the CSRF protection from kicking in when the visitor opens the
website in a second tab in his browser for example.

If the CSRFToken is added as a 'X_CSRFTOKEN' header in the HTTP POST, the token is
not removed from the session upon checking. This is done because this HTTP POST is likely
to be from a Ajax call or something similair. So this Ajax client can do his request
multiple times, without his CSRFToken to expire.

For each generated CSRF Token in the list a timestamp 'created'
is kept. CSRF Tokens older then 1 hour are removed from the list.
This cleaning up is done when the server receives a POST but before checking the
received token against the list in the session.

Credits
-------
I based this CSRF protection implemenation on https://github.com/scjody/django-session-csrf

Installation
------------

From github::

    git clone git://github.com/renehoek/django-session-csrf.git

Replace ``django.core.context_processors.csrf`` with
``session_csrf.context_processor`` in your ``TEMPLATE_CONTEXT_PROCESSORS``::

    TEMPLATE_CONTEXT_PROCESSORS = (
        ...
        'session_csrf.context_processor',
        ...
    )

Replace ``django.middleware.csrf.CsrfViewMiddleware`` with
``session_csrf.CsrfMiddleware`` in your ``MIDDLEWARE_CLASSES``
and make sure it is listed after the AuthenticationMiddleware::

    MIDDLEWARE_CLASSES = (
        ...
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        ...
        'session_csrf.CsrfMiddleware',
        ...
    )

Then we have to monkeypatch Django to fix the ``@csrf_protect`` decorator::

    import session_csrf
    session_csrf.monkeypatch()

Make sure that's in something like your root ``urls.py`` so the patch gets
applied before your views are imported.

Settings
--------

In the Django settings.py file you can set the following settings:

CSRF_STRICT_REFERER_CHECKING = ['True|False'] Default: True

In a SSL setup peform a strict referer check.

CSRF_NUMBER_OF_TOKENS_TO_KEEP = 5

The number of previous issued tokens to keep in the list.

CSRF_REMOVE_UNUSED_TOKENS_AFTER = 3600 

The max-age in seconds of issued tokens. Tokens older then the max-age are removed from the list.

CSRF_REMOVE_USED_TOKENS = ['True|False'] Default: True

Once a token is used, remove or keep it on the list. Default is to remove the used token from the list.

Decorators
----------
In decorators.csrf you find the ``csrf_keep_token`` decorator. When you apply this decorator to a view, the used
token is not removed from the session. This can be usefull if for example you use the jQuery FileUpload plugin. With this
plugin multiple files can be uploaded (POSTed). If you don't apply the ``csrf_keep_token`` decorator to the
corresponding 'upload view' the fifth+ upload will fail.

For Ajax calls this decorator is not needed. If a csrftoken is send with the X_CSRFTOKEN header in the http request the
used token is not removed from the session by default.


Disadvantages
------------
This CSRF implemenation is tied to the Django session framework. You can't use it
without sessions enabled.

It is not recommended to use 'Cookie-bases-sessions'. Otherwise you will leak previously
issued CSRF tokens.
https://docs.djangoproject.com/en/dev/topics/http/sessions/#using-cookie-based-sessions

Don't confuse this with the 'sessionid' cookies which just store a reference to a session
in a cookie.

Differences from Django
-----------------------

In this implementation 'anonymous' users will also get a session.
This is needed in order to store the CSRF Token server-side.

A CSRF token cookie is not sent because it is not needed for CSRF
protection.  If you have AJAX code or other web services that need a
CSRF token, you can add the '{{csrf_token_tag}}' on the template and
send it as a 'X_CSRFTOKEN' header with the following javascript (assumes jQuery):

$(document).ajaxSend(function(event, xhr, settings) {
    
    function getElementWithCSRFToken(name) {
        if (document.getElementsByName(name).length >= 1) {
            return document.getElementsByName(name)[0].value
        }
        return ""
    }
    
    function sameOrigin(url) {
        // url could be relative or scheme relative or absolute
        var host = document.location.host; // host + port
        var protocol = document.location.protocol;
        var sr_origin = '//' + host;
        var origin = protocol + sr_origin;
        // Allow absolute or scheme relative URLs to same origin
        return (url == origin || url.slice(0, origin.length + 1) == origin + '/') ||
            (url == sr_origin || url.slice(0, sr_origin.length + 1) == sr_origin + '/') ||
            // or any other URL that isn't scheme relative or absolute i.e relative.
            !(/^(\/\/|http:|https:).*/.test(url));
    }
    function safeMethod(method) {
        return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
    }

    if (!safeMethod(settings.type) && sameOrigin(settings.url)) {
        xhr.setRequestHeader("X-CSRFToken", getElementWithCSRFToken('csrfmiddlewaretoken'));
    }
});



Why do I want this?
-------------------

1. You must follow the OWASP 'Synchronizer Token Pattern' recommendation
   

Why don't I want this?
----------------------

1. Storing tokens in sessions means you have to hit your session store more
   often.
   
2. When a user submit a form, goes back in his browser with his 'back' button
   and sends the form again the CSRF protection will kick in. You can
   override this though with the 'CSRF_REMOVE_USED_TOKENS' setting.


