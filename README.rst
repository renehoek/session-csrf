What is this?
-------------

``django-session-csrf`` is an alternative implementation of Django's CSRF
protection. It maintains the CSRF token on the server using Django's session backend.
The csrf token must still be included in all POST requests. This is done with the cookie which is POSTed
along by the browser. On every GET a new CSRF Token is generated and stored in the session and in the cookie.

Why this replacement?
---------------------

The default Django CSRF protection provides adequate protection against CSRF attacks.

However the default Django CSRF protection does not follow the OWASP 'Synchronizer Token Pattern'
recommendation:
https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29_Prevention_Cheat_Sheet

This recommendation states that a CSRF token should be recycled as much as possible.

How does this implementation work?
-----------------------------------
On every GET a fresh CSRF token is generated and stored in the session. This CSRF token is als send too the browser
with a 'Set-Cookie' response header.

When a form is posted, a check is done on the server to see if the posted CSRF token from the cookie matches the token
stored in the session.

If the server side check is succesful the used token is replaced in the session with a new one. In the reply send
back to the browser a 'Set-Cookie' header is send with the new CSRF Token.


Credits
-------
I based this CSRF protection implemenation on https://github.com/scjody/django-session-csrf

Installation
------------

From github::

    git clone git://github.com/renehoek/django-session-csrf.git

Remove  ``django.core.context_processors.csrf`` from ``TEMPLATE_CONTEXT_PROCESSORS``::


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


Settings
--------

In the Django settings.py file you can set the following settings:

CSRF_STRICT_REFERER_CHECKING = ['True|False'] Default: True

In a SSL setup peform a strict referer check.


Decorators
----------
In decorators.csrf you find the ``csrf_keep_token`` decorator. This decorator is deprecated.

You also have the ``csrf_exempt`` decorator. You can use this to exempt a view from the CSRF protection.

Disadvantages
------------
This CSRF implemenation is tied to the Django session framework. You can't use it
without sessions enabled.

It is not recommended to use 'Cookie-based-sessions'.
https://docs.djangoproject.com/en/dev/topics/http/sessions/#using-cookie-based-sessions

Don't confuse this with the 'sessionid' cookies which just store a reference to a session
in a cookie.

Differences from Django
-----------------------

In this implementation 'anonymous' users will also get a session.
This is needed in order to store the CSRF Token server-side.


Why do I want this?
-------------------

1. You must follow the OWASP 'Synchronizer Token Pattern' recommendation
   

Why don't I want this?
----------------------

1. Storing tokens in sessions means you have to hit your session store more
   often.



