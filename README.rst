
What is this?
-------------

``django-session-csrf`` is an alternative implementation of Django's CSRF
protection.

In essence it is the same implementation of the built-in Django's CSRF, but with small improvements.

A CSRF token is generated and stored in a cookie. With the '{{csrf_token}}' template tag the csrf token value is stored on the HTML page.
The csrf token is included in all POST requests. The browser will send the CSRF Cookie along with the POST request.

On every POST, the middleware will check if the csrf token value in the POST and in the cookie is the same.


Why this replacement?
---------------------

The default Django CSRF protection provides adequate protection against CSRF attacks.

However the default Django CSRF protection does not follow the OWASP 'Synchronizer Token Pattern'
recommendation:
https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29_Prevention_Cheat_Sheet

This recommendation states that a CSRF token should be recycled as much as possible.

To recyle a CSRF token, call rotate_token_on_a_get before rendering a template. This call will generate a new CSRF token.


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


To use the 'clearcsrftoken' command include 'session_csrf' in the INSTALLED_APPS setting.

Decorators
----------

With the ``csrf_exempt`` decorator. You can use this to exempt a view from the CSRF protection.




