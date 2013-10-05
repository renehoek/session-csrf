What is this?
-------------

``django-session-csrf`` is an alternative implementation of Django's CSRF
protection.

On a HTTP GET a CSRF token is generated. This CSRF token is stored in it's own file on the server. This CSRF token
is also send to the browser with a 'Set-Cookie' header.

In the CSRF Token file on the server the session-id, a 'Time to live' and 'usage counter' is stored.
By storing the session-id in the CSRF Token file it is ensured that the CSRF Token is bound to a particular session.
By storing the 'Time to live' value in the CSRF Token file it is ensured that the received CSRF Token from the browser
has not expired.
By storing the 'usage counter' in the CSF Token file it is ensured that the same CSRF Token can only be used a couple
of times.

The csrf token is included in all POST requests. The browser will send the CSRF Cookie along with the POST request.

Why this replacement?
---------------------

The default Django CSRF protection provides adequate protection against CSRF attacks.

However the default Django CSRF protection does not follow the OWASP 'Synchronizer Token Pattern'
recommendation:
https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29_Prevention_Cheat_Sheet

This recommendation states that a CSRF token should be recycled as much as possible.

How does this implementation work?
-----------------------------------
On every GET a fresh CSRF token is generated and stored in it's own file. This CSRF token is als send too the browser
with a 'Set-Cookie' response header.

In the file the session-id, the 'Time to live' value, and the initial usage counter is stored. The file is named after
the CSRF Token value. So, given a CSRF Token value we can lookup the corresponding file.

When a form is posted, a check is done on the server to see if the posted CSRF token from the cookie matches a token
stored in a file. Four checks are performed:

1) Does a corresponding file exists? If not return a CSRF Failure response.

If the file exists then read it's contents. The following three checks are then performed:

2) Does the received CSRF Token belong to the current session? If not return a CSRF Failure response.
3) Is the 'Time to Live' of the CSRF Token expired? If so return a CSRF Failure response.
3) Is the 'usage counter' of the CSRF Token above the threshold? If so return a CSRF Failure response.

At this point the POSTing is genuine.

The 'Time to Live' value of the CSRF Token is decreased to a very low value. The default is the current time plus ten seconds.
The 'usage counter' is increased with one.

In the corresponding reply too the browser a new CSRF Token is issued with a 'Set-Cookie' response header.

Please take notion of this
--------------------------
On every GET a new CSRF Token is send to the browser. If however the response send to the browser is a '404', '500',
'302', '301' no new CSRF Token is generated. Also when the 'Content-Type' is e.g.
'application/javascript', 'text/css', 'image/png', etc. no new CSRF token is generated.

By doing this only a new CSRF Token is generated on a response send to browser for which it is likely to reply with a
POST request by the browser. There is no need anymore for the 'csrf_token' tag which insert a hidden input element
within a form.

A advantage of this is that POST requests not originating from a HTML Form (e.g. a AJAX POST call) are also protected with
this CSRF protection mechanism without falling back to javascript to read a value from a certain hidden input element
and inserting this into the AJAX Call.

After a AJAX call, the reply of the server has a new fresh CSRF Token which will be send along with the
following AJAX call. So with AJAX calls the CSRF Token is also frequently re-newed. Because no javascripting is necessary
to insert the CSRF Token into the AJAX call, the 'http-only' tag can be set on the CSRF Coookie.

By default the CSRF Token has to 'Time to Live' value of 7200 seconds (2 hours). After a CSRF Token has been submitted
the 'Time to Live' is decreased to 10 seconds. So effectively a CSRF Token can only be used once, but by allowing
a small time-window in which the same CSRF Token can be used again we prevent a CSRF Failure response if a user clicks
for example very quickly two or three times on the submit button resulting in the same number of POSTs send to the server.

A max re-use of the same CSRF Token is enforced. By default this is 5 times.

Why store every CSRF Token in it's own file?
--------------------------------------------
In one of the first implementation this module stored the issued CSRF Tokens in the session, but this resulted in
race conditions. When a browser does two or three times a GET request on exact the same time, the server will generate
the same number of CSRF tokens and attempt to store it in the session on the same time. Only one of these new CSRF tokens
will end up in the session. The other two inserts are a 'lost-update'.

This behaviour was monitored with using Django  (1.5.x) file based sessions. With Django file based sessions, each
concurrent update of the session is written in it's own temporary file. Then the temporary file is renamed to the final
session file name. So, only one update will survive, the others are lost.

This could result in a situation in which the browser had a genuine CSRF Token, but that this CSRF Token was lost on the
server. When POSTing data to the server with this CSRF Token, a false CSRF protection failure was raised.

By storing each CSRF Token in it's own file, this concurrent update problem is solved.

Cleaunup process
----------------
A Django command 'clearcsrftokens' is included. This command will remove CSRF Tokens files for which the creation date
is passed the CSRF Token 'Time to Live' value. This command can be setup as cron-job.

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

Settings
--------

In the Django settings.py file you can set the following settings:

CSRF_STRICT_REFERER_CHECKING = ['True|False'] Default: True

In a SSL setup peform a strict referer check.

CSRF_COOKIE_AGE = [seconds] Default: 7200 seconds

The expire date of the cookie.

CSRF_COOKIE_NAME = [cookie_name] Default: csrftoken

The name of the cookie to store the CSRF Token value in the browser.

CSRF_TOKEN_TTL = [seconds]. Default: 7200 seconds.

The Time to Live value of the CSRF Token stored server-side. This should be the same as CSRF_COOKIE_AGE.

CSRF_TOKEN_TTL_AFTER_USE = [seconds]. Default: 10 seconds.

The Time to Live value of the CSRF Token stored server-side after it's inital use.

CSRF_TOKEN_MAX_REUSE = [number of times]. Default: 4

The number of times the same CSRF Token may be used.

CSRF_DONOT_GENERATE_TOKEN_WITH_MIMETYPES = [list of mimetypes]

A python list of mimetypes for which no CSRF Token should be generated, if one of these mimetypes is in the
'Content-Type' header of the response send to the browser. Please see the code for the default list.

CSRF_TOKEN_FILE_PATH = [file-path]

The file path which is the location too store the CSRF Token files.


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

1. Storing tokens in files means you have to hit your file storage system more
   often.



