from collections import namedtuple

import django.test
from django import http
from django.conf.urls.defaults import patterns
from django.contrib.auth.models import User
from django.core.handlers.wsgi import WSGIRequest
from django.db import close_connection
from django.shortcuts import render
from django.template import context

import mock

from session_csrf import CsrfMiddleware


urlpatterns = patterns('', ('^$', lambda r: http.HttpResponse()))


class TestCsrfToken(django.test.TestCase):
    urls = 'session_csrf.tests'

    def setUp(self):
        self.client.handler = ClientHandler()
        User.objects.create_user('jbalogh', 'j@moz.com', 'password')

    def login(self):
        assert self.client.login(username='jbalogh', password='password')

    def test_csrftoken_unauthenticated(self):
        # request.csrf_token is '' for anonymous users.
        response = self.client.get('/', follow=True)
        self.assertEqual(response._request.csrf_token, '')

    def test_csrftoken_authenticated(self):
        # request.csrf_token is a random non-empty string for authed users.
        self.login()
        response = self.client.get('/', follow=True)
        # The CSRF token is a 32-character MD5 string.
        self.assertEqual(len(response._request.csrf_token), 32)

    def test_csrftoken_new_session(self):
        # The csrf_token is added to request.session the first time.
        self.login()
        response = self.client.get('/', follow=True)
        # The CSRF token is a 32-character MD5 string.
        token = response._request.session['csrf_token']
        self.assertEqual(len(token), 32)
        self.assertEqual(token, response._request.csrf_token)

    def test_csrftoken_existing_session(self):
        # The csrf_token in request.session is reused on subsequent requests.
        self.login()
        r1 = self.client.get('/', follow=True)
        token = r1._request.session['csrf_token']

        r2 = self.client.get('/', follow=True)
        self.assertEqual(r1._request.csrf_token, r2._request.csrf_token)
        self.assertEqual(token, r2._request.csrf_token)


class TestCsrfMiddleware(django.test.TestCase):

    def setUp(self):
        self.token = 'a' * 32
        self.rf = django.test.RequestFactory()
        self.mw = CsrfMiddleware()

    def process_view(self, request, view=None):
        return self.mw.process_view(request, view, None, None)

    def test_reject_view(self):
        # Check that the reject view returns a 403.
        response = self.process_view(self.rf.post('/'))
        self.assertEqual(response.status_code, 403)

    def test_csrf_exempt(self):
        # Make sure @csrf_exempt still works.
        view = namedtuple('_', 'csrf_exempt')
        self.assertEqual(self.process_view(self.rf.post('/'), view), None)

    def test_only_check_post(self):
        # CSRF should only get checked on POST requests.
        self.assertEqual(self.process_view(self.rf.get('/')), None)

    def test_csrfmiddlewaretoken(self):
        # The user token should be found in POST['csrfmiddlewaretoken'].
        request = self.rf.post('/', {'csrfmiddlewaretoken': self.token})
        self.assertEqual(self.process_view(request).status_code, 403)

        request.csrf_token = self.token
        self.assertEqual(self.process_view(request), None)

    def test_x_csrftoken(self):
        # The user token can be found in the X-CSRFTOKEN header.
        request = self.rf.post('/', HTTP_X_CSRFTOKEN=self.token)
        self.assertEqual(self.process_view(request).status_code, 403)

        request.csrf_token = self.token
        self.assertEqual(self.process_view(request), None)

    def test_require_request_token_or_user_token(self):
        # Blank request and user tokens raise an error on POST.
        request = self.rf.post('/', HTTP_X_CSRFTOKEN='')
        request.csrf_token = ''
        self.assertEqual(self.process_view(request).status_code, 403)

    def test_token_no_match(self):
        # A 403 is returned when the tokens don't match.
        request = self.rf.post('/', HTTP_X_CSRFTOKEN='woo')
        request.csrf_token = ''
        self.assertEqual(self.process_view(request).status_code, 403)

    def test_csrf_token_context_processor(self):
        # Our CSRF token should be available in the template context.
        request = mock.Mock()
        request.csrf_token = self.token
        request.groups = []
        ctx = {}
        for processor in context.get_standard_processors():
            ctx.update(processor(request))
        self.assertEqual(ctx['csrf_token'], self.token)


class ClientHandler(django.test.client.ClientHandler):
    """
    Handler that stores the real request object on the response.

    Almost all the code comes from the parent class.
    """

    def __call__(self, environ):
        from django.conf import settings
        from django.core import signals

        # Set up middleware if needed. We couldn't do this earlier, because
        # settings weren't available.
        if self._request_middleware is None:
            self.load_middleware()

        signals.request_started.send(sender=self.__class__)
        try:
            request = WSGIRequest(environ)
            # sneaky little hack so that we can easily get round
            # CsrfViewMiddleware.  This makes life easier, and is probably
            # required for backwards compatibility with external tests against
            # admin views.
            request._dont_enforce_csrf_checks = not self.enforce_csrf_checks
            response = self.get_response(request)
        finally:
            signals.request_finished.disconnect(close_connection)
            signals.request_finished.send(sender=self.__class__)
            signals.request_finished.connect(close_connection)

        # Store the request object.
        response._request = request
        return response
