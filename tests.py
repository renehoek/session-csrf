__author__ = 'renevanhoek'

from django.test import TestCase, RequestFactory
from session_csrf import CsrfViewMiddleware, decorators
from session_csrf.decorators.csrf import csrf_exempt
from django.conf import settings
from django.http import HttpResponse
from django.contrib.sessions.backends.file import SessionStore
import datetime
import time

from django.middleware import csrf as django_csrf
from django.test.utils import override_settings

def get_utc_timestamp_from_cookie_time(cookie_value):
    import email
    tm_utc = email.utils.mktime_tz(email.utils.parsedate_tz(cookie_value))
    return datetime.datetime.utcfromtimestamp(tm_utc)

def our_text_plain_view(request):
    return HttpResponse("Text only, please.", content_type="text/plain")

@csrf_exempt
def our_exempt_view(request):
    return HttpResponse("Text only, please.", content_type="text/plain")

class SessionCSRFTests(TestCase):

    def setUp(self):
        # Every test needs access to the request factory.
        self.factory = RequestFactory()

    def test_request_has_processing_done_attribute(self):
        """
        Test that the request has a 'csrf processing done' attribute.
        """
        request = self.factory.get('/')
        csrf_mw = CsrfViewMiddleware()

        request.session = SessionStore(session_key='abc')
        result = csrf_mw.process_view(request, our_text_plain_view, [], {})
        self.assertEqual(request.csrf_processing_done, True)
        self.assertEqual(result, None)

    def test_response_has_csrf_cookie(self):
        pass
       #TODO

    def test_response_has_no_csrf_cookie(self):
        pass
       #TODO

    def test_respect_csrf_exempt_view(self):
        """
        Test that the csrf_exempt view are no subject to CSRF verification
        """
        pass
        #TODO


    def test_form_post_genuine(self):
        pass
        #TODO

    def test_form_post_nonexistent_csrf_token(self):
        pass
        #TODO

    def test_form_post_switch_session(self):
        pass
        #TODO

    def test_form_post_reissue_same_token(self):
        pass
       #TODO

    def test_form_post_reissue_expired_token(self):
        pass
        #TODO

    def test_form_post_strict_referer_check(self):
        pass
        #TODO

    def test_configuration_settings(self):
        pass
        #TODO

    def test_request_without_accessed_session(self):
        pass
        #TODO




