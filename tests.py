__author__ = 'renevanhoek'

from django.test import TestCase, RequestFactory
from session_csrf import CsrfMiddleware, decorators
from session_csrf import MIMETYPES_NO_TOKEN_GENERATION
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
        csrf_mw = CsrfMiddleware()

        request.session = SessionStore(session_key='abc')
        result = csrf_mw.process_view(request, our_text_plain_view, [], {})
        self.assertEqual(request.csrf_processing_done, True)
        self.assertEqual(result, None)

    def test_response_has_csrf_cookie(self):

        request = self.factory.get('/')
        request.session = SessionStore(session_key='abc')
        response = our_text_plain_view(request)

        csrf_mw = CsrfMiddleware()
        csrf_cookie_name = csrf_mw.csrf_cookie_name
        csrf_cookie_age = csrf_mw.csrf_cookie_age

        csrf_mw.process_response(request, response)
        self.assertNotEqual(response.cookies.get(csrf_cookie_name, None), None)

        cookie = response.cookies.get(csrf_cookie_name)
        self.assertTrue(cookie.get('httponly'), msg="Cookie has not http-only flag")
        self.assertEqual(cookie.get('path'), "/", msg="Cookie should have path '/'")

        utc_expire_value = get_utc_timestamp_from_cookie_time(cookie.get('expires'))
        utc_now = datetime.datetime.utcnow()
        diff_in_seconds = (utc_expire_value - utc_now).seconds
        self.assertAlmostEqual(diff_in_seconds, csrf_cookie_age, delta=3)

    def test_response_has_no_csrf_cookie(self):

        request = self.factory.get('/')
        request.session = SessionStore(session_key='abc')
        csrf_mw = CsrfMiddleware()
        csrf_cookie_name = csrf_mw.csrf_cookie_name

        for mime_without_csrf_cookie in MIMETYPES_NO_TOKEN_GENERATION:
            response = HttpResponse(content="Whatever", content_type=mime_without_csrf_cookie)
            csrf_mw.process_response(request, response)
            self.assertEqual(response.cookies.get(csrf_cookie_name, None), None, msg="Cookie found with a response with content_type %s" % (mime_without_csrf_cookie, ))

        for response_code in [301, 302, 404, 500]:
            response = HttpResponse(content="Whatever", content_type="text/html", status=response_code)
            csrf_mw.process_response(request, response)
            self.assertEqual(response.cookies.get(csrf_cookie_name, None), None, msg="Cookie found with a response with status %d" % (response_code, ))

    def test_respect_csrf_exempt_view(self):
        """
        Test that the csrf_exempt view are no subject to CSRF verification
        """
        request = self.factory.post('/')

        csrf_mw = CsrfMiddleware()
        csrf_cookie_name = csrf_mw.csrf_cookie_name

        request.session = SessionStore(session_key='abc')
        result = csrf_mw.process_view(request, our_exempt_view, [], {})
        self.assertFalse(hasattr(request, 'csrf_processing_done'))
        self.assertEqual(result, None)

        response = HttpResponse(content="Whatever", content_type="text/html", status=200)
        csrf_mw.process_response(request, response)
        self.assertNotEqual(response.cookies.get(csrf_cookie_name, None), None, msg="No Cookie found with a csrf_exempt decorated view. Although it is a csrf_exempt view, it should return a cookie.")


    def test_form_post_genuine(self):

        request = self.factory.get('/')
        request.session = SessionStore(session_key='abc')
        response = our_text_plain_view(request)

        csrf_mw = CsrfMiddleware()
        csrf_cookie_name = csrf_mw.csrf_cookie_name
        csrf_mw.process_response(request, response)
        self.assertNotEqual(response.cookies.get(csrf_cookie_name, None), None)

        factory = RequestFactory()
        factory.cookies[csrf_cookie_name] = response.cookies.get(csrf_cookie_name, None).value

        factory.cookies[settings.SESSION_COOKIE_NAME] = 'abc'
        request = factory.post('/', data={'my_name': 'John Doe'})
        request.session = SessionStore(session_key='abc')

        result = csrf_mw.process_view(request, our_text_plain_view, [], {})
        self.assertTrue(hasattr(request, 'csrf_processing_done'))
        self.assertIsNone(result)

    def test_form_post_nonexistent_csrf_token(self):

        request = self.factory.get('/')
        request.session = SessionStore(session_key='abc')
        response = our_text_plain_view(request)

        csrf_mw = CsrfMiddleware()
        csrf_cookie_name = csrf_mw.csrf_cookie_name
        csrf_mw.process_response(request, response)
        self.assertNotEqual(response.cookies.get(csrf_cookie_name, None), None)

        non_existent_tokens = [django_csrf._get_new_csrf_key(), '', '   ', '/tmp/', '/bin/sh/', 'alert(\'hi\')']

        for sign_it in [True, False]:
            for non_existent_token in non_existent_tokens:
                factory = RequestFactory()

                if sign_it:
                    from django.core import signing
                    cookie_value_not_server_side = signing.get_cookie_signer(salt=csrf_cookie_name).sign(non_existent_token)
                else:
                    cookie_value_not_server_side = non_existent_token

                factory.cookies[csrf_cookie_name] = cookie_value_not_server_side

                factory.cookies[settings.SESSION_COOKIE_NAME] = 'abc'
                request = factory.post('/', data={'my_name': 'John Doe'})
                request.session = SessionStore(session_key='abc')

                result = csrf_mw.process_view(request, our_text_plain_view, [], {})
                self.assertTrue(hasattr(request, 'csrf_verification_failed'))
                self.assertIsNotNone(result)

    def test_form_post_switch_session(self):
        request = self.factory.get('/')
        request.session = SessionStore(session_key='abc')
        response = our_text_plain_view(request)

        csrf_mw = CsrfMiddleware()
        csrf_cookie_name = csrf_mw.csrf_cookie_name
        csrf_mw.process_response(request, response)
        self.assertNotEqual(response.cookies.get(csrf_cookie_name, None), None)

        factory = RequestFactory()
        factory.cookies[csrf_cookie_name] = response.cookies.get(csrf_cookie_name, None).value

        factory.cookies[settings.SESSION_COOKIE_NAME] = 'cba'
        request = factory.post('/', data={'my_name': 'John Doe'})
        request.session = SessionStore(session_key='cba')

        result = csrf_mw.process_view(request, our_text_plain_view, [], {})
        self.assertTrue(hasattr(request, 'csrf_verification_failed'))
        self.assertIsNotNone(result)

    def test_form_post_reissue_same_token(self):

        with override_settings(CSRF_TOKEN_TTL_AFTER_USE=2):
            request = self.factory.get('/')
            request.session = SessionStore(session_key='abc')
            response = our_text_plain_view(request)

            csrf_mw = CsrfMiddleware()
            csrf_cookie_name = csrf_mw.csrf_cookie_name

            csrf_mw.process_response(request, response)
            self.assertNotEqual(response.cookies.get(csrf_cookie_name, None), None)

            factory = RequestFactory()
            factory.cookies[csrf_cookie_name] = response.cookies.get(csrf_cookie_name, None).value
            factory.cookies[settings.SESSION_COOKIE_NAME] = 'abc'

            request = factory.post('/', data={'my_name': 'John Doe'})
            request.session = SessionStore(session_key='abc')

            result = csrf_mw.process_view(request, our_text_plain_view, [], {})
            self.assertTrue(hasattr(request, 'csrf_processing_done'))
            self.assertIsNone(result)

            request = factory.post('/', data={'my_name': 'John Doe'})
            request.session = SessionStore(session_key='abc')

            result = csrf_mw.process_view(request, our_text_plain_view, [], {})
            self.assertTrue(hasattr(request, 'csrf_processing_done'))
            self.assertIsNone(result)

            time.sleep(3)

            request = factory.post('/', data={'my_name': 'John Doe'})
            request.session = SessionStore(session_key='abc')

            result = csrf_mw.process_view(request, our_text_plain_view, [], {})
            self.assertTrue(hasattr(request, 'csrf_verification_failed'))
            self.assertIsNotNone(result)

    def test_form_post_reissue_expired_token(self):
        with override_settings(CSRF_COOKIE_AGE=2, CSRF_TOKEN_TTL=2):
            request = self.factory.get('/')
            request.session = SessionStore(session_key='abc')
            response = our_text_plain_view(request)

            csrf_mw = CsrfMiddleware()
            csrf_cookie_name = csrf_mw.csrf_cookie_name

            csrf_mw.process_response(request, response)
            self.assertNotEqual(response.cookies.get(csrf_cookie_name, None), None)

            factory = RequestFactory()
            factory.cookies[csrf_cookie_name] = response.cookies.get(csrf_cookie_name, None).value
            factory.cookies[settings.SESSION_COOKIE_NAME] = 'abc'

            request = factory.post('/', data={'my_name': 'John Doe'})
            request.session = SessionStore(session_key='abc')

            result = csrf_mw.process_view(request, our_text_plain_view, [], {})
            self.assertTrue(hasattr(request, 'csrf_processing_done'))
            self.assertIsNone(result)

            request = factory.post('/', data={'my_name': 'John Doe'})
            request.session = SessionStore(session_key='abc')

            result = csrf_mw.process_view(request, our_text_plain_view, [], {})
            self.assertTrue(hasattr(request, 'csrf_processing_done'))
            self.assertIsNone(result)

            time.sleep(3)

            request = factory.post('/', data={'my_name': 'John Doe'})
            request.session = SessionStore(session_key='abc')

            result = csrf_mw.process_view(request, our_text_plain_view, [], {})
            self.assertTrue(hasattr(request, 'csrf_verification_failed'))
            self.assertIsNotNone(result)

