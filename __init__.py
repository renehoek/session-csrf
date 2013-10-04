"""CSRF protection without cookies."""
from django.conf import settings
from django.middleware import csrf as django_csrf
from django.utils import crypto
from django.core import signing
from django.utils.http import same_origin

from django.utils.log import getLogger
logger = getLogger('django.request')

CSRF_STRICT_REFERER_CHECKING = getattr(settings, 'CSRF_STRICT_REFERER_CHECKING', True)
CSRF_COOKIE_AGE = getattr(settings, 'CSRF_COOKIE_AGE', 7200)

class CsrfMiddleware(object):

    # csrf_processing_done prevents checking CSRF more than once. That could
    # happen if the requires_csrf_token decorator is used.
    def _accept(self, request):
        request.csrf_processing_done = True
        return None

    def _reject(self, request, reason):
        return django_csrf._get_failure_view()(request, reason)


    def _is_user_token_in_session_token(self, request, user_token):
        if 'csrf_protection_token' not in request.session:
            return False

        if crypto.constant_time_compare(user_token, request.get_signed_cookie('csrf_protection_token')):
            return True

        return False

    def process_view(self, request, view_func, args, kwargs):
        """Check the CSRF token if this is a POST."""
        if getattr(request, 'csrf_processing_done', False):
            return None

        # Allow @csrf_exempt views.
        if getattr(view_func, 'csrf_exempt', False):
            return None

        # Bail if this is a safe method.
        if request.method in ('GET', 'HEAD', 'OPTIONS', 'TRACE'):
            return self._accept(request)

        # The test client uses this to get around CSRF processing.
        if getattr(request, '_dont_enforce_csrf_checks', False):
            return self._accept(request)

        # This is a POST, so insist on a CSRF cookie

        if CSRF_STRICT_REFERER_CHECKING and request.is_secure():
            referer = request.META.get('HTTP_REFERER')
            if referer is None:
                logger.warning('Forbidden (%s): %s',
                               django_csrf.REASON_NO_REFERER, request.path,
                    extra={
                        'status_code': 403,
                        'request': request,
                    }
                )
                return self._reject(request, django_csrf.REASON_NO_REFERER)

            # Note that request.get_host() includes the port.
            good_referer = 'https://%s/' % request.get_host()
            if not same_origin(referer, good_referer):
                reason = django_csrf.REASON_BAD_REFERER % (referer, good_referer)
                logger.warning('Forbidden (%s): %s', reason, request.path,
                    extra={
                        'status_code': 403,
                        'request': request,
                    }
                )
                return self._reject(request, reason)

        # Try to get the token from the Signed cookie

        user_token = ''

        if request.method == 'POST':
            try:
                user_token = request.get_signed_cookie('csrf_protection_token')
            except (KeyError, signing.BadSignature):
                django_csrf.logger.warning('Forbidden (%s): %s' % (django_csrf.REASON_BAD_TOKEN, request.path), extra=dict(status_code=403, request=request))
                return self._reject(request, django_csrf.REASON_BAD_TOKEN)


        user_token = django_csrf._sanitize_token(user_token)

        # Check that both strings match.
        if not self._is_user_token_in_session_token(request, user_token):
            django_csrf.logger.warning('Forbidden (%s): %s' % (django_csrf.REASON_BAD_TOKEN, request.path), extra=dict(status_code=403, request=request))
            return self._reject(request, django_csrf.REASON_BAD_TOKEN)

        return self._accept(request)

    def process_response(self, request, response):
        token = django_csrf._get_new_csrf_key()
        request.session['csrf_protection_token'] = token
        request.session.modified = True
        response.set_signed_cookie('csrf_protection_token', token, secure=settings.SESSION_COOKIE_SECURE, max_age=CSRF_COOKIE_AGE, httponly=True)
        return response


def context_processor(request):
    import warnings
    warnings.warn("In session_csrf the context_processor is not required anymore. Remove this from your TEMPLATE_CONTEXT_PROCESSORS in settings.py", DeprecationWarning)
    return {}

# Replace Django's middleware with our own.
def monkeypatch():
    import warnings
    warnings.warn("In session_csrf the monkeypath is not required anymore. Remove this call from your main urls.py file", DeprecationWarning)

