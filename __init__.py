"""CSRF protection with every time a fresh csrf protection token."""
from django.conf import settings
from django.middleware import csrf as django_csrf
from django.utils import crypto
from django.core import signing
from django.utils.encoding import force_text
from django.core.exceptions import SuspiciousOperation, ImproperlyConfigured
from django.utils.http import same_origin
import datetime
import tempfile
import os.path
import os
import re
import time


from django.utils.log import getLogger
logger = getLogger('django.request')

CSRF_STRICT_REFERER_CHECKING = getattr(settings, 'CSRF_STRICT_REFERER_CHECKING', True)
CSRF_COOKIE_AGE = int(getattr(settings, 'CSRF_COOKIE_AGE', 7200) )
CSRF_COOKIE_NAME = getattr(settings, 'CSRF_COOKIE_NAME', 'csrftoken')
CSRF_TOKEN_TTL = float(getattr(settings, 'CSRF_TOKEN_TTL', 7200 ) )
CSRF_TOKEN_TTL_AFTER_USE = float(getattr(settings, 'CSRF_TOKEN_TTL_AFTER_USE', 10 ) )
CSRF_TOKEN_MAX_REUSE = getattr(settings, 'CSRF_TOKEN_MAX_REUSE', 4)
CSRF_DONOT_GENERATE_TOKEN_WITH_MIMETYPES = getattr(settings, 'CSRF_DONOT_GENERATE_TOKEN_WITH_MIMETYPES',
    ['text/css', 'image/jpeg', 'image/png', 'image/gif', 'image/x-ms-bmp', 'image/tiff', 'application/javascript',
     'application/pdf', 'application/msword', 'application/vnd.ms-excel', 'application/vnd.ms-powerpoint',
     'application/x-shockwave-flash', ])

CSRF_TOKEN_FILE_PATH = getattr(settings, 'CSRF_TOKEN_FILE_PATH', '')
if CSRF_TOKEN_FILE_PATH == '':
    CSRF_TOKEN_FILE_PATH = os.path.join(getattr(settings, 'SESSION_FILE_PATH', '/tmp/'), 'csrf_tokens')

class CsrfMiddleware(object):

    def __init__(self,):
        self.file_prefix = CSRF_COOKIE_NAME
        self.storage_path = type(self)._get_storage_path()
        super(CsrfMiddleware, self).__init__()

    # csrf_processing_done prevents checking CSRF more than once. That could
    # happen if the requires_csrf_token decorator is used.
    def _accept(self, request):
        request.csrf_processing_done = True
        return None

    def _reject(self, request, reason):
        request.csrf_verification_failed = True
        return django_csrf._get_failure_view()(request, reason)

    @classmethod
    def _get_storage_path(cls):
        try:
            return cls._storage_path
        except AttributeError:
            storage_path = CSRF_TOKEN_FILE_PATH

            # Make sure the storage path is valid.
            if not os.path.isdir(storage_path):
                try:
                    os.makedirs(storage_path)
                except OSError:
                    raise EnvironmentError("CSRF Token directory '%s' does not exist and could not be created'" % storage_path)

            cls._storage_path = storage_path
            return storage_path


    def __csrf_token_filename(self, token):

        result = re.match('[a-zA-Z0-9]+', force_text(token))
        if result is None:
            raise SuspiciousOperation("Invalid characters in csrf token")

        directory_prefix = token[:2].lower()
        folder = os.path.join(self.storage_path, directory_prefix)
        try:
            if not os.path.exists( folder ):
                os.makedirs(folder)
        except (IOError, OSError):
            raise EnvironmentError("CSRF Token directory '%s' does not exist and could not be created'" % folder)

        return os.path.join(folder, self.file_prefix + token)


    def __load(self, token):
        try:
            with open(self.__csrf_token_filename(token), "rb") as csrf_token_file:
                file_data = csrf_token_file.read()

            # Don't fail if there is no data in the csrf token file.
            # We may have opened the empty placeholder file.
            if file_data:
                the_lines = file_data.split("\n")
            else:
                the_lines = ['', '', '0']
        except IOError:
            the_lines = ['', '', '0']

        return the_lines

    def __save_token_in_file(self, token, session_key, ttl, use_counter ):

        csrf_token_file_name = self.__csrf_token_filename(token)

        # Make sure the file exists.  If it does not already exist, an
        # empty placeholder file is created.

        flags = os.O_WRONLY | os.O_CREAT | getattr(os, 'O_BINARY', 0)

        fd = os.open(csrf_token_file_name, flags)
        os.close(fd)

        # Write the csrf token file without interfering with other threads
        # or processes.  By writing to an atomically generated temporary
        # file and then using the atomic os.rename() to make the complete
        # file visible, we avoid having to lock the csrf token file, while
        # still maintaining its integrity.

        folder, prefix = os.path.split(csrf_token_file_name)

        try:
            output_file_fd, output_file_name = tempfile.mkstemp(dir=folder, prefix=prefix + '_out_')
            renamed = False
            try:
                try:
                    os.write(output_file_fd, "%s\n%f\n%d" % (session_key, ttl, use_counter))
                finally:
                    os.close(output_file_fd)
                os.rename(output_file_name, csrf_token_file_name)
                renamed = True
            finally:
                if not renamed:
                    os.unlink(output_file_name)

        except (OSError, IOError, EOFError):
            pass


    def _add_csrf_token_in_session(self, request):

        token = django_csrf._get_new_csrf_key()

        self.__save_token_in_file(token, request.session.session_key, time.time() + CSRF_TOKEN_TTL, 0)

        return token

    def _decrease_ttl_on_token(self, request, received_token):

        if not os.path.exists(self.__csrf_token_filename(received_token)):
            return

        the_lines = self.__load(received_token)
        use_counter = int(the_lines[2])
        use_counter += 1

        self.__save_token_in_file(received_token, request.session.session_key, time.time() + CSRF_TOKEN_TTL_AFTER_USE, use_counter)


    def _is_received_token_in_session(self, request, received_token):

        if not os.path.exists(self.__csrf_token_filename(received_token)):
            return False

        the_lines = self.__load(received_token)

        if the_lines[0] == request.session.session_key and float(the_lines[1]) > time.time() and \
                        int(the_lines[2]) <=  CSRF_TOKEN_MAX_REUSE:
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

        received_token = ''

        if request.method == 'POST':
            try:
                received_token = request.get_signed_cookie(CSRF_COOKIE_NAME)
                #received_token = request.COOKIES.get(CSRF_COOKIE_NAME)
            except (KeyError, signing.BadSignature):
                django_csrf.logger.warning('Forbidden (%s): %s' % (django_csrf.REASON_BAD_TOKEN, request.path), extra=dict(status_code=403, request=request))
                return self._reject(request, django_csrf.REASON_BAD_TOKEN)

        received_token = django_csrf._sanitize_token(received_token)

        # Check that both strings match.
        if not self._is_received_token_in_session(request, received_token):
            django_csrf.logger.warning('Forbidden (%s): %s' % (django_csrf.REASON_BAD_TOKEN, request.path), extra=dict(status_code=403, request=request))
            return self._reject(request, django_csrf.REASON_BAD_TOKEN)

        self._decrease_ttl_on_token(request, received_token)

        return self._accept(request)

    def process_response(self, request, response):
        if not hasattr(request, 'session'):
            return response

        if hasattr(request, 'csrf_verification_failed') and request.csrf_verification_failed == True:
            return response

        if response.status_code in [301, 302, 404, 500]:
            return response

        content_type = response.get('content-type')
        if content_type is not None:
            mimetype = content_type.split(';')[0]
            if mimetype in CSRF_DONOT_GENERATE_TOKEN_WITH_MIMETYPES:
                return response

        token = self._add_csrf_token_in_session(request)

        #response.set_cookie(CSRF_COOKIE_NAME, token)
        response.set_signed_cookie(CSRF_COOKIE_NAME, token, secure=settings.SESSION_COOKIE_SECURE, max_age=CSRF_COOKIE_AGE, httponly=True)
        return response


def context_processor(request):
    import warnings
    warnings.warn("In session_csrf the context_processor is not required anymore. Remove this from your TEMPLATE_CONTEXT_PROCESSORS in settings.py", DeprecationWarning)
    return {}

# Replace Django's middleware with our own.
def monkeypatch():
    import warnings
    warnings.warn("In session_csrf the monkeypath is not required anymore. Remove this call from your main urls.py file", DeprecationWarning)

