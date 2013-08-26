"""CSRF protection without cookies."""
from django.conf import settings
from django.middleware import csrf as django_csrf
from django.utils import crypto
from django.utils.cache import patch_vary_headers
from django.utils.http import same_origin
from django.utils.functional import SimpleLazyObject

import datetime

from django.utils.log import getLogger
logger = getLogger('django.request')

CSRF_STRICT_REFERER_CHECKING = getattr(settings, 'CSRF_STRICT_REFERER_CHECKING', True)
CSRF_REMOVE_USED_TOKENS = getattr(settings, 'CSRF_REMOVE_USED_TOKENS', True)
CSRF_NUMBER_OF_TOKENS_TO_KEEP = getattr(settings, 'CSRF_NUMBER_OF_TOKENS_TO_KEEP', 5)
CSRF_REMOVE_UNUSED_TOKENS_AFTER = getattr(settings, 'CSRF_REMOVE_UNUSED_TOKENS_AFTER', 3600 * 3 )

def add_csrf_token_in_session(request):
    if 'csrf_tokens' not in request.session:
        request.session['csrf_tokens'] = []
    
    token = django_csrf._get_new_csrf_key()
    request.session['csrf_tokens'].append({'token_value': token, 'created': datetime.datetime.now()})
    request.session.modified = True

    return token


# This overrides django.core.context_processors.csrf to dump our csrf_token
# into the template context.
# Using a Lazy Object ensures that a csrf token is generated at the moment the templatetag 'csrf_token' is used in a template.
def context_processor(request):
    return {'csrf_token': SimpleLazyObject(lambda: add_csrf_token_in_session(request))}


class CsrfMiddleware(object):

    # csrf_processing_done prevents checking CSRF more than once. That could
    # happen if the requires_csrf_token decorator is used.
    def _accept(self, request):
        request.csrf_processing_done = True
        return None

    def _reject(self, request, reason):
        return django_csrf._get_failure_view()(request, reason)


    def _is_user_token_in_session_tokens(self, request, user_token):
        if 'csrf_tokens' not in request.session:
            return False

        for token in request.session['csrf_tokens']:
            if crypto.constant_time_compare(user_token, token['token_value']):
                return True
        return False
    
    def _remove_token_from_session(self, request, user_token):
        if 'csrf_tokens' not in request.session:
            return
        
        left_over_tokens = []
        for token in request.session['csrf_tokens']:
            if not crypto.constant_time_compare(user_token, token['token_value']):
                left_over_tokens.append(token)
        
        request.session['csrf_tokens'] = left_over_tokens
        request.session.modified = True
        
    def _remove_old_tokens_from_session(self, request):
        if 'csrf_tokens' not in request.session:
            return
        
        request.session['csrf_tokens'] = request.session['csrf_tokens'][-CSRF_NUMBER_OF_TOKENS_TO_KEEP:]
        
        current_timestamp = datetime.datetime.now()
        left_over_tokens = []
        for token in request.session['csrf_tokens']:
            if (current_timestamp - token['created']).seconds < CSRF_REMOVE_UNUSED_TOKENS_AFTER:
                left_over_tokens.append(token)
        
        request.session['csrf_tokens'] = left_over_tokens
        request.session.modified = True

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

        # Try to get the token from the POST and fall back to looking at the X-CSRFTOKEN header.
        #
        #Remove the used token, except if the user_token is in 'HTTP_X_CSRFTOKEN'. This is probally a ajax call which will be repeated for some time.
        #Ajax clients don't make a typical 'client --> POST --> Server ---> Response Redirect --> Client --> GET --> Server' cycle.
        #So the CSRF Token template tag is never updated in the browsser
        #
        
        self._remove_old_tokens_from_session(request)
        
        user_token = ''
        remove_this_token = True 
        if request.method == 'POST':
            user_token = request.POST.get('csrfmiddlewaretoken', '')
        if user_token == '':
            remove_this_token = False
            user_token = request.META.get('HTTP_X_CSRFTOKEN', '')

        #Keep the token if the view is decorated with @csrf_keep_token
        if getattr(view_func, 'csrf_keep_token', False):
            remove_this_token = False

        user_token = django_csrf._sanitize_token(user_token)
        
        # Check that both strings match.
        if not self._is_user_token_in_session_tokens(request, user_token):
            django_csrf.logger.warning(
                'Forbidden (%s): %s' % (django_csrf.REASON_BAD_TOKEN, request.path),
                extra=dict(status_code=403, request=request))
            return self._reject(request, django_csrf.REASON_BAD_TOKEN)
        
        if CSRF_REMOVE_USED_TOKENS and remove_this_token:
            self._remove_token_from_session(request, user_token)
            
        return self._accept(request)
            
    def process_response(self, request, response):
        return response


# Replace Django's middleware with our own.
def monkeypatch():
    from django.views.decorators import csrf as csrf_dec
    django_csrf.CsrfViewMiddleware = CsrfMiddleware
    csrf_dec.csrf_protect = csrf_dec.decorator_from_middleware(CsrfMiddleware)
