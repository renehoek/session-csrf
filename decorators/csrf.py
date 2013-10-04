__author__ = 'renevanhoek'


from django.utils.decorators import available_attrs
from functools import wraps

def csrf_exempt(view_func):
    """
    Marks a view function as being exempt from the CSRF view protection.
    """
    # We could just do view_func.csrf_exempt = True, but decorators
    # are nicer if they don't have side-effects, so we return a new
    # function.
    def wrapped_view(*args, **kwargs):
        return view_func(*args, **kwargs)
    wrapped_view.csrf_exempt = True
    return wraps(view_func, assigned=available_attrs(view_func))(wrapped_view)


def csrf_keep_token(view_func):
    """
    Marks a view function so that the csrf token can be used a unlimited times.
    """
    def wrapped_view(*args, **kwargs):
        return view_func(*args, **kwargs)

    import warnings
    warnings.warn("In session_csrf the csrf_keep_token is not supported anymore. Remove this decorator from your view", DeprecationWarning)

    return wraps(view_func, assigned=available_attrs(view_func))(wrapped_view)