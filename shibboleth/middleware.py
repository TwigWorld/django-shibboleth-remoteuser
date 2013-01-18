from django.conf import settings
from django.contrib.auth.middleware import RemoteUserMiddleware
from django.contrib import auth
from django.core.exceptions import ImproperlyConfigured
import hashlib
import re


class ShibbolethRemoteUserMiddleware(RemoteUserMiddleware):

    def process_request(self, request):
        # AuthenticationMiddleware is required so that request.user exists.
        if not hasattr(request, 'user'):
            raise ImproperlyConfigured(
                "The Django remote user auth middleware requires the"
                " authentication middleware to be installed.  Edit your"
                " MIDDLEWARE_CLASSES setting to insert"
                " 'django.contrib.auth.middleware.AuthenticationMiddleware'"
                " before the RemoteUserMiddleware class.")

        if request.user.is_authenticated():
            return  # Exit early is already authenticated

        if "AUTH_TYPE" in request.META and request.META["AUTH_TYPE"] == "shibboleth":
            username = request.META['persistent-id']

            username_regex = re.compile('[^\w.@+-]|.{31}', re.IGNORECASE)
            if username_regex.match(username):  # invalid username
                username = hashlib.md5(username).hexdigest()[:30]


            # We are seeing this user for the first time in this session, attempt
            # to authenticate the user.
            user = auth.authenticate(remote_user=username)

            if user:
                # User is valid.  Set request.user and persist user in the session
                # by logging the user in.
                request.user = user
                auth.login(request, user)
                user.set_unusable_password()
                user.save()