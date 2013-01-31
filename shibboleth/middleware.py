from datetime import datetime, timedelta, date
from annoying.functions import get_object_or_None
from django.conf import settings
from django.contrib.auth.middleware import RemoteUserMiddleware
from django.contrib import auth
from django.core.exceptions import ImproperlyConfigured
from twig.subscriptions.models import SubscriptionPackage, SubscriptionLength, UserPurchasedPackage
from twig.users.models import UserProfile, AccountType
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

        username = False

        if "AUTH_TYPE" in request.META and request.META["AUTH_TYPE"] == "shibboleth":
            # Try and find something unique to use as an id
            if "persistent-id" in request.META:
                username = request.META['persistent-id']
            elif "HTTP_SHIB_SESSION_ID" in request.META:
                username = request.META["HTTP_SHIB_SESSION_ID"]
            else:
                return  # can't find shib value in META

            if username:
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

                    account_type = AccountType.objects.get(title="Glow user")

                    # Set them up with a profile if one does not exist
                    if not get_object_or_None(UserProfile, user=user):
                        profile = UserProfile.objects.create(
                            user=user,
                            user_type=UserProfile.MULTI_USER,
                            account_type=account_type
                        )

                        profile.set_school_name("Glow Scotland School")

                    # Give them the good shit
                    package = SubscriptionPackage.objects.get(title="All of Twig (GLOW)")
                    sub_length = SubscriptionLength.objects.get(title="Glow single day")

                    start_date = date.today()
                    end_date = date.today() + timedelta(days=1)

                    UserPurchasedPackage.objects.create(
                        user = user,
                        subscription_package = package,
                        subscription_length = sub_length,
                        account_type = account_type,
                        start_date = start_date,
                        end_date = end_date
                    )