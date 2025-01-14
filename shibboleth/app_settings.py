
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

#At a minimum you will need username, 
default_shib_attributes = {
  "Shibboleth-eppn": (True, "username"),
} 

SHIB_ATTRIBUTE_MAP = getattr(settings, 'SHIBBOLETH_ATTRIBUTE_MAP', default_shib_attributes)
#Set to true if you are testing and want to insert sample headers.
SHIB_MOCK_HEADERS = getattr(settings, 'SHIBBOLETH_MOCK_HEADERS', False)

LOGIN_URL = getattr(settings, 'LOGIN_URL', None)

if not LOGIN_URL:
    raise ImproperlyConfigured("A LOGIN_URL is required.  Specify in settings.py")


