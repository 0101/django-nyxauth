from hashlib import md5

from django.conf import settings
from django.contrib.auth.models import User


class NyxAuthBackend(object):

    supports_anonymous_user = False
    supports_object_permissions = False

    def authenticate(self, username='', auth=''):
        auth_string = md5(username + settings.NYX_AUTH_PHRASE).hexdigest()

        if auth_string == auth:
            user, created = User.objects.get_or_create(
                username=username,
                defaults={'is_active': True},
            )
            return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
