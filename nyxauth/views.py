from django.conf import settings
from django.conf.urls.defaults import patterns, url
from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect
from django.utils.translation import ugettext_lazy as _


NEXT_KEY = getattr(settings, 'NYX_AUTH_SESSION_NEXT_KEY', 'nyx-auth-next')


class NyxAuth(object):

    def dispatch(self, request):
        next = request.GET.get('next')
        if next:
            request.session[NEXT_KEY] = next

        if request.user.is_authenticated():
            return HttpResponseRedirect(next or '/')

        return HttpResponseRedirect(settings.NYX_AUTH_PLUGIN_URL)

    def authenticate(self, request):
        if 'user' not in request.GET or 'auth' not in request.GET:
            messages.error(request, _('An error occured during authentication.'))
            return HttpResponseRedirect('/')

        user = authenticate(username=request.GET['user'],
                            auth=request.GET['auth'])

        if not user:
            messages.error(request, _('Authentication failed.'))
            return HttpResponseRedirect('/')

        return self.post_auth(request, user)

    def post_auth(self, request, user):
        next = self.get_next(request)
        login(request, user)
        return HttpResponseRedirect(next)

    def get_next(self, request):
        return request.session.get(NEXT_KEY, '/')

    def urls(self):
        return patterns('',
            url(r'^$', self.dispatch, name='dispatch'),
            url(r'^authenticate/$', self.authenticate, name='authenticate'),
        )
