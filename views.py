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
            request.session[NEXT_KEY] = request.GET['next']

        if request.user.is_authenticated():
            return HttpResponseRedirect(next or '/')

        return HttpResponseRedirect(settings.NYX_AUTH_PLUGIN_URL)

    def authenticate(self, request, phrase=settings.NYX_AUTH_PHRASE):

        if 'user' not in request.GET or 'auth' not in request.GET:
            #TODO: better message
            messages.error(request, _('There was an error during authentication.'))
            return HttpResponseRedirect('/')

        user = authenticate(username=request.GET['user'],
                            auth=request.GET['auth'])

        if not user:
            messages.error(request, _('Authentication failed.'))
            return HttpResponseRedirect('/')

        return self.post_auth(request, user)

    def post_auth(self, request, user):
        login(request, user)
        return HttpResponseRedirect(self.get_next(request))

    def get_next(self, request):
        return request.session.get('next', '/')

    def urls(self):
        return patterns('',
            url(r'^$', self.dispatch, name='dispatch'),
            url(r'^authenticate/$', self.authenticate, name='authenticate'),
        )
