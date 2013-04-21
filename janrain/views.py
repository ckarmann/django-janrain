from django.http import HttpResponse, HttpResponseRedirect
from django.core.urlresolvers import reverse
from django.contrib import auth
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render_to_response
from django.template import RequestContext

from janrain import api
from janrain.models import JanrainUser
from janrain.signals import *

from django.utils import simplejson


def returnError(message) :
    data = { "status" : "e", "error" : message}
    return HttpResponse(simplejson.dumps(data), content_type="application/json")


@csrf_exempt
def login(request):
    pre_login.send(JanrainSignal, request=request)

    # get Janrain token    
    try:
        token = request.POST['token']
    except KeyError:
        # TODO: set ERROR to something
        login_failure.send(JanrainSignal, message='Error retreiving token', data=None)
        return returnError('Error retreiving token')

    # retrieve profile
    try:
        profile = api.auth_info(token)
    except api.JanrainAuthenticationError:
        login_failure.send(JanrainSignal, message='Error retreiving profile', data=None)
        return returnError('Error retreiving profile')
    post_profile_data.send(JanrainSignal, profile_data=profile)

    # authenticate
    u = None
    p = profile['profile']
    u = auth.authenticate(profile=p)
    post_authenticate.send(JanrainSignal, user=u, profile_data=profile)

    # get or create Janrain user in DB
    juser = JanrainUser.objects.get_or_create(
                user=u,
                username=p.get('preferredUsername'),
                provider=p.get('providerName').lower(),
                identifier=p.get('identifier'),
                avatar=p.get('photo'),
                url=p.get('url'),
            )[0]
    juser.save()
    post_janrain_user.send(JanrainSignal, janrain_user=juser, profile_data=profile)

    # login in django
    if u is not None:
        request.user = u
        auth.login(request, u)
        post_login.send(JanrainSignal, user=u, profile_data=profile)

    # answer
    data = { "status" : "m", "message" : "good." }
    return HttpResponse(simplejson.dumps(data), content_type="application/json")

def logout(request):
    pre_logout.send(JanrainSignal, request=request)

    # logout from django
    auth.logout(request)
    # try:
    #     redirect = pre_redirect.send(JanrainSignal, type='logout', 
    #             redirect=request.GET.get('next', request.META["HTTP_REFERER"]))[-1][1]
    # except IndexError:
    #     redirect = '/'
    redirect = request.META["HTTP_REFERER"]
    return HttpResponseRedirect(redirect)

def loginpage(request):
    context = {'next':request.GET['next']}
    return render_to_response(
        'janrain/loginpage.html',
        context,
        context_instance=RequestContext(request)
    )
    
