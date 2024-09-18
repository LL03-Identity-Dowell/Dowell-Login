"""core URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include, re_path
from django.conf.urls import handler404, handler500
from django.conf import settings
from django.conf.urls.static import static
from django.conf.urls.i18n import i18n_patterns
from django.views.generic.base import TemplateView
from server.views import error_404, error_500
from django.views.generic import TemplateView
from loginapp import views as main

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('api.urls')),

    # endpoints needed from old version

    # path('linklogin',main.LinkLogin,name="linklogin"),
    path('linklogin', main.master_login, name="linklogin"),
    path('linkbased', main.linked_based, name="linkbased"),
    path('allow_location', main.allow_location, name="allow_location"),
    path("check_status", main.check_status, name="check_status"),
    path("live_status/", main.live_status, name="live_status"),
    path("add_public", main.add_public, name="add_public"),
    path("userdetails", main.userdetails, name="userdetails"),
    path("mobile_register", main.register, name="mobile_register"),
    path("main_signout", main.logout, name="main_signout"),
    path("removeaccount", main.removeaccount, name="removeaccount"),
    path("legalpolicy1", main.login_legal_policy, name="legalpolicy1"),
    path("legalpolicy", main.register_legal_policy, name="legalpolicy"),

    # main react app
    re_path(r'.*', TemplateView.as_view(template_name='index.html'))
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# urlpatterns + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
urlpatterns += i18n_patterns(
    path('server/', include("server.urls")),
    path('main/', include("loginapp.urls")),
    prefix_default_language=True,
)

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL,
                          document_root=settings.MEDIA_ROOT)


handler404 = error_404
handler500 = error_500
