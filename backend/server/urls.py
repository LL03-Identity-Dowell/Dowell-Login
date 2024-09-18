from django.urls import path
from server.views import *

urlpatterns = [
    path('server-report/',serverStatus.as_view()),   
]