from django.urls import path
from loginapp import views
from django.views.generic.base import TemplateView

urlpatterns = [
    path('', views.login, name="login"),
    path('register/', views.register, name="register"),
    path('logout/', views.logout, name="logout"),
    path('sign-out/', views.before_logout, name="before_logout"),
    path('register/legalpolicy/', views.register_legal_policy,
         name="register_legal_policy"),
    path('legalpolicy1', views.login_legal_policy,
         name="login_legal_policy"),

    path('update_qrobj/', views.update_qrobj, name="update_qrobj"),
    path('qr_creation/', views.qr_creation, name="qr_creation"),

    path('forgot_username', views.forgot_username, name="forgot_username"),
    path('forgot_password/', views.forgot_password, name="forgot_password"),

    path('link_based/', views.linked_based, name="link_based"),
    path('check_status/', views.check_status, name="check_status"),
    path("live_status/", views.live_status, name="live_status"),
    path("live_qr_status/", views.live_qr_status, name="live_qr_status"),
    path("live_public_status/", views.live_public_status,
         name="live_public_status"),
    path("user_details/", views.user_info, name="userdetails"),
    path('linklogin',views.LinkLogin,name="linklogin"),

    path("user_chart/", TemplateView.as_view(template_name="chart.html")),

    path('validate_username/', views.validate_username, name='validate-username'),

     path("removeaccount",views.removeaccount,name="removeaccount"),
     path('add_public/',views.add_public,name="add_public"),
]
