from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name="index"),
    path('inner', views.inner, name="in"),
    path('signup', views.signup, name="signup"),
    path('signin', views.signin, name="signin"),
    path('homePage', views.homePage, name="homePage"),
    path('signout', views.signout, name="signout"),
    path('afterSignup', views.afterSignup, name="afterSignup")
]