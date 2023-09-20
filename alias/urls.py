from django.urls import path
from . import views

urlpatterns = [
    path('createAliasForm', views.createAliasForm, name="createAliasForm"),
    path('createAlias', views.createAlias, name="createAlias"),
    path('verifyDigits', views.verifyDigits, name="verifyDigits"),
    path('confirmedDigits', views.confirmedDigits, name="confirmedDigits"),
    path('sendToAlias', views.sendToAlias, name="send"),
    path('transactionDone', views.transactionDone, name="transactionDone"),
    path('sendForm', views.sendForm, name="sendForm"),
    path('interact/<str:the_alias>', views.interact, name="interact"),
    path('stk/<theDigits>/<organization>', views.stk_push, name="stk"),
    path('tokenaccess', views.get_access_token, name="tokenaccess"),
    path('query/<checkoutid>', views.query_stk_status, name="query"),
    #---------------------------------------------
    path('', views.index, name="index"),
    path('inner', views.inner, name="in"),
    path('signup', views.signup, name="signup"),
    path('signin', views.signin, name="signin"),
    path('homePage', views.homePage, name="homePage"),
    path('signout', views.signout, name="signout"),
    path('afterSignup', views.afterSignup, name="afterSignup"),
    path('emailConfirmed', views.emailConfirmed, name="emailConfirmed")
]