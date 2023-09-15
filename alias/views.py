import os
import json
from django import forms
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.urls import reverse
from django.db import IntegrityError

from dotenv import load_dotenv
load_dotenv()
from supabase import create_client

url = os.environ.get("supabase_url")
key = os.environ.get("supabase_key")
supabase = create_client(url, key)

# Create your views here.
def index(request):
    return render(request, "alias/index.html")

def inner(request):
    user_email = request.session.get('user_email', None)
    print(user_email)
    return render(request, "alias/in.html")

def signin(request):
    if request.method == "POST":
        # attempt signin
        email = request.POST["email"]
        password = request.POST["password"]
        try:
            user_session = supabase.auth.sign_in_with_password({"email": email, "password": password})
        except Exception as e:
            return render(request, "alias/login.html", {
                "message": "Invalid email and/or passsword"
            })
        print("===============================================")
        #print(user_session.user)
        request.session["user_email"] = user_session.user.email
        print("================================================")
        return HttpResponseRedirect(reverse("in"))        
    else:
        return render(request, "alias/login.html")

def signout(request):
    supabase.auth.sign_out()
    return HttpResponseRedirect(reverse("index"))

def signup(request):
    if request.method == "POST":
        email = request.POST["email"]
        # phone validation with mpesa req

        # confirms passwords match
        password = request.POST["password"]
        confirmation = request.POST["confirmation"]

        if len(password) < 6:
            return render(request, "alias/signup.html", {
                "message": "Passwords must be greater than 6 characters"
            })

        if password != confirmation:
            return render(request, "alias/signup.html", {
                "message": "Passwords don't match"
            })

        # attempt to create the user
        try:
            user = supabase.auth.sign_up({"email": email, "password": password})
        except IntegrityError:
            return render(request, "alias/signup.html", {
                "message": "ensure your credentials are unique and correct"
            })

        return HttpResponseRedirect(reverse("afterSignup"))
    else:
        return render(request, "alias/signup.html")

def afterSignup(request):
    response =  render(request, "alias/afterSignup.html")

    response['Cache-Control'] = 'no-store, max-age=0'
    response['Pragma'] = 'no-chache'

    return response