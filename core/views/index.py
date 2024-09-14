from django.shortcuts import render, redirect 
from django.http import HttpResponse, JsonResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout, authenticate
from core.models.user import CustomUser
from django.contrib import messages


@login_required(login_url="/login/")
def index_view(request):
    return render(request, 'core/index.html', status=200)


def login_view(request):
    if request.user.is_authenticated:
        return redirect('index')

    if request.method == "POST":
        # login email
        email = request.POST['email']
        password = request.POST['password']

        if not CustomUser.objects.filter(email=email).exists():
            # message
            return redirect('login')

        username = CustomUser.objects.get(email=email).username
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('index')
        else:
            # message
            return redirect('login')

    return render(request, 'core/login.html', status=200)


def register_view(request):
    if request.user.is_authenticated:
        return redirect('index')

    if request.method == "POST":
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']

        if CustomUser.objects.filter(username=username).exists():
            # message
            return redirect('register')

        if CustomUser.objects.filter(email=email).exists():
            # message
            return redirect('register')

        user = CustomUser.objects.create_user(username, email, password)
        user.save()
        login(request, user)
        return redirect('index')

    return render(request, 'core/register.html', status=200)


@login_required(login_url="/login/")
def logout_view(request):
    logout(request)
    return redirect('login')
