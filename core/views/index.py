from django.shortcuts import render, redirect 
from django.http import HttpResponse, JsonResponse 


def index_view(request):
    return render(request, 'core/index.html', status=200)


def login_view(request):
    return render(request, 'core/login.html', status=200)


def register_view(request):
    return render(request, 'core/register.html', status=200)
