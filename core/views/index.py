from django.shortcuts import render, redirect 
from django.http import HttpResponse, JsonResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout, authenticate 
from django.contrib.auth.models import User
from core.models.profile import Profile
from django.contrib import messages 
from core.forms.pcap_form import UploadFileForm 
from core.models.pcap_file import PcapFileUpload
import pyshark 


@login_required(login_url="/login/")
def index_view(request):
    if request.method == 'POST':
        file_upload = request.FILES['file_upload']
        pcap = PcapFileUpload.objects.create(user=request.user, file_upload=file_upload)

        pcap_file_path = pcap.file_upload.path 
        cap = pyshark.FileCapture(pcap_file_path)

        for pkt in cap:
            print(f"Packet {pkt.number}:")
            # print(f"    Timestamp: {pkt.sniff_time}")
            # print(f"    Source IP: {pkt.ip.src}")
            # print(f"    Destination IP: {pkt.ip.dst}")
            # print(f"    Protocol: {pkt.highest_layer}")
            # print(f"    Length: {pkt.length}\n")


        return render(request, 'core/index.html', status=200)
        # return redirect('results')
    return render(request, 'core/index.html', status=200)


def analyze_pcap(file_path):
    cap = pyshark.FileCapture(file_path)
    protocol_stats = {}

    for pkt in cap:
        protocol = pkt.highest_layer 
        protocol_stats[protocol] = protocol_stats.get(protocol, 0) + 1 
    
    cap.close()
    return protocol_stats 


def results(request):
    uploaded_file = PcapFileUpload.objects.last()
    file_path = uploaded_file.file.path
    protocol_stats = analyze_pcap(file_path)
    
    context = {
        'protocol_stats': protocol_stats,
        'file_name': uploaded_file.file.name
    }
    return render(request, 'analysis/results.html', context)


def login_view(request):
    if request.user.is_authenticated:
        return redirect('index')

    if request.method == "POST":
        # login email
        email = request.POST['email']
        password = request.POST['password']

        if not User.objects.filter(email=email).exists():
            # message
            messages.error(request, 'Email không tồn tại!')
            return redirect('login')

        username = User.objects.get(email=email).username 
        is_access = User.objects.get(email=email).profile.is_access 
        is_superuser = User.objects.get(email=email).is_superuser 
        user = authenticate(username=username, password=password)
        if user is not None:
            if is_superuser:
                login(request, user)
                return redirect('index')

            if is_access:
                login(request, user)
                return redirect('index')
            else:
                # message: not access 
                messages.error(request, 'Tài khoản chưa có quyền truy cập!')
                return redirect('login')
        else:
            # message
            messages.error(request, 'Mật khẩu không đúng!')
            return redirect('login')

    return render(request, 'core/login.html', status=200)


def register_view(request):
    if request.user.is_authenticated:
        return redirect('index')

    if request.method == "POST":
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']

        if User.objects.filter(username=username).exists():
            # message
            messages.error(request, 'Tên tài khoản đăng ký đã tồn tại!')
            return redirect('register')

        if User.objects.filter(email=email).exists():
            # message
            messages.error(request, 'Email đăng ký đã tồn tại!')
            return redirect('register')

        user = User.objects.create_user(username, email, password)

        profile = Profile.objects.create(
            user=user
        )

        if user.profile.is_access:
            login(request, user)
            return redirect('index') 
        else:
            return render(request, 'core/wait.html', status=200)

    return render(request, 'core/register.html', status=200)


@login_required(login_url="/login/")
def logout_view(request):
    logout(request)
    return redirect('login')
