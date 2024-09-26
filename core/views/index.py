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
    context = {}
    if request.method == 'POST':
        file_upload = request.FILES['file_upload']
        pcap = PcapFileUpload.objects.create(user=request.user, file_upload=file_upload)

        # pcap_file_path = pcap.file_upload.path 
        # cap = pyshark.FileCapture(pcap_file_path)
        
        context['id'] = pcap.id 
        return render(request, 'core/index.html', context, status=200)
    
    context['id'] = PcapFileUpload.objects.order_by('uploaded_at').first().id 
    return render(request, 'core/index.html', context, status=200)


def analyze_pcap_api(request, pk):
    try:
        pcap = PcapFileUpload.objects.get(pk=pk)
    except PcapFileUpload.DoesNotExist():
        return JsonResponse({
            'flag': False,
            'data': [], 
        }, status=404)

    file_path = pcap.file_upload.path 
    # giao thức lớp mạng: IP, ICMP, ARP, IPv6
    # giao thức lớp giao vận: TCP, UDP, SCTP, QUIC 
    # giao thức lớp ứng dụng: HTTP, HTTPS, FTP, DNS, DHCP, SMTP, POP3, IMAP, MQTT 
    # giao thức bảo mật: TLS, SSL, IPSec 
    # giao thức chuyển mạch: Ethernet, MPLS, VLAN

    cap = pyshark.FileCapture(file_path)
    
    protocol_stats = {}

    for packet in cap:
        protocol = packet.highest_layer # top layer của packet 
        if protocol in protocol_stats:
            protocol_stats[protocol] += 1
        else:
            protocol_stats[protocol] = 1
    print("---------------------------------------")
    print("Thống kê các giao thức trong capture: ")
    for protocol, count in protocol_stats.items():
        print(f"{protocol}: {count} packets")
    print("---------------------------------------")

    for packet in cap:
        if 'IP' in packet:
            print(packet)
            break
    print("---------------------------------------")
    for packet in cap:
        if 'TCP' in packet:
            print(packet)
            break 
    print("---------------------------------------")
    for packet in cap:
        if 'UDP' in packet:
            print(packet)
            break 
    print("---------------------------------------")
    for packet in cap:
        if 'HTTP' in packet:
            print(packet)
            break 
    print("---------------------------------------")
    for packet in cap:
        if 'DNS' in packet:
            print(packet)
            break 
    print("---------------------------------------")
    for packet in cap:
        if 'TLS' in packet:
            print(packet)
            break




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


from django.http import FileResponse, Http404, HttpResponse
import os 

def download_report_demo_view(request):
    file_path = os.path.join(os.path.dirname(__file__), 'report.docx')
    print(f"File path: {file_path}")
    if os.path.exists(file_path):
        with open(file_path, 'rb') as file:
            response = HttpResponse(file.read(), content_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document')
            response['Content-Disposition'] = 'attachment; filename="report.docx"'
            return response
    else:
        raise Http404("File not found")


def download_export_demo_view(request):
    file_path = os.path.join(os.path.dirname(__file__), 'export.csv')
    print(f"File path: {file_path}")
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as file:
            response = HttpResponse(file.read(), content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="export.csv"'
            return response
    else:
        raise Http404("File not found") 

