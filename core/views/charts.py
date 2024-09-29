# view xử lý các dữ liệu cho biểu đồ 
from django.shortcuts import render, redirect, HttpResponse
from django.http import JsonResponse  
from django.contrib.auth.decorators import login_required 
from core.models.pcap_file import PcapFileUpload 


@login_required(login_url='/login/')
def main_chart_api(request, pk):
    try:
        pcap = PcapFileUpload.objects.get(pk=pk)
    except PcapFileUpload.DoesNotExist:
        return JsonResponse({
            'message': 'PCAP file not found',
        }, status=404)
    
    analysis_file_path = pcap.analysis_json_file.path 
    print(analysis_file_path)
    return JsonResponse({
        'message': 'oke'
    }, status=200)
