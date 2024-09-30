# view xử lý các dữ liệu cho biểu đồ 
from django.shortcuts import render, redirect, HttpResponse
from django.http import JsonResponse  
from django.contrib.auth.decorators import login_required 
from core.models.pcap_file import PcapFileUpload  
import json 


@login_required(login_url='/login/')
def check_status_api(request, pk):
    try:
        pcap = PcapFileUpload.objects.get(pk=pk)
    except PcapFileUpload.DoesNotExist:
        return JsonResponse({
            'flag': False,
        }, status=404)
    
    return JsonResponse({
        'flag': pcap.status_completed,
    })


@login_required(login_url='/login/')
def main_chart_api(request, pk):
    try:
        pcap = PcapFileUpload.objects.get(pk=pk)
    except PcapFileUpload.DoesNotExist:
        return JsonResponse({
            'message': 'PCAP file not found',
        }, status=404)
    
    analysis_file_path = pcap.analysis_json_file.path 
    # print(analysis_file_path)
    try:
        with open(analysis_file_path, 'r') as json_file:
            analysis_data = json.load(json_file)
    except FileNotFoundError:
        return JsonResponse({
            'message': 'Analysis file not found'
        }, status=404)
    
    labels = analysis_data.get('labels', [])
    datasets = analysis_data.get('datasets', [])

    return JsonResponse({
        'message': 'oke',
        'labels': labels,
        'datasets': datasets,
    }, status=200)
