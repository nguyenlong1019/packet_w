from django.shortcuts import render, redirect, HttpResponse 
from django.contrib.auth.decorators import login_required 
from core.models.pcap_file import PcapFileUpload 
import pyshark 
import csv 
import json 
import xml.etree.ElementTree as ET 


@login_required(login_url='/login')
def handle_export_view(request, pk):
    try:
        pcap = PcapFileUpload.objects.get(pk=pk)
    except PcapFileUpload.DoesNotExist:
        print("Pcap File not found")
        return HttpResponse("Pcap File not found", status=404)

    if request.method == 'GET':
        format = request.GET.get('format_export')
        print(format)
        if format == 'csv':
            return return_file_response(pcap.csv_file, 'text/csv', f'csv_{pcap.id}.csv')

        elif format == 'json':
            return return_file_response(pcap.json_file, 'application/json', f'json_{pcap.id}.json')

        elif format == 'xml':
            return return_file_response(pcap.xml_file, 'application/xml', f'xml_{pcap.id}.xml')
        
        elif format == 'plain_text':
            return return_file_response(pcap.text_file, 'text/plain', f'txt_{pcap.id}.txt')

        elif format == 'FTP-DATA object list':
            return return_file_response(pcap.ftp_data_file, 'text/csv', f'ftp_objects.csv')

        elif format == 'HTTP object list':
            return return_file_response(pcap.http_data_file, 'text/csv', f'http_objects.csv')

        elif format == 'TLS Session Key':
            return return_file_response(pcap.tls_session_key, 'text/plain', f'tls_key.txt')

        # elif format == 'SNMP Export':
        #     return pass 

        # elif format == 'Telnet Export':
        #     return pass 

        # elif format == 'SMTP Export':
        #     return pass 

        # elif format == 'SSH Export':
        #     return pass  
            
        else:
            print("Format export error: not support this format file")
            # return 
            return HttpResponse("Format export error: not support this format file", status=400)

    return HttpResponse("Invalid request method", status=405)


def return_file_response(file_field, content_type, filename):
    if not file_field or not file_field.name:
        return HttpResponse("File not found", status=404)

    try:
        file_content = file_field.read()
        response = HttpResponse(file_content, content_type=content_type)
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
    except Exception as e:
        return HttpResponse(f"Error reading file: {e}", status=500)
