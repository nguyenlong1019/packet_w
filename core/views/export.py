from django.shortcuts import render, redirect, HttpResponse 
from django.contrib.auth.decorators import login_required 
from core.models.pcap_file import PcapFileUpload 
import pyshark 
import csv 
import json 
import xml.etree.ElementTree as ET 
import asyncio 
from asgiref.sync import sync_to_async, async_to_sync 


# Giải pháp fix bug -> xử lý luôn tại view để lưu file tất các các dạng export vào server (media)
# @sync_to_async
@login_required(login_url='/login')
# @async_to_sync
async def handle_export_view(request, pk):
    try:
        pcap = await sync_to_async(PcapFileUpload.objects.get)(pk=pk)
    except PcapFileUpload.DoesNotExist:
        print("Pcap File not found")
        return 

    file_path = pcap.file_upload.path 
    # cap = pyshark.FileCapture(file_path)

    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())

    cap = await sync_to_async(pyshark.FileCapture)(file_path)

    if request.method == 'POST':
        format = request.POST.get('format_export')
        if format == 'csv':
            return await sync_to_async(export_to_csv)(cap) 

        elif format == 'json':
            return await sync_to_async(export_to_json)(cap)

        elif format == 'xml':
            return await sync_to_async(export_to_xml)(cap)
        
        elif format == 'plain_text':
            return await sync_to_async(export_to_plain_text)(cap)

        elif format == 'FTP-DATA object list':
            return await sync_to_async(export_ftp_data_objects)(cap)

        elif format == 'HTTP object list':
            return await sync_to_async(export_http_objects)(cap)

        elif format == 'TLS Session Key':
            return await sync_to_async(export_tls_keys)(cap)

        elif format == 'SNMP Export':
            pass 

        elif format == 'Telnet Export':
            pass 

        elif format == 'SMTP Export':
            pass 

        elif format == 'SSH Export':
            pass  
            
        else:
            print("Format export error: not support this format file")
            return 
            # return HttpResponse("Format export error: not support this format file", status=400)

    # return HttpResponse("Invalid request method", status=405)


def export_to_csv(capture):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="export.csv"'
    writer = csv.writer(response)
    writer.writerow(['No.', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])

    for packet in capture:
        try:
            writer.writerow([packet.number, packet.ip.src, packet.ip.dst, packet.highest_layer, packet.length, packet.info])
        except AttributeError:
            continue 
    
    return response 


def export_to_json(capture):
    data = []

    for packet in capture:
        try:
            packet_data = {
                'number': packet.number,
                'source': packet.ip.src, 
                'destination': packet.ip.dst,
                'protocol': packet.highest_layer, 
                'length': packet.length,
                'info': packet.info,
            }
            data.append(packet_data)
        except AttributeError:
            continue 
    response = HttpResponse(json.dumps(data, indent=4), content_type='application/json')
    response['Content-Disposition'] = 'attachment; filename="export.json"'
    return response 


def export_to_xml(capture):
    root = ET.Element("Packets")

    for packet in capture:
        try:
            packet_element = ET.SubElement(root, "Packet")
            ET.SubElement(packet_element, "Number").text = str(packet.number)
            ET.SubElement(packet_element, "Source").text = packet.ip.src 
            ET.SubElement(packet_element, "Destination").text = packet.ip.dst 
            ET.SubElement(packet_element, "Protocol").text = packet.highest_layer 
            ET.SubElement(packet_element, "Length").text = packet.length 
            ET.SubElement(packet_element, "Info").text = packet.info 
        except AttributeError:
            continue 
    
    tree = ET.ElementTree(root)
    response = HttpResponse(content_type='application/xml')
    response['Content-Disposition'] = 'attachment; filename="export.xml"'
    tree.write(response, encoding='utf-8', xml_declaration=True)
    return response 


def export_to_plain_text(capture):
    response = HttpResponse(content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename="export.txt"'

    for packet in capture:
        try:
            response.write(f"Packet Number: {packet.number}\n")
            response.write(f"Source: {packet.ip.src}\n")
            response.write(f"Destination: {packet.ip.dst}\n")
            response.write(f"Protocol: {packet.highest_layer}\n")
            response.write(f"Length: {packet.length}\n")
            response.write(f"Info: {packet.info}\n\n")
        except AttributeError:
            continue

    return response


def export_ftp_data_objects(capture):
    ftp_objects = []
    for packet in capture:
        if 'FTP-DATA' in packet:
            try:
                ftp_data = {
                    'packet_number': packet.number,
                    'hostname': packet.ip.dst,  # Địa chỉ IP đích
                    'content_type': 'FTP file',  # Loại nội dung
                    'size': f"{len(packet.ftp_data)} bytes" if hasattr(packet, 'ftp_data') else 'Unknown',
                    'filename': packet.ftp_data.split()[-1] if hasattr(packet, 'ftp_data') else 'Unknown'
                }
                ftp_objects.append(ftp_data)
            except AttributeError:
                continue

    if not ftp_objects:
        return HttpResponse("No FTP-DATA objects found in the capture file.", content_type='text/plain')

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="ftp_data_objects.csv"'
    writer = csv.writer(response)
    writer.writerow(['Packet', 'Hostname', 'Content Type', 'Size', 'Filename'])

    for obj in ftp_objects:
        writer.writerow([obj['packet_number'], obj['hostname'], obj['content_type'], obj['size'], obj['filename']])

    return response


def export_http_objects(capture):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="http_objects.csv"'
    writer = csv.writer(response)
    writer.writerow(['No.', 'Source', 'Destination', 'Host', 'Path', 'Method', 'User-Agent'])

    for packet in capture:
        if 'HTTP' in packet:
            try:
                writer.writerow([packet.number, packet.ip.src, packet.ip.dst, packet.http.host, packet.http.request_uri, packet.http.request_method, packet.http.user_agent])
            except AttributeError:
                continue

    return response


def export_tls_keys(capture):
    response = HttpResponse(content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename="tls_keys.txt"'
    
    tls_keys_found = False

    for packet in capture:
        if 'TLS' in packet:
            try:
                if hasattr(packet.tls, 'handshake_session_id'):
                    tls_keys_found = True
                    response.write(f"Session ID: {packet.tls.handshake_session_id}\n")
                if hasattr(packet.tls, 'handshake_session_ticket'):
                    tls_keys_found = True
                    response.write(f"Session Ticket: {packet.tls.handshake_session_ticket}\n")
            except AttributeError:
                continue

    if not tls_keys_found:
        response.write("No TLS session keys found in the capture file.\n")

    return response

