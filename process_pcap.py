import os 
import sys 
import django 
from django.core.files.base import ContentFile 
import pyshark 
import csv 
import json 
import xml.etree.ElementTree as ET 
from io import StringIO 


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'packet_server.settings')
django.setup()


from core.models.pcap_file import PcapFileUpload 


def process_pcap(pcap_id):
    instance = PcapFileUpload.objects.get(id=pcap_id)
    file_path = instance.file_upload.path 
    capture = pyshark.FileCapture(file_path, keep_packets=False)

    csv_data = generate_csv(capture)
    instance.csv_file.save(f"csv_{instance.id}.csv", ContentFile(csv_data.getvalue()))

    json_data = generate_json(capture)
    instance.json_file.save(f"json_{instance.id}.json", ContentFile(json.dumps(json_data, indent=4)))

    xml_data = generate_xml(capture)
    instance.xml_file.save(f"xml_{instance.id}.xml", ContentFile(xml_data))

    plain_text_data = generate_plain_text(capture)
    instance.text_file.save(f"text_{instance.id}.txt", ContentFile(plain_text_data))

    ftp_data = generate_fpt_data_objects(capture)
    if ftp_data:
        instance.ftp_data_file.save(f"ftp_{instance.id}.csv", ContentFile(ftp_data.getvalue()))
    else:
        instance.ftp_data_file.save(f"ftp_{instance.id}.txt", ContentFile("Không có data ftp objects"))
    
    http_objects = generate_http_objects(capture)
    if http_objects:
        instance.http_data_file.save(f"http_{instance.id}.csv", ContentFile(http_objects.getvalue()))
    else:
        instance.http_data_file.save(f"http_{instance.id}.txt", ContentFile("Không có data HTTP objects"))
    
    tls_keys_content = generate_tls_keys(capture)
    if tls_keys_content:
        instance.tls_session_key.save(f"tls_{instance.id}.txt", ContentFile(tls_keys_content))
    else:
        instance.tls_session_key.save(f"tls_{instance.id}.txt", ContentFile("Không có TLS Session Key"))

    instance.save()


def generate_csv(capture):
    csv_output = StringIO()
    writer = csv.writer(csv_output)
    writer.writerow(['No.', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])

    for packet in capture:
        try:
            writer.writerow([packet.number, packet.ip.src, packet.ip.dst, packet.highest_layer, packet.length, packet.info])
        except AttributeError:
            continue 
    return csv_output 


def generate_json(capture):
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
    return data  


def generate_xml(capture):
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
    
    # tree = ET.ElementTree(root)
    xml_data = ET.tostring(root, encoding='unicode')
    return xml_data 


def generate_plain_text(capture):
    text_output = ""
    for packet in capture:
        try:
            text_output += f"Packet Number: {packet.number}\n"
            text_output += f"Source: {packet.ip.src}\n"
            text_output += f"Destination: {packet.ip.dst}\n"
            text_output += f"Protocol: {packet.highest_layer}\n"
            text_output += f"Length: {packet.length}\n"
            text_output += f"Info: {packet.info}\n\n"
        except AttributeError:
            continue
    return text_output 


def generate_fpt_data_objects(capture):
    ftp_objects = StringIO()
    writer = csv.writer(ftp_objects)
    writer.writerow(['Packet', 'Hostname', 'Content Type', 'Size', 'Filename'])
    for packet in capture:
        if 'FTP-DATA' in packet:
            try:
                ftp_data = {
                    'packet_number': packet.number,
                    'hostname': packet.ip.dst,
                    'content_type': 'FTP file',
                    'size': f"{len(packet.ftp_data)} bytes" if hasattr(packet, 'ftp_data') else 'Unknown',
                    'filename': packet.ftp_data.split()[-1] if hasattr(packet, 'ftp_data') else 'Unknown'
                }
                writer.writerow([ftp_data['packet_number'], ftp_data['hostname'], ftp_data['content_type'], ftp_data['size'], ftp_data['filename']])
            except AttributeError:
                continue
    if ftp_objects.getvalue() == "":
        return None
    return ftp_objects 


def generate_http_objects(capture):
    http_objects = StringIO()
    writer = csv.writer(http_objects)
    writer.writerow(['No.', 'Source', 'Destination', 'Host', 'Path', 'Method', 'User-Agent'])
    for packet in capture:
        if 'HTTP' in packet:
            try:
                writer.writerow([packet.number, packet.ip.src, packet.ip.dst, packet.http.host, packet.http.request_uri, packet.http.request_method, packet.http.user_agent])
            except AttributeError:
                continue
    if http_objects.getvalue() == "":
        return None
    return http_objects 


def generate_tls_keys(capture):
    tls_keys = ""
    for packet in capture:
        if 'TLS' in packet:
            try:
                if hasattr(packet.tls, 'handshake_session_id'):
                    tls_keys += f"Session ID: {packet.tls.handshake_session_id}\n"
                if hasattr(packet.tls, 'handshake_session_ticket'):
                    tls_keys += f"Session Ticket: {packet.tls.handshake_session_ticket}\n"
            except AttributeError:
                continue
    if tls_keys == "":
        return None
    return tls_keys 



if __name__ == '__main__':
    print("--------------------Start------------------")
    pcap_id = sys.argv[1]
    process_pcap(pcap_id)
    print("--------------------Finish-----------------")
