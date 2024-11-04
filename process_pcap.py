import os 
import sys 
import django 
import django.core.files.base import ContentFile 
import pyshark 
import csv 
import json 
import xml.etree.ElementTree as ET 
from io import StringIO, BytesIO 
from collections import defaultdict 
from datetime import datetime, timedelta 
from docx import Document 
from docx.shared import Pt 
from docx.oxml.ns import qn 
from docx.enum.text import WD_PARAGRAPH_ALIGNMENT 
from docx.shared import Inches 
import pyshark 
import socket 
import dns.resolver 


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'packet_server.settings')
django.setup()


ALLOWED_PROTOCOLS = {
    'IP', 'ICMP', 'ARP', 'IPv6', 'ICMPV6', 'TCP', 'UDP', 'QUIC', 'SCTP',
    'HTTP', 'HTTPS', 'FTP', 'DNS', 'DHCP', 'SMTP', 'POP3', 'IMAP',
    'MQTT', 'TLS', 'SSL', 'IPSec', 'Ethernet', 'MPLS', 'VLAN'
}


from core.models.pcap_file import PcapFileUpload 
from django.db import transaction 


def process_pcap(pcap_id):
    with transaction.atomic():
        instance = PcapFileUpload.objects.get(id=pcap_id)
        file_path = instance.file_upload.path 
        capture = pyshark.FileCapture(file_path, keep_packets=False)

        csv_output = StringIO()
        json_data = []
        xml_root = ET.Element("Packets")
        text_output = ""
        
        ftp_objects = StringIO()
        ftp_writer = csv.writer(ftp_objects)
        ftp_writer.writerow(['Packet', 'Hostname', 'Content Type', 'Size', 'Filename'])
        
        http_objects = StringIO()
        http_writer = csv.writer(http_objects)
        http_writer.writerow(['No', 'Source', 'Destination', 'Host', 'Path', 'Method', 'User-Agent'])

        tls_keys = ""
        protocol_stats = defaultdict(lambda: {'count': 0, 'size': 0})
        tcp_packets = []
        udp_packets = []

        csv_writer = csv.writer(csv_output)
        csv_writer.writerow(['No', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])

        for packet in capture:
            try:
                # common data processing 
                packet_data = {
                    'number': packet.number,
                    'source': packet.ip.src if hasattr(packet, 'ip') else 'N/A',
                    'destination': packet.ip.dst if hasattr(packet, 'ip') else 'N/A',
                    'protocol': packet.highest_layer,
                    'length': packet.length,
                    'info': packet.info if hasattr(packet, 'info') else 'N/A',
                }

                protocol = packet_data['protocol']
                packet_size = int(packet_data['length'])

                # CSV and JSON generation 
                csv_writer.writerow([packet_data['number'], packet_data['source'], packet_data['destination'], protocol, packet_data['length'], packet_data['info']])
                
                # XML generation 
                packet_element = ET.SubElement(xml_root, "Packet")
                for key, value in packet_data.items():
                    ET.SubElement(packet_element, key.capitalize()).text = str(value)

                # Plain text generation 
                text_output += f"Packet Number: {packet_data['number']}\nSource: {packet_data['source']}\nDestination: {packet_data['destination']}\nProtocol: {protocol}\nLength: {packet_data['length']}\nInfo: {packet_data['info']}\n\n"

                # Protocol stats calculation 
                protocol_stats[protocol]['count'] += 1
                protocol_stats[protocol]['size'] += packet_size 

                # TCP and UDP packet processing 
                if protocol == 'TCP':
                    tcp_packets.append(packet)
                elif protocol == 'UDP':
                    udp_packets.append(packet)

                # FTP and HTTP object generation 
                if 'FTP-DATA' in packet:
                    ftp_writer.writerow([])



            except:
                pass

