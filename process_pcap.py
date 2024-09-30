import os 
import sys 
import django 
from django.core.files.base import ContentFile 
import pyshark 
import csv 
import json 
import xml.etree.ElementTree as ET 
from io import StringIO 
from collections import defaultdict
from datetime import datetime, timedelta 


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'packet_server.settings')
django.setup()


ALLOWED_PROTOCOLS = {'IP', 'ICMP', 'ARP', 'IPv6', 'ICMPV6', 'TCP', 'UDP', 'QUIC', 'SCTP',
                     'HTTP', 'HTTPS', 'FTP', 'DNS', 'DHCP', 'SMTP', 'POP3', 'IMAP', 
                     'MQTT', 'TLS', 'SSL', 'IPSec', 'Ethernet', 'MPLS', 'VLAN'}


from core.models.pcap_file import PcapFileUpload 
from django.db import transaction 


def process_pcap(pcap_id):
    with transaction.atomic():
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

        chart_data_json = analyze_pcap_for_chart(file_path, num_intervals=8)
        json_content = ContentFile(chart_data_json)

        json_filename = f"analysis_{instance.id}.json"
        instance.analysis_json_file.save(json_filename, json_content)

        instance.status_completed = True

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


def analyze_pcap_for_chart(file_path, num_intervals=8):
    protocol_stats = defaultdict(lambda: defaultdict(lambda: {'packet_count': 0, 'total_bytes': 0}))
    start_time = None
    end_time = None

    try:
        cap = pyshark.FileCapture(file_path)

        # Lấy thời gian bắt đầu và thời gian kết thúc từ các packet trong file
        for packet in cap:
            packet_time = datetime.fromtimestamp(float(packet.sniff_timestamp))

            if start_time is None:
                start_time = packet_time
            end_time = packet_time

        # Kiểm tra nếu không có gói tin nào trong file
        if start_time is None or end_time is None:
            print("File PCAP không chứa gói tin nào.")
            return None

        # In thời gian bắt đầu và kết thúc
        print(f"Thời gian bắt đầu: {start_time}")
        print(f"Thời gian kết thúc: {end_time}")

        # Tổng thời gian của toàn bộ file PCAP
        total_duration = (end_time - start_time).total_seconds()

        # Tính toán khoảng thời gian cho mỗi interval
        interval_duration = total_duration / num_intervals

        # Quay lại và phân tích chi tiết cho từng packet
        cap.close()
        cap = pyshark.FileCapture(file_path)

        for packet in cap:
            try:
                protocol = packet.highest_layer
                packet_size = int(packet.length)
                packet_time = datetime.fromtimestamp(float(packet.sniff_timestamp))

                # Chỉ xử lý nếu giao thức thuộc danh sách được phép
                if protocol not in ALLOWED_PROTOCOLS:
                    continue

                # Xác định khoảng thời gian hiện tại (time slot) dựa trên số interval
                time_delta = (packet_time - start_time).total_seconds()
                time_slot = int(time_delta // interval_duration)  # Lấy phần nguyên

                # Tăng số lượng packet và tổng số bytes cho giao thức tương ứng tại time_slot
                protocol_stats[time_slot][protocol]['packet_count'] += 1
                protocol_stats[time_slot][protocol]['total_bytes'] += packet_size
            except AttributeError:
                continue

        # Đóng file capture
        cap.close()

    except Exception as e:
        print(f"Error processing file: {e}")
        return None

    # Tạo cấu trúc dữ liệu để dùng cho vẽ biểu đồ
    chart_data = {
        'labels': [f"{round(i*interval_duration, 3)}s" for i in range(num_intervals + 1)],
        'datasets': []
    }

    # Thêm các thống kê vào datasets
    all_protocols = set()
    for time_slot, stats in protocol_stats.items():
        for protocol in stats.keys():
            all_protocols.add(protocol)

    for protocol in all_protocols:
        protocol_data = []
        for i in range(num_intervals + 1):
            if i in protocol_stats and protocol in protocol_stats[i]:
                protocol_data.append(protocol_stats[i][protocol]['total_bytes'] / 1024)  # Dữ liệu tính bằng kB
            else:
                protocol_data.append(0)
        
        chart_data['datasets'].append({
            'label': protocol,
            'data': protocol_data,
            'borderColor': get_color(protocol),
            'backgroundColor': get_background_color(protocol),
            'fill': True,
            'tension': 0.4
        })
    # print(chart_data_json)
    # Chuyển dữ liệu thành JSON để dùng cho vẽ biểu đồ
    return json.dumps(chart_data, indent=4)
    # return chart_data 


def get_color(protocol):
    # Hàm để lấy màu cho từng giao thức
    colors = {
        'IP': 'rgba(0, 123, 255, 1)',
        'ICMP': 'rgba(255, 159, 64, 1)',
        'ARP': 'rgba(75, 192, 192, 1)',
        'IPv6': 'rgba(153, 102, 255, 1)',
        'ICMPV6': 'rgba(128, 0, 0, 1)',
        'TCP': 'rgba(54, 162, 235, 1)',
        'UDP': 'rgba(255, 99, 132, 1)',
        'QUIC': 'rgba(0, 206, 86, 1)',
        'SCTP': 'rgba(150, 150, 0, 1)',
        'HTTP': 'rgba(0, 200, 83, 1)',
        'HTTPS': 'rgba(139, 0, 139, 1)',
        'FTP': 'rgba(0, 255, 255, 1)',
        'DNS': 'rgba(255, 99, 132, 1)',
        'DHCP': 'rgba(255, 165, 0, 1)',
        'SMTP': 'rgba(0, 128, 128, 1)',
        'POP3': 'rgba(255, 20, 147, 1)',
        'IMAP': 'rgba(64, 224, 208, 1)',
        'MQTT': 'rgba(128, 0, 128, 1)',
        'TLS': 'rgba(255, 206, 86, 1)',
        'SSL': 'rgba(255, 215, 0, 1)',
        'IPSec': 'rgba(128, 0, 0, 1)',
        'Ethernet': 'rgba(255, 20, 147, 1)',
        'MPLS': 'rgba(34, 139, 34, 1)',
        'VLAN': 'rgba(106, 90, 205, 1)',
    }
    return colors.get(protocol, 'rgba(0, 0, 0, 1)')


def get_background_color(protocol):
    # Hàm để lấy màu nền cho từng giao thức
    colors = {
        'IP': 'rgba(0, 123, 255, 0.2)',
        'ICMP': 'rgba(255, 159, 64, 0.2)',
        'ARP': 'rgba(75, 192, 192, 0.2)',
        'IPv6': 'rgba(153, 102, 255, 0.2)',
        'ICMPV6': 'rgba(128, 0, 0, 0.2)',
        'TCP': 'rgba(54, 162, 235, 0.2)',
        'UDP': 'rgba(255, 99, 132, 0.2)',
        'QUIC': 'rgba(0, 206, 86, 0.2)',
        'SCTP': 'rgba(150, 150, 0, 0.2)',
        'HTTP': 'rgba(0, 200, 83, 0.2)',
        'HTTPS': 'rgba(139, 0, 139, 0.2)',
        'FTP': 'rgba(0, 255, 255, 0.2)',
        'DNS': 'rgba(255, 99, 132, 0.2)',
        'DHCP': 'rgba(255, 165, 0, 0.2)',
        'SMTP': 'rgba(0, 128, 128, 0.2)',
        'POP3': 'rgba(255, 20, 147, 0.2)',
        'IMAP': 'rgba(64, 224, 208, 0.2)',
        'MQTT': 'rgba(128, 0, 128, 0.2)',
        'TLS': 'rgba(255, 206, 86, 0.2)',
        'SSL': 'rgba(255, 215, 0, 0.2)',
        'IPSec': 'rgba(128, 0, 0, 0.2)',
        'Ethernet': 'rgba(255, 20, 147, 0.2)',
        'MPLS': 'rgba(34, 139, 34, 0.2)',
        'VLAN': 'rgba(106, 90, 205, 0.2)',
    }
    return colors.get(protocol, 'rgba(0, 0, 0, 0.2)')




if __name__ == '__main__':
    print("--------------------Start------------------")
    pcap_id = sys.argv[1]
    process_pcap(pcap_id)
    print("--------------------Finish-----------------")
