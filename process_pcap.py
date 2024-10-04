import os 
import sys 
import django 
from django.core.files.base import ContentFile 
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
from collections import defaultdict 


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

        protocol_stats, total_packets, total_size, tcp_packets, udp_packets = analyze_pcap(capture)
        generate_report(protocol_stats, total_packets, total_size, tcp_packets, udp_packets, instance)

        chart_data_json = analyze_pcap_for_chart(capture, num_intervals=8)
        json_content = ContentFile(chart_data_json)

        json_filename = f"analysis_{instance.id}.json"
        instance.analysis_json_file.save(json_filename, json_content)

        instance.status_completed = True 

        print(f"------------------DONE {pcap_id}----------------------")

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


# Function to check protocol and extract information
def get_protocol_info(packet):
    protocol = 'N/A'
    info = 'N/A'
    src = 'N/A'
    dst = 'N/A'
    
    try:
        # Layer 2: Ethernet, MPLS, VLAN
        if hasattr(packet, 'eth') and 'Ethernet' in ALLOWED_PROTOCOLS:
            src = packet.eth.src
            dst = packet.eth.dst
            protocol = 'Ethernet'

        if hasattr(packet, 'mpls') and 'MPLS' in ALLOWED_PROTOCOLS:
            protocol = 'MPLS'
            info = 'MPLS Label: {}'.format(packet.mpls.label)

        if hasattr(packet, 'vlan') and 'VLAN' in ALLOWED_PROTOCOLS:
            protocol = 'VLAN'
            info = 'VLAN ID: {}'.format(packet.vlan.id)

        # Layer 3: IP, ARP, IPv6
        if hasattr(packet, 'ip') and 'IP' in ALLOWED_PROTOCOLS:
            src = packet.ip.src
            dst = packet.ip.dst
            protocol = 'IP'

        if hasattr(packet, 'arp') and 'ARP' in ALLOWED_PROTOCOLS:
            src = packet.arp.src_proto_ipv4
            dst = packet.arp.dst_proto_ipv4
            protocol = 'ARP'
            info = '{} request'.format(packet.arp.opcode)

        if hasattr(packet, 'ipv6') and 'IPv6' in ALLOWED_PROTOCOLS:
            src = packet.ipv6.src
            dst = packet.ipv6.dst
            protocol = 'IPv6'

        # Layer 3: ICMP, ICMPv6
        if hasattr(packet, 'icmp') and 'ICMP' in ALLOWED_PROTOCOLS:
            protocol = 'ICMP'
            info = 'Type: {}, Code: {}'.format(packet.icmp.type, packet.icmp.code)

        if hasattr(packet, 'icmpv6') and 'ICMPV6' in ALLOWED_PROTOCOLS:
            protocol = 'ICMPV6'
            info = 'Type: {}, Code: {}'.format(packet.icmpv6.type, packet.icmpv6.code)

        # Layer 4: TCP, UDP, SCTP, QUIC
        if hasattr(packet, 'tcp') and 'TCP' in ALLOWED_PROTOCOLS:
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport
            protocol = 'TCP'
            info = 'Src Port: {}, Dst Port: {}'.format(src_port, dst_port)

        if hasattr(packet, 'udp') and 'UDP' in ALLOWED_PROTOCOLS:
            src_port = packet.udp.srcport
            dst_port = packet.udp.dstport
            protocol = 'UDP'
            info = 'Src Port: {}, Dst Port: {}'.format(src_port, dst_port)

        if hasattr(packet, 'sctp') and 'SCTP' in ALLOWED_PROTOCOLS:
            protocol = 'SCTP'
            info = 'SCTP Stream: {}'.format(packet.sctp.stream)

        if hasattr(packet, 'quic') and 'QUIC' in ALLOWED_PROTOCOLS:
            protocol = 'QUIC'
            info = 'QUIC Stream: {}'.format(packet.quic.stream_id)

        # Application Layer Protocols: HTTP, HTTPS, DNS, DHCP, etc.
        if hasattr(packet, 'http') and 'HTTP' in ALLOWED_PROTOCOLS:
            protocol = 'HTTP'
            info = packet.http.host if hasattr(packet.http, 'host') else 'N/A'

        if hasattr(packet, 'ssl') and 'SSL' in ALLOWED_PROTOCOLS:
            protocol = 'SSL/TLS'
            info = 'SSL Record Version: {}'.format(packet.ssl.record_version) if hasattr(packet.ssl, 'record_version') else 'N/A'

        if hasattr(packet, 'dns') and 'DNS' in ALLOWED_PROTOCOLS:
            protocol = 'DNS'
            info = 'Query Name: {}'.format(packet.dns.qry_name) if hasattr(packet.dns, 'qry_name') else 'N/A'

        if hasattr(packet, 'dhcp') and 'DHCP' in ALLOWED_PROTOCOLS:
            protocol = 'DHCP'
            info = 'Client IP: {}'.format(packet.dhcp.client_ip_addr) if hasattr(packet.dhcp, 'client_ip_addr') else 'N/A'

        if hasattr(packet, 'ftp') and 'FTP' in ALLOWED_PROTOCOLS:
            protocol = 'FTP'
            info = 'Command: {}'.format(packet.ftp.request_command) if hasattr(packet.ftp, 'request_command') else 'N/A'

        if hasattr(packet, 'smtp') and 'SMTP' in ALLOWED_PROTOCOLS:
            protocol = 'SMTP'
            info = 'Command: {}'.format(packet.smtp.command) if hasattr(packet.smtp, 'command') else 'N/A'

        if hasattr(packet, 'pop') and 'POP3' in ALLOWED_PROTOCOLS:
            protocol = 'POP3'
            info = 'Command: {}'.format(packet.pop.request_command) if hasattr(packet.pop, 'request_command') else 'N/A'

        if hasattr(packet, 'imap') and 'IMAP' in ALLOWED_PROTOCOLS:
            protocol = 'IMAP'
            info = 'Command: {}'.format(packet.imap.request_command) if hasattr(packet.imap, 'request_command') else 'N/A'

        if hasattr(packet, 'mqtt') and 'MQTT' in ALLOWED_PROTOCOLS:
            protocol = 'MQTT'
            info = 'Message Type: {}'.format(packet.mqtt.msgtype) if hasattr(packet.mqtt, 'msgtype') else 'N/A'

    except AttributeError:
        info = 'N/A'
    
    # Return the protocol, source, destination, and info
    return protocol, src, dst, info


def check_record_type(domain):
    try:
        # Kiểm tra bản ghi A
        answers = dns.resolver.resolve(domain, 'A')
        return 'A'
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    try:
        # Kiểm tra bản ghi AAAA
        answers = dns.resolver.resolve(domain, 'AAAA')
        return 'AAAA'
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    try:
        # Kiểm tra bản ghi CNAME
        answers = dns.resolver.resolve(domain, 'CNAME')
        return 'CNAME'
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    try:
        # Kiểm tra bản ghi MX
        answers = dns.resolver.resolve(domain, 'MX')
        return 'MX'
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    try:
        # Kiểm tra bản ghi NS
        answers = dns.resolver.resolve(domain, 'NS')
        return 'NS'
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return 'N/A'


# Hàm lấy địa chỉ IP từ tên miền (sử dụng socket)
def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return 'N/A'


# Hàm để lấy tên miền từ địa chỉ IP
def get_domain_from_ip(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return 'N/A'


def analyze_pcap_for_chart(cap, num_intervals=8):
    protocol_stats = defaultdict(lambda: defaultdict(lambda: {'packet_count': 0, 'total_bytes': 0}))
    start_time = None
    end_time = None

    try:
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

    # handle FRAME
    data_frames = []
    for i, packet in enumerate(cap):
        # Extracting timestamp
        time = packet.sniff_time.timestamp() if hasattr(packet, 'sniff_time') else 'N/A'
        
        # Get protocol information
        protocol, src, dst, info = get_protocol_info(packet)
        
        # Extract length if available
        length = packet.length if hasattr(packet, 'length') else 'N/A'
        
        # Append the extracted data to the list 
        if 'N/A' not in (time, src, dst, protocol, length, info):
            data_frames.append([i+1, time, src, dst, protocol, length, info])

    chart_data['frames'] = data_frames  

    # handle TCP 
    data_tcp = []
    for packet in cap:
        try:
            # Chỉ lấy gói tin TCP và có IP
            if 'TCP' in packet and hasattr(packet, 'ip'):
                # Lấy các thông tin cơ bản từ gói tin
                src = f"{packet.ip.src}:{packet.tcp.srcport}" if hasattr(packet, 'ip') else None
                dst = f"{packet.ip.dst}:{packet.tcp.dstport}" if hasattr(packet, 'ip') else None
                
                # Chỉ thêm vào danh sách nếu cả src và dst đều tồn tại
                if src and dst:
                    # Lấy độ dài gói tin để tính throughput
                    length = int(packet.length) if hasattr(packet, 'length') else 0
                    
                    # Giả lập giá trị accuracy và throughput
                    s_accuracy = f"{round(100 * length / 1500, 2)}%"  # 1500 bytes là kích thước MTU chuẩn
                    s_throughput = length * 8  # Throughput = độ dài gói * 8 (bits)
                    
                    t_accuracy = f"{round(100 * (length / 1500), 2)}%"
                    t_throughput = s_throughput // 2  # Ví dụ giả lập throughput tại đích
                    
                    # Thêm dữ liệu vào danh sách
                    data_tcp.append([src, dst, s_accuracy, s_throughput, t_accuracy, t_throughput, length])

        except AttributeError as e:
            # Bỏ qua lỗi nếu có thuộc tính không tồn tại
            continue 
    chart_data['tcp'] = data_tcp
    

    # handle DNS 
    data_dns = [] 
    # Lặp qua từng gói tin và lọc gói tin DNS
    for packet in cap:
        try:
            # Chỉ lấy gói tin DNS
            if 'DNS' in packet:
                # Lấy tên miền từ truy vấn hoặc phản hồi DNS
                name = packet.dns.qry_name if hasattr(packet.dns, 'qry_name') else packet.dns.resp_name if hasattr(packet.dns, 'resp_name') else 'N/A'
                
                # Kiểm tra loại bản ghi và địa chỉ (A, AAAA, CNAME)
                if hasattr(packet.dns, 'a'):
                    address = packet.dns.a  # IPv4
                    dns_type = 'A'
                elif hasattr(packet.dns, 'aaaa'):
                    address = packet.dns.aaaa  # IPv6
                    dns_type = 'AAAA'
                elif hasattr(packet.dns, 'cname'):
                    address = packet.dns.cname  # CNAME
                    dns_type = 'CNAME'
                else:
                    address = 'N/A'
                    dns_type = 'N/A'

                # TTL và lớp (class)
                ttl = packet.dns.resp_ttl if hasattr(packet.dns, 'resp_ttl') else 'N/A'
                clz = 'IN'  # Class Internet (IN) phổ biến
                
                # Nếu dns_type là 'N/A' nhưng có địa chỉ, kiểm tra loại bản ghi bằng dnspython
                if dns_type == 'N/A' and address != 'N/A':
                    dns_type = check_record_type(name)

                # Nếu address là 'N/A', sử dụng socket để tìm IP
                if address == 'N/A' and name != 'N/A':
                    address = get_ip(name)

                # Chỉ thêm vào set nếu name, dns_type, và address không phải 'N/A'
                if name != 'N/A' and dns_type != 'N/A' and address != 'N/A':
                    data_dns.add((name, dns_type, clz, ttl, address))

        except AttributeError:
            # Bỏ qua lỗi nếu gói tin không có thuộc tính mong muốn
            continue
    chart_data['dns'] = data_dns

    # dhcp 
    data_dhcp = []
    for p in cap:
        if 'DHCP' in p:
            data_dhcp.append([p.dhcp.hw_mac_addr, p.dhcp.option_requested_ip_address, p.dhcp.option_hostname])
    chart_data['dhcp'] = data_dhcp 

    
    # Src & Dst IP 
    # data_src_dst_ip = []
    ip_mapping = defaultdict(set)
    for packet in cap:
        try:
            # Lấy địa chỉ IP nguồn (source) và IP đích (destination)
            src_ip = packet.ip.src if hasattr(packet, 'ip') else None
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else None
            
            # Nếu cả source và destination đều tồn tại
            if src_ip and dst_ip:
                ip_mapping[src_ip].add(dst_ip)

        except AttributeError:
            # Bỏ qua các gói tin không có địa chỉ IP
            continue
    # chart_data['src_dst'] = ip_mapping
    chart_data['src_dst'] = {k: list(v) for k, v in ip_mapping.items()}  # Convert set to list

    # Dst Domain 
    data_dst_domain = []
    # Lặp qua từng gói tin và lấy thông tin Source, Destination, và Domain
    for packet in cap:
        try:
            # Lấy địa chỉ IP nguồn (src) và đích (dst) nếu có
            src_ip = packet.ip.src if hasattr(packet, 'ip') else None
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else None
            
            # Nếu cả IP nguồn và IP đích tồn tại
            if src_ip and dst_ip:
                # Lấy tên miền của địa chỉ IP đích
                domain = get_domain_from_ip(dst_ip)
                
                # In thông tin ra terminal 
                if domain != 'N/A':
                    # print(f"IP src: {src_ip:<15}  IP dst: {dst_ip:<15}  Domain: {domain}")
                    data_dst_domain.append([src_ip, dst_ip, domain])

        except AttributeError:
            # Bỏ qua các gói tin không có địa chỉ IP
            continue 
    chart_data['dst_domain'] = data_dst_domain 





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


# Hàm phân tích file PCAP
def analyze_pcap(capture):
    protocol_stats = {}
    total_packets = 0
    total_size = 0
    tcp_packets = []
    udp_packets = []

    # Duyệt từng gói tin trong file PCAP
    for packet in capture:
        total_packets += 1
        packet_length = int(packet.length)
        total_size += packet_length

        protocol = packet.highest_layer
        if protocol in protocol_stats:
            protocol_stats[protocol]['count'] += 1
            protocol_stats[protocol]['size'] += packet_length
        else:
            protocol_stats[protocol] = {'count': 1, 'size': packet_length}

        if protocol == 'TCP':
            tcp_packets.append(packet)
        elif protocol == 'UDP':
            udp_packets.append(packet)

    return protocol_stats, total_packets, total_size, tcp_packets, udp_packets

# Hàm thêm đoạn văn bản định dạng vào tài liệu
def add_paragraph(doc, text, bold=False, align='left', font_size=12):
    p = doc.add_paragraph()
    run = p.add_run(text)
    run.bold = bold
    p.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER if align == 'center' else WD_PARAGRAPH_ALIGNMENT.LEFT
    p.style.font.size = Pt(font_size)

# Hàm phân tích và tạo nhận xét cho UDP
def generate_udp_analysis(udp_packets):
    total_udp = len(udp_packets)
    dns_count = 0
    dhcp_count = 0
    streaming_count = 0

    # Phân loại gói tin UDP
    for packet in udp_packets:
        if 'DNS' in packet.highest_layer:
            dns_count += 1
        elif 'DHCP' in packet.highest_layer:
            dhcp_count += 1
        else:
            streaming_count += 1  # Giả định phần còn lại là streaming
    
    # Tính toán phần trăm
    dns_percentage = (dns_count / total_udp) * 100 if total_udp > 0 else 0
    dhcp_percentage = (dhcp_count / total_udp) * 100 if total_udp > 0 else 0
    streaming_percentage = (streaming_count / total_udp) * 100 if total_udp > 0 else 0

    # Tạo nhận xét tự động dựa trên tỷ lệ phần trăm
    remarks = []
    remarks.append(f"Tổng số lượng gói tin UDP: {total_udp}")
    remarks.append(f"Tổng dung lượng: {sum(int(p.length) for p in udp_packets) / 1024:.2f} KB")
    remarks.append("Các dịch vụ UDP phổ biến:")

    if dns_count > 0:
        remarks.append(f"• DNS: {dns_count} gói tin ({dns_percentage:.2f}%), chủ yếu là các yêu cầu và phản hồi DNS.")
    if dhcp_count > 0:
        remarks.append(f"• DHCP: {dhcp_count} gói tin ({dhcp_percentage:.2f}%), liên quan đến việc cấp phát địa chỉ IP cho các thiết bị trong mạng.")
    if streaming_count > 0:
        remarks.append(f"• Streaming: {streaming_count} gói tin ({streaming_percentage:.2f}%), cho thấy có các dịch vụ streaming video hoặc audio.")

    remarks.append("Nhận xét:")
    if dns_count > 0 or dhcp_count > 0:
        remarks.append("• DNS và DHCP: Đây là các giao thức UDP tiêu chuẩn, hoạt động ổn định.")
    if streaming_count > 0:
        remarks.append("• Streaming: Tỷ lệ cao cho thấy có hoạt động streaming trong mạng, có thể dẫn đến tình trạng tắc nghẽn mạng nếu không quản lý tốt.")
    
    return remarks

# Hàm phân tích và tạo nhận xét cho TCP
def generate_tcp_remarks(tcp_stats, tcp_packet_count):
    remarks = []
    
    for flag, count in tcp_stats.items():
        percentage = (count / tcp_packet_count) * 100 if tcp_packet_count > 0 else 0
        if flag == 'SYN':
            remarks.append(f"• Gói SYN: Chiếm tỷ lệ {percentage:.2f}% trong tổng số gói tin TCP, cho thấy nhiều kết nối TCP mới được thiết lập.")
        elif flag == 'ACK':
            remarks.append(f"• Gói ACK: Chiếm {percentage:.2f}%, là dấu hiệu của các kết nối đang hoạt động bình thường với nhiều gói tin xác nhận (acknowledgement).")
        elif flag == 'FIN':
            remarks.append(f"• Gói FIN: Có tỷ lệ thấp ({percentage:.2f}%), cho thấy một số kết nối TCP đã được kết thúc.")
        elif flag == 'PSH':
            remarks.append(f"• Gói PSH: Chiếm {percentage:.2f}%, chỉ ra rằng có sự truyền tải dữ liệu giữa các máy.")

    return remarks 


# Hàm tạo báo cáo
def generate_report(protocol_stats, total_packets, total_size, tcp_packets, udp_packets, instance):
    doc = Document()
    doc.styles['Normal'].font.name = 'Times New Roman'
    doc.styles['Normal']._element.rPr.rFonts.set(qn('w:eastAsia'), 'Times New Roman')
    
    # Set line spacing
    for style in doc.styles:
        if style.type == 1:  # Paragraph style
            style.paragraph_format.line_spacing = 1.5
    
    section = doc.sections[0]
    section.page_height = Inches(11.7)  # A4 size
    section.page_width = Inches(8.3)
    
    # Title và Overview
    doc.add_heading('Báo Cáo Phân Tích Dữ Liệu Mạng từ File PCAP', 0)
    doc.add_heading('1. Thông Tin Tổng Quan', level=1)
    add_paragraph(doc, f"Tên file: test_data.pcap", align='left', font_size=12)
    add_paragraph(doc, f"Thời gian bắt đầu phân tích: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", align='left', font_size=12)
    add_paragraph(doc, f"Số lượng gói tin: {total_packets}", align='left', font_size=12)
    add_paragraph(doc, f"Tổng dung lượng: {total_size / 1024:.2f} KB", align='left', font_size=12)
    
    # Phân tích giao thức
    doc.add_heading('2. Phân Tích Chi Tiết Giao Thức', level=1)
    table = doc.add_table(rows=1, cols=4)
    hdr_cells = table.rows[0].cells
    hdr_cells[0].text = 'Giao thức'
    hdr_cells[1].text = 'Số lượng gói tin'
    hdr_cells[2].text = 'Dung lượng (KB)'
    hdr_cells[3].text = 'Tỉ lệ (%)'

    for protocol, stats in protocol_stats.items():
        row_cells = table.add_row().cells
        row_cells[0].text = protocol
        row_cells[1].text = str(stats['count'])
        row_cells[2].text = f"{stats['size'] / 1024:.2f}"
        row_cells[3].text = f"{(stats['count'] / total_packets) * 100:.2f}"

    # Nhận xét giao thức
    doc.add_heading('Nhận xét:', level=2)
    for protocol, stats in protocol_stats.items():
        percentage = (stats['count'] / total_packets) * 100
        add_paragraph(doc, f"• {protocol}: Giao thức {protocol} chiếm tỷ lệ {percentage:.2f}% trong tổng số lượng gói tin.", font_size=12)
    
    # Phân tích TCP
    doc.add_heading('4. Phân Tích Lưu Lượng TCP', level=1)
    add_paragraph(doc, f'Tổng số lượng gói tin TCP: {len(tcp_packets)}', font_size=12)
    add_paragraph(doc, f'Tổng dung lượng: {sum(int(p.length) for p in tcp_packets) / 1024:.2f} KB', font_size=12)

    # Phân loại gói tin TCP
    doc.add_heading('Phân loại gói tin TCP:', level=2)
    table_tcp = doc.add_table(rows=1, cols=4)
    hdr_cells_tcp = table_tcp.rows[0].cells
    hdr_cells_tcp[0].text = 'Loại gói tin'
    hdr_cells_tcp[1].text = 'Số lượng'
    hdr_cells_tcp[2].text = 'Dung lượng (kB)'
    hdr_cells_tcp[3].text = 'Tỉ lệ (%)'

    # Phân tích các cờ TCP (SYN, ACK, FIN, PSH)
    tcp_stats = {
        'SYN': 0,
        'ACK': 0,
        'FIN': 0,
        'PSH': 0
    }
    for packet in tcp_packets:
        flags = packet.tcp.flags.int_value  # Lấy giá trị cờ TCP từ gói tin
        if flags == 2:  # SYN flag
            tcp_stats['SYN'] += 1
        if flags == 16:  # ACK flag
            tcp_stats['ACK'] += 1
        if flags == 1:  # FIN flag
            tcp_stats['FIN'] += 1
        if flags == 8:  # PSH flag
            tcp_stats['PSH'] += 1

    for flag, count in tcp_stats.items():
        row_cells_tcp = table_tcp.add_row().cells
        row_cells_tcp[0].text = flag
        row_cells_tcp[1].text = str(count)
        row_cells_tcp[2].text = f"{count * int(packet.length) / 1024:.2f}"
        row_cells_tcp[3].text = f"{(count / len(tcp_packets)) * 100:.2f}"

    # Tạo nhận xét TCP dựa trên phân tích
    doc.add_heading('Nhận xét:', level=2)
    tcp_remarks = generate_tcp_remarks(tcp_stats, len(tcp_packets))
    for remark in tcp_remarks:
        add_paragraph(doc, remark, font_size=12)

    # Phân tích UDP
    doc.add_heading('5. Phân Tích Lưu Lượng UDP', level=1)
    udp_analysis = generate_udp_analysis(udp_packets)
    for line in udp_analysis:
        add_paragraph(doc, line, font_size=12)

    file_stream = BytesIO()
    doc.save(file_stream)
    file_stream.seek(0) # di chuyen con tro ve dau file 
    report_content = ContentFile(file_stream.read())
    instance.report_file.save(f"report_{instance.id}.docx", report_content)
    



if __name__ == '__main__':
    print("--------------------Start------------------")
    pcap_id = sys.argv[1]
    process_pcap(pcap_id)
    print("--------------------Finish-----------------")
