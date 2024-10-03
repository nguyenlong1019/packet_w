import pyshark
from scapy.all import *

# Tải file PCAP
cap = pyshark.FileCapture('test2.pcapng')

# Hàm để lấy tên miền từ địa chỉ IP bằng Scapy
def get_domain_from_ip(ip):
    try:
        domain = sr1(IP(dst="8.8.8.8")/UDP()/DNS(rd=1,qd=DNSQR(qname=ip)), verbose=0)
        if domain and domain.an:
            return domain.an.rdata.decode('utf-8')
        return 'N/A'
    except Exception:
        return 'N/A'

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
            print(f"IP src: {src_ip:<15}  IP dst: {dst_ip:<15}  Domain: {domain}")

    except AttributeError:
        # Bỏ qua các gói tin không có địa chỉ IP
        continue
