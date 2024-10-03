import pyshark
from collections import defaultdict

# Tải file PCAP
cap = pyshark.FileCapture('test2.pcapng')

# Sử dụng defaultdict để lưu danh sách IP đích theo từng IP nguồn
ip_mapping = defaultdict(set)

# Lặp qua từng gói tin và lấy thông tin Source và Destination
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

# In ra danh sách địa chỉ IP nguồn và đích
print(f"{'Src':<20} {'Dst'}")
for src_ip, dst_ips in ip_mapping.items():
    print(f"{src_ip:<20} {', '.join(dst_ips)}")
