import pyshark
import socket

# Tải file PCAP
cap = pyshark.FileCapture('test2.pcapng')

# Hàm để lấy tên miền từ địa chỉ IP
def get_domain_from_ip(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
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
            if domain != 'N/A':
                print(f"IP src: {src_ip:<15}  IP dst: {dst_ip:<15}  Domain: {domain}")

    except AttributeError:
        # Bỏ qua các gói tin không có địa chỉ IP
        continue















# import pyshark
# import dns.resolver

# # Tải file PCAP
# cap = pyshark.FileCapture('test2.pcapng')

# # Hàm để lấy tên miền từ địa chỉ IP bằng dnspython
# def get_domain_from_ip(ip):
#     try:
#         query = dns.reversename.from_address(ip)
#         domain = str(dns.resolver.resolve(query, 'PTR')[0])
#         return domain
#     except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
#         return 'N/A'

# # Lặp qua từng gói tin và lấy thông tin Source, Destination, và Domain
# for packet in cap:
#     try:
#         # Lấy địa chỉ IP nguồn (src) và đích (dst) nếu có
#         src_ip = packet.ip.src if hasattr(packet, 'ip') else None
#         dst_ip = packet.ip.dst if hasattr(packet, 'ip') else None
        
#         # Nếu cả IP nguồn và IP đích tồn tại
#         if src_ip and dst_ip:
#             # Lấy tên miền của địa chỉ IP đích
#             domain = get_domain_from_ip(dst_ip)
            
#             # In thông tin ra terminal
#             print(f"IP src: {src_ip:<15}  IP dst: {dst_ip:<15}  Domain: {domain}")

#     except AttributeError:
#         # Bỏ qua các gói tin không có địa chỉ IP
#         continue
