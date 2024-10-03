import pyshark
import socket
import dns.resolver

# Tải file PCAP
cap = pyshark.FileCapture('test2.pcapng')

# Sử dụng set để tránh các bản ghi trùng lặp
data = set()

# Hàm kiểm tra loại bản ghi DNS từ tên miền (sử dụng dnspython)
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
                data.add((name, dns_type, clz, ttl, address))

    except AttributeError:
        # Bỏ qua lỗi nếu gói tin không có thuộc tính mong muốn
        continue

# In tổng số gói tin DNS đã phân tích
print(f"Tổng số gói tin DNS: {len(data)}")

# In dữ liệu chi tiết từng gói tin DNS
print(f"{'name':<40} {'type':<8} {'clz':<8} {'ttl':<8} {'address'}")
for record in data:
    name, dns_type, clz, ttl, address = record
    print(f"{name:<40} {dns_type:<8} {clz:<8} {ttl:<8} {address}")
