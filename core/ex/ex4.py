import pyshark

# Đọc file PCAP
cap = pyshark.FileCapture('example.pcap')

# Dictionary để lưu trữ kết quả {src_ip: [dst_domain]}
ip_domain_mapping = {}

# Duyệt qua tất cả các gói tin
for pkt in cap:
    if 'IP' in pkt:  # Kiểm tra nếu gói tin là IP
        src_ip = pkt.ip.src  # Lấy địa chỉ IP nguồn
        dst_ip = pkt.ip.dst  # Lấy địa chỉ IP đích

        # Kiểm tra xem gói tin có thuộc giao thức DNS không
        if 'DNS' in pkt:
            try:
                # Trích xuất tên miền đích từ gói tin DNS
                dst_domain = pkt.dns.qry_name

                # Lưu trữ kết quả theo IP nguồn
                if src_ip not in ip_domain_mapping:
                    ip_domain_mapping[src_ip] = []

                # Thêm domain đích vào danh sách
                if dst_domain not in ip_domain_mapping[src_ip]:
                    ip_domain_mapping[src_ip].append(dst_domain)
            except AttributeError:
                pass  # Trường hợp không có tên miền DNS

# Hiển thị kết quả
for src_ip, domains in ip_domain_mapping.items():
    print(f"Src IP: {src_ip} -> Dst Domains: {', '.join(domains)}")
