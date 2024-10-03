import pyshark

# Tải file PCAP
cap = pyshark.FileCapture('test2.pcapng')

# Danh sách để lưu trữ thông tin HTTP đã format
http_data = []

# Lặp qua từng gói tin và kiểm tra xem có HTTP không
for packet in cap:
    try:
        # Chỉ xử lý các gói tin có lớp HTTP
        if hasattr(packet, 'http'):
            # Lấy method từ HTTP request
            method = packet.http.request_method if hasattr(packet.http, 'request_method') else None
            
            # Bỏ qua gói tin nếu method không xác định được
            if method is None:
                continue

            # Lấy thông tin cơ bản của gói tin
            src_ip = packet.ip.src
            dest_ip = packet.ip.dst
            
            # Lấy path từ HTTP request
            path = packet.http.request_uri if hasattr(packet.http, 'request_uri') else 'N/A'
            
            # Lấy thông tin HTTP status từ HTTP response
            status = packet.http.response_code if hasattr(packet.http, 'response_code') else 'N/A'
            
            # Lấy tổng thời gian phản hồi (ttr - time to respond)
            ttr = packet.sniff_time.microsecond if hasattr(packet, 'sniff_time') else 'N/A'
            
            # Thêm thông tin vào danh sách
            http_data.append({
                'source': src_ip,
                'dest': dest_ip,
                'method': method,
                'status': status,
                'ttr': ttr,
                'path': path,
                'http_request': str(packet.http) if hasattr(packet, 'http') else 'N/A',
                'http_response': str(packet.http) if hasattr(packet, 'http') else 'N/A'
            })

    except AttributeError as e:
        # Bỏ qua các gói tin không có thuộc tính HTTP hoặc các lỗi khác
        continue

# In ra thông tin HTTP đã phân tích
for entry in http_data:
    print(f"Source: {entry['source']}")
    print(f"Destination: {entry['dest']}")
    print(f"Method: {entry['method']}")
    print(f"Status: {entry['status']}")
    print(f"Time to Respond (microsec): {entry['ttr']}")
    print(f"Path: {entry['path']}")
    print(f"HTTP Request: {entry['http_request']}")
    print(f"HTTP Response: {entry['http_response']}")
    print("-" * 80)
