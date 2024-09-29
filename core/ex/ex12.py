import pyshark
import json
from collections import defaultdict

def analyze_pcap_for_chart(file_path):
    # Khởi tạo dictionary lưu thông tin thống kê
    protocol_stats = defaultdict(lambda: {'packet_count': 0, 'total_bytes': 0})
    
    try:
        cap = pyshark.FileCapture(file_path)

        for packet in cap:
            try:
                protocol = packet.highest_layer
                packet_size = int(packet.length)  # Lấy kích thước của packet

                # Tăng số lượng packet và tổng số bytes cho giao thức tương ứng
                protocol_stats[protocol]['packet_count'] += 1
                protocol_stats[protocol]['total_bytes'] += packet_size
            except AttributeError:
                continue

        # Đóng file capture
        cap.close()

    except Exception as e:
        print(f"Error processing file: {e}")
        return None

    # Tạo cấu trúc dữ liệu để dùng cho vẽ biểu đồ
    chart_data = {
        'labels': [],
        'datasets': []
    }

    # Gán nhãn cho các giao thức
    chart_data['labels'] = list(protocol_stats.keys())

    # Thêm các thống kê vào datasets
    for protocol, stats in protocol_stats.items():
        chart_data['datasets'].append({
            'label': protocol,
            'data': [stats['packet_count'], stats['total_bytes']],
            'borderColor': get_color(protocol),
            'backgroundColor': get_background_color(protocol),
            'fill': True,
            'tension': 0.4
        })

    # Chuyển dữ liệu thành JSON để dùng cho vẽ biểu đồ
    return json.dumps(chart_data, indent=4)

def get_color(protocol):
    # Hàm để lấy màu cho từng giao thức
    colors = {
        'TCP': 'rgba(54, 162, 235, 1)',
        'UDP': 'rgba(255, 99, 132, 1)',
        'HTTP': 'rgba(75, 192, 192, 1)',
        'DNS': 'rgba(153, 102, 255, 1)',
        'TLS': 'rgba(255, 206, 86, 1)',
        'ICMP': 'rgba(255, 159, 64, 1)',
        'ARP': 'rgba(54, 162, 235, 1)',
        'IPv6': 'rgba(99, 132, 255, 1)',
        'HTTPS': 'rgba(201, 203, 207, 1)',
    }
    return colors.get(protocol, 'rgba(0, 0, 0, 1)')

def get_background_color(protocol):
    # Hàm để lấy màu nền cho từng giao thức
    colors = {
        'TCP': 'rgba(54, 162, 235, 0.2)',
        'UDP': 'rgba(255, 99, 132, 0.2)',
        'HTTP': 'rgba(75, 192, 192, 0.2)',
        'DNS': 'rgba(153, 102, 255, 0.2)',
        'TLS': 'rgba(255, 206, 86, 0.2)',
        'ICMP': 'rgba(255, 159, 64, 0.2)',
        'ARP': 'rgba(54, 162, 235, 0.2)',
        'IPv6': 'rgba(99, 132, 255, 0.2)',
        'HTTPS': 'rgba(201, 203, 207, 0.2)',
    }
    return colors.get(protocol, 'rgba(0, 0, 0, 0.2)')

# Ví dụ sử dụng hàm
file_path = 'test_data.pcapng'
chart_data_json = analyze_pcap_for_chart(file_path)

# Lưu dữ liệu chart vào file JSON để dùng trong frontend
with open('chart_data.json', 'w') as f:
    f.write(chart_data_json)
