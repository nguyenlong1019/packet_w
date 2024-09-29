import pyshark 
import json 
from collections import defaultdict  
from datetime import datetime, timedelta


def analyze_pcap_for_chart(file_path):
    protocol_stats = defaultdict(lambda: {'packet_count': 0, 'total_bytes': 0})

    try:
        cap = pyshark.FileCapture(file_path)

        for packet in cap:
            try:
                protocol = packet.highest_layer 
                packet_size = int(packet.length)

                protocol_stats[protocol]['packet_count'] += 1
                protocol_stats[protocol]['total_bytes'] += packet_size  
            except AttributeError:
                continue 
        
        cap.close()
    except Exception as e:
        return None 


    chart_data = {
        'labels': [],
        'datasets': [],
    }

    chart_data['labels'] = list(protocol_stats.keys())

    for protocol, stats in protocol_stats.items():
        chart_data['datasets'].append({
            'label': protocol, 
            'data': [stats['packet_count'], stats['total_bytes']],
            'borderColor': get_color(protocol),
            'backgroundColor': get_background_color(protocol),
            'fill': True,
            'tension': 0.4,
        })
    
    return json.dumps(chart_data, indent=4)


def get_color(protocol):
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
    return colors.get(protocol, 'rgba(201, 203, 207, 1)')


def get_background_color(protocol):
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

# Phân tích tất cả các giao thức có trong file PCAP 
# Tính toán thống kê về số lượng packet và dung lượng dữ liệu cho từng giao thức 
# Xuất kết quả dưới dạng cấu trúc JSON để có thể dùng trong mã JavaScript cho biểu đồ 
