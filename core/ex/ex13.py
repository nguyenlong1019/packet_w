import pyshark
import json
from collections import defaultdict
from datetime import datetime, timedelta

def analyze_pcap_for_chart(file_path, time_interval='5S'):
    # Dictionary chứa thông tin thống kê về giao thức và thời gian
    protocol_stats = defaultdict(lambda: defaultdict(lambda: {'packet_count': 0, 'total_bytes': 0}))

    try:
        cap = pyshark.FileCapture(file_path)

        # Xác định thời gian bắt đầu (time start) của gói tin đầu tiên
        start_time = None

        for packet in cap:
            try:
                protocol = packet.highest_layer
                packet_size = int(packet.length)
                packet_time = datetime.fromtimestamp(float(packet.sniff_timestamp))  # Thời gian bắt gói tin

                if start_time is None:
                    start_time = packet_time  # Đặt thời gian bắt đầu

                # Tính toán khoảng thời gian (time slot) dựa trên thời gian bắt đầu và interval
                time_delta = packet_time - start_time
                time_slot = int(time_delta.total_seconds() / timedelta(seconds=parse_time_interval(time_interval)).total_seconds())
                time_label = str(time_slot * parse_time_interval(time_interval).total_seconds()) + "s"

                # Tăng số lượng packet và tổng số bytes cho giao thức tương ứng tại time_slot
                protocol_stats[time_label][protocol]['packet_count'] += 1
                protocol_stats[time_label][protocol]['total_bytes'] += packet_size
            except AttributeError:
                continue

        # Đóng file capture
        cap.close()

    except Exception as e:
        print(f"Error processing file: {e}")
        return None

    # Tạo cấu trúc dữ liệu để dùng cho vẽ biểu đồ
    chart_data = {
        'labels': list(protocol_stats.keys()),
        'datasets': []
    }

    # Thêm các thống kê vào datasets
    all_protocols = set()
    for time_slot, stats in protocol_stats.items():
        for protocol in stats.keys():
            all_protocols.add(protocol)

    for protocol in all_protocols:
        protocol_data = []
        for time_slot in chart_data['labels']:
            if protocol in protocol_stats[time_slot]:
                protocol_data.append(protocol_stats[time_slot][protocol]['total_bytes'] / 1024)  # Dữ liệu tính bằng kB
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

    # Chuyển dữ liệu thành JSON để dùng cho vẽ biểu đồ
    return json.dumps(chart_data, indent=4)


def parse_time_interval(interval):
    """
    Chuyển đổi chuỗi thời gian thành đối tượng timedelta.
    """
    if interval[-1] == 'S':
        return timedelta(seconds=int(interval[:-1]))
    elif interval[-1] == 'M':
        return timedelta(minutes=int(interval[:-1]))
    elif interval[-1] == 'H':
        return timedelta(hours=int(interval[:-1]))
    else:
        raise ValueError("Invalid time interval format.")


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
chart_data_json = analyze_pcap_for_chart(file_path, time_interval='10S')  # Phân tích theo khoảng thời gian 10 giây
print(chart_data_json)
# Lưu dữ liệu chart vào file JSON để dùng trong frontend
# with open('chart_data1.json', 'w') as f:
#     f.write(chart_data_json)
