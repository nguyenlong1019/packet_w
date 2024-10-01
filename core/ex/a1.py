import pyshark

# Đọc file PCAP
capture = pyshark.FileCapture('test_data.pcapng')

# Khởi tạo một tập hợp để lưu các giao thức
protocol_set = set()

# Duyệt qua các packet
for packet in capture:
    # Duyệt qua tất cả các lớp giao thức trong packet
    for layer in packet.layers:
        # Thêm giao thức vào tập hợp
        protocol_set.add(layer.layer_name)

# In danh sách các giao thức
print("Các giao thức có trong file PCAP:", protocol_set)
