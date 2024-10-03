import pyshark

# Tải file PCAP
cap = pyshark.FileCapture('test2.pcapng')

# Danh sách để lưu trữ dữ liệu đã format
data = []

# Lặp qua từng gói tin và lọc gói tin TCP
for packet in cap:
    try:
        # Chỉ lấy gói tin TCP và có IP
        if 'TCP' in packet and hasattr(packet, 'ip'):
            # Lấy các thông tin cơ bản từ gói tin
            src = f"{packet.ip.src}:{packet.tcp.srcport}" if hasattr(packet, 'ip') else None
            dst = f"{packet.ip.dst}:{packet.tcp.dstport}" if hasattr(packet, 'ip') else None
            
            # Chỉ thêm vào danh sách nếu cả src và dst đều tồn tại
            if src and dst:
                # Lấy độ dài gói tin để tính throughput
                length = int(packet.length) if hasattr(packet, 'length') else 0
                
                # Giả lập giá trị accuracy và throughput
                s_accuracy = f"{round(100 * length / 1500, 2)}%"  # 1500 bytes là kích thước MTU chuẩn
                s_throughput = length * 8  # Throughput = độ dài gói * 8 (bits)
                
                t_accuracy = f"{round(100 * (length / 1500), 2)}%"
                t_throughput = s_throughput // 2  # Ví dụ giả lập throughput tại đích
                
                # Thêm dữ liệu vào danh sách
                data.append([src, dst, s_accuracy, s_throughput, t_accuracy, t_throughput, length])

    except AttributeError as e:
        # Bỏ qua lỗi nếu có thuộc tính không tồn tại
        continue

# In tổng số gói tin TCP đã phân tích
print(f"Tổng số gói tin TCP hợp lệ: {len(data)}")
# In dữ liệu chi tiết từng gói tin
for i in data:
    print(i)

