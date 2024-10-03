import pyshark
import xml.etree.ElementTree as ET

# Tải file PCAP
cap = pyshark.FileCapture('test2.pcapng')

# Danh sách để lưu trữ phân cấp của từng gói tin
packets_hierarchy = []

# Lặp qua từng gói tin và phân tích các lớp giao thức
for packet_num, packet in enumerate(cap, start=1):
    try:
        # Danh sách để lưu các lớp giao thức của từng gói tin
        packet_info = {"packet_number": packet_num, "protocols": []}
        
        # Lấy danh sách các lớp giao thức của gói tin
        for layer in packet.layers:
            # Lấy tên lớp giao thức và số bytes của gói tin
            protocol_name = layer.layer_name
            length = int(packet.length) if hasattr(packet, 'length') else 0
            
            # Thêm thông tin lớp giao thức vào packet_info
            packet_info["protocols"].append({
                "protocol": protocol_name,
                "length": length
            })
        
        # Thêm cấu trúc phân cấp của gói tin vào danh sách
        packets_hierarchy.append(packet_info)

    except AttributeError:
        # Bỏ qua các gói tin không hợp lệ
        continue

# Hàm để hiển thị phân cấp của từng gói tin
def print_packet_hierarchy(packet_hierarchy):
    for packet in packet_hierarchy:
        print(f"Packet {packet['packet_number']}:")
        for proto in packet['protocols']:
            print(f"  Protocol: {proto['protocol']} - Length: {proto['length']} bytes")
        print("-" * 40)

# In ra phân cấp của từng gói tin
print("Packet Protocol Hierarchy:")
print_packet_hierarchy(packets_hierarchy)

# Bước 2: Xuất cấu trúc phân cấp của từng gói tin ra file XML
root = ET.Element("packets_hierarchy")

for packet in packets_hierarchy:
    packet_element = ET.SubElement(root, "packet", number=str(packet["packet_number"]))
    for proto in packet["protocols"]:
        proto_element = ET.SubElement(packet_element, "protocol", name=proto["protocol"])
        length_element = ET.SubElement(proto_element, "length")
        length_element.text = str(proto["length"])

# Xuất ra file XML
tree = ET.ElementTree(root)
tree.write("packet_hierarchy.xml")

print("Dữ liệu phân cấp của từng gói tin đã được xuất ra file packet_hierarchy.xml")
