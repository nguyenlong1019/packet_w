# import pyshark
# import xml.etree.ElementTree as ET
# from collections import defaultdict

# # Tải file PCAP
# cap = pyshark.FileCapture('test2.pcapng')

# # Sử dụng defaultdict để lưu trữ cấu trúc phân cấp các giao thức
# protocol_hierarchy = defaultdict(lambda: {'frames': 0, 'bytes': 0, 'sub_protocols': defaultdict(lambda: {'frames': 0, 'bytes': 0})})

# # Lặp qua từng gói tin và phân tích lớp giao thức
# for packet in cap:
#     try:
#         # Lấy lớp giao thức cao nhất (Ethernet, IP, TCP, etc.)
#         highest_protocol = packet.highest_layer
#         # Lấy số bytes của gói tin
#         packet_length = int(packet.length)

#         # Phân tích từng lớp giao thức từ thấp đến cao
#         layers = [layer.layer_name for layer in packet.layers]
        
#         # Cấp giao thức đầu tiên
#         current_level = protocol_hierarchy
#         for i, layer in enumerate(layers):
#             current_level[layer]['frames'] += 1
#             current_level[layer]['bytes'] += packet_length

#             # Chuyển đến lớp con
#             if i < len(layers) - 1:
#                 current_level = current_level[layer]['sub_protocols']

#     except AttributeError:
#         # Bỏ qua các gói tin không hợp lệ
#         continue

# # Hàm để in ra cấu trúc phân cấp giao thức
# def print_protocol_hierarchy(proto_dict, indent=0):
#     for proto, stats in proto_dict.items():
#         print('  ' * indent + f"{proto} (Frames: {stats['frames']}, Bytes: {stats['bytes']})")
#         if stats['sub_protocols']:
#             print_protocol_hierarchy(stats['sub_protocols'], indent + 1)

# # Hiển thị phân cấp giao thức
# print("Protocol Hierarchy:")
# print_protocol_hierarchy(protocol_hierarchy)

# # Bước 2: Xuất cấu trúc phân cấp ra file XML
# root = ET.Element("protocol_hierarchy")

# def add_protocol_to_xml(proto_dict, xml_element):
#     for proto, stats in proto_dict.items():
#         proto_element = ET.SubElement(xml_element, "protocol", name=proto)
#         frames_element = ET.SubElement(proto_element, "frames")
#         frames_element.text = str(stats['frames'])
#         bytes_element = ET.SubElement(proto_element, "bytes")
#         bytes_element.text = str(stats['bytes'])

#         if stats['sub_protocols']:
#             add_protocol_to_xml(stats['sub_protocols'], proto_element)

# add_protocol_to_xml(protocol_hierarchy, root)

# # Xuất ra file XML
# tree = ET.ElementTree(root)
# tree.write("protocol_hierarchy.xml")

# print("Dữ liệu phân cấp giao thức đã được xuất ra file protocol_hierarchy.xml")








import pyshark
import xml.etree.ElementTree as ET
from collections import defaultdict

# Tải file PCAP
cap = pyshark.FileCapture('test2.pcapng')

# Sử dụng defaultdict để lưu trữ cấu trúc phân cấp các giao thức
def create_protocol_dict():
    return {'frames': 0, 'bytes': 0, 'sub_protocols': defaultdict(create_protocol_dict)}

protocol_hierarchy = defaultdict(create_protocol_dict)

# Lặp qua từng gói tin và phân tích lớp giao thức
for packet in cap:
    try:
        # Lấy lớp giao thức cao nhất (Ethernet, IP, TCP, etc.)
        packet_length = int(packet.length)
        layers = [layer.layer_name for layer in packet.layers]
        
        # Bắt đầu từ cấp cao nhất
        current_level = protocol_hierarchy
        
        # Duyệt qua từng lớp giao thức
        for i, layer in enumerate(layers):
            current_level[layer]['frames'] += 1
            current_level[layer]['bytes'] += packet_length

            # Chuyển xuống lớp con (sub_protocols)
            current_level = current_level[layer]['sub_protocols']

    except AttributeError:
        # Bỏ qua các gói tin không hợp lệ
        continue

# Hàm để in ra cấu trúc phân cấp giao thức
def print_protocol_hierarchy(proto_dict, indent=0):
    for proto, stats in proto_dict.items():
        print('  ' * indent + f"{proto} (Frames: {stats['frames']}, Bytes: {stats['bytes']})")
        if stats['sub_protocols']:
            print_protocol_hierarchy(stats['sub_protocols'], indent + 1)

# Hiển thị phân cấp giao thức
print("Protocol Hierarchy:")
print_protocol_hierarchy(protocol_hierarchy)

# Bước 2: Xuất cấu trúc phân cấp ra file XML
root = ET.Element("protocol_hierarchy")

def add_protocol_to_xml(proto_dict, xml_element):
    for proto, stats in proto_dict.items():
        proto_element = ET.SubElement(xml_element, "protocol", name=proto)
        frames_element = ET.SubElement(proto_element, "frames")
        frames_element.text = str(stats['frames'])
        bytes_element = ET.SubElement(proto_element, "bytes")
        bytes_element.text = str(stats['bytes'])

        if stats['sub_protocols']:
            add_protocol_to_xml(stats['sub_protocols'], proto_element)

add_protocol_to_xml(protocol_hierarchy, root)

# Xuất ra file XML
tree = ET.ElementTree(root)
tree.write("protocol_hierarchy.xml")

print("Dữ liệu phân cấp giao thức đã được xuất ra file protocol_hierarchy.xml")
