import pyshark
import xml.etree.ElementTree as ET
import matplotlib.pyplot as plt
from collections import defaultdict

# Tải file PCAP
cap = pyshark.FileCapture('test2.pcapng')

# Tạo một dictionary để lưu số lượng gói tin cho mỗi giao thức
protocol_hierarchy = defaultdict(lambda: {'frames': 0, 'bytes': 0})

# Lặp qua từng gói tin và phân tích giao thức
for packet in cap:
    try:
        highest_protocol = packet.highest_layer
        protocol_hierarchy[highest_protocol]['frames'] += 1
        protocol_hierarchy[highest_protocol]['bytes'] += int(packet.length)

    except AttributeError:
        # Bỏ qua các gói tin không hợp lệ
        continue

# Bước 2: Vẽ biểu đồ số lượng gói tin theo từng giao thức
protocols = list(protocol_hierarchy.keys())
frames = [protocol_hierarchy[proto]['frames'] for proto in protocols]
bytes_used = [protocol_hierarchy[proto]['bytes'] for proto in protocols]

fig, ax = plt.subplots()
ax.bar(protocols, frames, label='Frames')
ax.bar(protocols, bytes_used, bottom=frames, label='Bytes')

ax.set_xlabel('Protocol')
ax.set_ylabel('Count')
ax.legend()
plt.xticks(rotation=45)
# plt.show()
plt.savefig('protocol_statistics.png', format='png')
print("Biểu đồ đã được lưu thành file protocol_statistics.png")

# Bước 3: Tạo file XML phân cấp giao thức
root = ET.Element("protocol_hierarchy")

for protocol, stats in protocol_hierarchy.items():
    proto_element = ET.SubElement(root, "protocol", name=protocol)
    frames_element = ET.SubElement(proto_element, "frames")
    frames_element.text = str(stats['frames'])
    bytes_element = ET.SubElement(proto_element, "bytes")
    bytes_element.text = str(stats['bytes'])

# Xuất ra file XML
tree = ET.ElementTree(root)
tree.write("protocol_hierarchy.xml")

print("Dữ liệu phân cấp giao thức đã được xuất ra file protocol_hierarchy.xml")
