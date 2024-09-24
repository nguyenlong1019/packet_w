import pyshark

# Đọc file PCAP
cap = pyshark.FileCapture('example.pcap')

# Duyệt qua từng gói tin
for pkt in cap:
    print(f"Packet {pkt.number}:")
    print(f"    Timestamp: {pkt.sniff_time}")
    print(f"    Source IP: {pkt.ip.src}")
    print(f"    Destination IP: {pkt.ip.dst}")
    print(f"    Protocol: {pkt.highest_layer}")
    print(f"    Length: {pkt.length}\n")
