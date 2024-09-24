import pyshark

# Đọc file PCAP
cap = pyshark.FileCapture('example.pcap')

# Lọc gói tin DHCP
for pkt in cap:
    if 'bootp' in pkt:
        print(f"Client MAC Address: {pkt.bootp.hw_mac_addr}")
        print(f"Requested IP Address: {pkt.bootp.requested_ip_addr}")
        print(f"Host Name: {pkt.bootp.host_name}\n")
