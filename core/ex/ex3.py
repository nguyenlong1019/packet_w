import pyshark

cap = pyshark.FileCapture('example.pcap', display_filter='http')

for pkt in cap:
    if 'http' in pkt:
        print(f"Source: {pkt.ip.src}")
        print(f"Destination: {pkt.ip.dst}")
        print(f"Host: {pkt.http.host}")
        print(f"User-Agent: {pkt.http.user_agent}")
        print(f"Cookie: {pkt.http.cookie}")
