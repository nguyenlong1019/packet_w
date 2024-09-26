import pyshark 



def analyze_pcap_api(file_path):
    # giao thức lớp mạng: IP, ICMP, ARP, IPv6
    # giao thức lớp giao vận: TCP, UDP, SCTP, QUIC 
    # giao thức lớp ứng dụng: HTTP, HTTPS, FTP, DNS, DHCP, SMTP, POP3, IMAP, MQTT 
    # giao thức bảo mật: TLS, SSL, IPSec 
    # giao thức chuyển mạch: Ethernet, MPLS, VLAN

    cap = pyshark.FileCapture(file_path)
    
    protocol_stats = {}

    try:
        for packet in cap:
            protocol = packet.highest_layer # top layer của packet 
            if protocol in protocol_stats:
                protocol_stats[protocol] += 1
            else:
                protocol_stats[protocol] = 1
        print("---------------------------------------")
        print("Thống kê các giao thức trong capture: ")
        for protocol, count in protocol_stats.items():
            print(f"{protocol}: {count} packets")
        print("---------------------------------------")

        for packet in cap:
            if 'IP' in packet:
                print(packet)
                break
        print("---------------------------------------")
        for packet in cap:
            if 'TCP' in packet:
                print(packet)
                break 
        print("---------------------------------------")
        for packet in cap:
            if 'UDP' in packet:
                print(packet)
                break 
        print("---------------------------------------")
        for packet in cap:
            if 'HTTP' in packet:
                print(packet)
                break 
        print("---------------------------------------")
        for packet in cap:
            if 'DNS' in packet:
                print(packet)
                break 
        print("---------------------------------------")
        for packet in cap:
            if 'TLS' in packet:
                print(packet)
                break
    except pyshark.capture.capture.TSharkCrashException:
        pass 

    try:
        cap.close()
    except pyshark.capture.capture.TSharkCrashException:
        pass 


file_path = 'test_data.pcapng'
analyze_pcap_api(file_path)
