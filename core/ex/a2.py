# import pyshark

# # Load the PCAP file
# cap = pyshark.FileCapture('test2.pcapng')

# # List to store the formatted data
# data = []

# # Iterate through the packets and extract required fields
# for i, packet in enumerate(cap):
#     # Extracting timestamp, source, destination, protocol, length, and info
#     time = packet.sniff_time.timestamp() if hasattr(packet, 'sniff_time') else 'N/A'
#     src = packet.ip.src if hasattr(packet, 'ip') else 'N/A'
#     dst = packet.ip.dst if hasattr(packet, 'ip') else 'N/A'
#     protocol = packet.transport_layer if hasattr(packet, 'transport_layer') else 'N/A'
#     length = packet.length if hasattr(packet, 'length') else 'N/A'
#     info = packet.info if hasattr(packet, 'info') else 'N/A'
    
#     # Append the extracted data to the list
#     data.append([i+1, time, src, dst, protocol, length, info])

# # print(len(data))
# # Print the table (optional: format it using pandas or any other library)
# print("Index\tTime\t\t\tSource\t\t\tDestination\t\tProtocol\tLength\tInfo")
# for row in data:
#     print("\t".join(str(x) for x in row))





import pyshark

# List of allowed protocols
ALLOWED_PROTOCOLS = {'IP', 'ICMP', 'ARP', 'IPv6', 'ICMPV6', 'TCP', 'UDP', 'QUIC', 'SCTP',
                     'HTTP', 'HTTPS', 'FTP', 'DNS', 'DHCP', 'SMTP', 'POP3', 'IMAP', 
                     'MQTT', 'TLS', 'SSL', 'IPSec', 'Ethernet', 'MPLS', 'VLAN'}

# Load the PCAP file
cap = pyshark.FileCapture('test2.pcapng')

# List to store the formatted data
data = []

# Function to check protocol and extract information
def get_protocol_info(packet):
    protocol = 'N/A'
    info = 'N/A'
    src = 'N/A'
    dst = 'N/A'
    
    try:
        # Layer 2: Ethernet, MPLS, VLAN
        if hasattr(packet, 'eth') and 'Ethernet' in ALLOWED_PROTOCOLS:
            src = packet.eth.src
            dst = packet.eth.dst
            protocol = 'Ethernet'

        if hasattr(packet, 'mpls') and 'MPLS' in ALLOWED_PROTOCOLS:
            protocol = 'MPLS'
            info = 'MPLS Label: {}'.format(packet.mpls.label)

        if hasattr(packet, 'vlan') and 'VLAN' in ALLOWED_PROTOCOLS:
            protocol = 'VLAN'
            info = 'VLAN ID: {}'.format(packet.vlan.id)

        # Layer 3: IP, ARP, IPv6
        if hasattr(packet, 'ip') and 'IP' in ALLOWED_PROTOCOLS:
            src = packet.ip.src
            dst = packet.ip.dst
            protocol = 'IP'

        if hasattr(packet, 'arp') and 'ARP' in ALLOWED_PROTOCOLS:
            src = packet.arp.src_proto_ipv4
            dst = packet.arp.dst_proto_ipv4
            protocol = 'ARP'
            info = '{} request'.format(packet.arp.opcode)

        if hasattr(packet, 'ipv6') and 'IPv6' in ALLOWED_PROTOCOLS:
            src = packet.ipv6.src
            dst = packet.ipv6.dst
            protocol = 'IPv6'

        # Layer 3: ICMP, ICMPv6
        if hasattr(packet, 'icmp') and 'ICMP' in ALLOWED_PROTOCOLS:
            protocol = 'ICMP'
            info = 'Type: {}, Code: {}'.format(packet.icmp.type, packet.icmp.code)

        if hasattr(packet, 'icmpv6') and 'ICMPV6' in ALLOWED_PROTOCOLS:
            protocol = 'ICMPV6'
            info = 'Type: {}, Code: {}'.format(packet.icmpv6.type, packet.icmpv6.code)

        # Layer 4: TCP, UDP, SCTP, QUIC
        if hasattr(packet, 'tcp') and 'TCP' in ALLOWED_PROTOCOLS:
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport
            protocol = 'TCP'
            info = 'Src Port: {}, Dst Port: {}'.format(src_port, dst_port)

        if hasattr(packet, 'udp') and 'UDP' in ALLOWED_PROTOCOLS:
            src_port = packet.udp.srcport
            dst_port = packet.udp.dstport
            protocol = 'UDP'
            info = 'Src Port: {}, Dst Port: {}'.format(src_port, dst_port)

        if hasattr(packet, 'sctp') and 'SCTP' in ALLOWED_PROTOCOLS:
            protocol = 'SCTP'
            info = 'SCTP Stream: {}'.format(packet.sctp.stream)

        if hasattr(packet, 'quic') and 'QUIC' in ALLOWED_PROTOCOLS:
            protocol = 'QUIC'
            info = 'QUIC Stream: {}'.format(packet.quic.stream_id)

        # Application Layer Protocols: HTTP, HTTPS, DNS, DHCP, etc.
        if hasattr(packet, 'http') and 'HTTP' in ALLOWED_PROTOCOLS:
            protocol = 'HTTP'
            info = packet.http.host if hasattr(packet.http, 'host') else 'N/A'

        if hasattr(packet, 'ssl') and 'SSL' in ALLOWED_PROTOCOLS:
            protocol = 'SSL/TLS'
            info = 'SSL Record Version: {}'.format(packet.ssl.record_version) if hasattr(packet.ssl, 'record_version') else 'N/A'

        if hasattr(packet, 'dns') and 'DNS' in ALLOWED_PROTOCOLS:
            protocol = 'DNS'
            info = 'Query Name: {}'.format(packet.dns.qry_name) if hasattr(packet.dns, 'qry_name') else 'N/A'

        if hasattr(packet, 'dhcp') and 'DHCP' in ALLOWED_PROTOCOLS:
            protocol = 'DHCP'
            info = 'Client IP: {}'.format(packet.dhcp.client_ip_addr) if hasattr(packet.dhcp, 'client_ip_addr') else 'N/A'

        if hasattr(packet, 'ftp') and 'FTP' in ALLOWED_PROTOCOLS:
            protocol = 'FTP'
            info = 'Command: {}'.format(packet.ftp.request_command) if hasattr(packet.ftp, 'request_command') else 'N/A'

        if hasattr(packet, 'smtp') and 'SMTP' in ALLOWED_PROTOCOLS:
            protocol = 'SMTP'
            info = 'Command: {}'.format(packet.smtp.command) if hasattr(packet.smtp, 'command') else 'N/A'

        if hasattr(packet, 'pop') and 'POP3' in ALLOWED_PROTOCOLS:
            protocol = 'POP3'
            info = 'Command: {}'.format(packet.pop.request_command) if hasattr(packet.pop, 'request_command') else 'N/A'

        if hasattr(packet, 'imap') and 'IMAP' in ALLOWED_PROTOCOLS:
            protocol = 'IMAP'
            info = 'Command: {}'.format(packet.imap.request_command) if hasattr(packet.imap, 'request_command') else 'N/A'

        if hasattr(packet, 'mqtt') and 'MQTT' in ALLOWED_PROTOCOLS:
            protocol = 'MQTT'
            info = 'Message Type: {}'.format(packet.mqtt.msgtype) if hasattr(packet.mqtt, 'msgtype') else 'N/A'

    except AttributeError:
        info = 'N/A'
    
    # Return the protocol, source, destination, and info
    return protocol, src, dst, info

# for p in cap:
#     print(p)
#     break

ind = 1
# Iterate through the packets and extract required fields
for i, packet in enumerate(cap):
    # Extracting timestamp
    time = packet.sniff_time.timestamp() if hasattr(packet, 'sniff_time') else 'N/A'
    
    # Get protocol information
    protocol, src, dst, info = get_protocol_info(packet)
    
    # Extract length if available
    length = packet.length if hasattr(packet, 'length') else 'N/A'
    if 'N/A' not in (time, src, dst, protocol, length, info):
        # Append the extracted data to the list
        data.append([ind, time, src, dst, protocol, length, info])
        ind += 1

# Print the table (optional: format it using pandas or any other library)
print("Index\tTime\t\t\tSource\t\t\tDestination\t\tProtocol\tLength\tInfo")
for row in data:
    print("\t".join(str(x) for x in row))
