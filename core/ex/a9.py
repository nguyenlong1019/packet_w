import pyshark

# Tải file PCAP
cap = pyshark.FileCapture('test_data.pcapng')

# Lưu thông tin DHCP vào danh sách
dhcp_data = []

for p in cap:
    if 'DHCP' in p:
        print(p)
        print(dir(p.dhcp))
        print(p.dhcp.hw_mac_addr)
        print(p.dhcp.option_requested_ip_address)
        print(p.dhcp.option_hostname)
        break

# # Lặp qua từng gói tin và kiểm tra xem có lớp DHCP không
# for packet in cap:
#     try:
#         # Kiểm tra nếu gói tin có lớp DHCP
#         if 'DHCP' in packet:
#             # Lấy thông tin MAC của Client
#             client_mac = packet.dhcp.hw_mac_addr if hasattr(packet.dhcp, 'hw_mac_addr') else 'N/A'
            
#             # Lấy địa chỉ IP được yêu cầu từ gói DHCP
#             requested_ip = packet.dhcp.requested_ip_addr if hasattr(packet.dhcp, 'requested_ip_addr') else 'N/A'
            
#             # Lấy tên máy chủ từ gói DHCP (hostname)
#             host_name = packet.dhcp.host_name if hasattr(packet.dhcp, 'host_name') else 'N/A'
            
#             # Thêm thông tin vào danh sách
#             dhcp_data.append({
#                 'client_mac': client_mac,
#                 'requested_ip': requested_ip,
#                 'host_name': host_name
#             })

#     except AttributeError:
#         # Bỏ qua các gói tin không hợp lệ
#         continue

# # Hiển thị thông tin các gói tin DHCP
# for entry in dhcp_data:
#     print("DHCP Information:")
#     print(f"Client MAC address: {entry['client_mac']}")
#     print(f"Requested IP Address: {entry['requested_ip']}")
#     print(f"Host Name: {entry['host_name']}")
#     print("-" * 40)
