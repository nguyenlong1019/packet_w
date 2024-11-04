def process_pcap(pcap_id):
    with transaction.atomic():
        instance = PcapFileUpload.objects.get(id=pcap_id)
        file_path = instance.file_upload.path
        capture = pyshark.FileCapture(file_path, keep_packets=False)

        csv_output = StringIO()
        json_data = []
        xml_root = ET.Element("Packets")
        text_output = ""
        ftp_objects = StringIO()
        ftp_writer = csv.writer(ftp_objects)
        ftp_writer.writerow(['Packet', 'Hostname', 'Content Type', 'Size', 'Filename'])
        http_objects = StringIO()
        http_writer = csv.writer(http_objects)
        http_writer.writerow(['No.', 'Source', 'Destination', 'Host', 'Path', 'Method', 'User-Agent'])
        tls_keys = ""
        protocol_stats = defaultdict(lambda: {'count': 0, 'size': 0})
        tcp_packets = []
        udp_packets = []

        csv_writer = csv.writer(csv_output)
        csv_writer.writerow(['No.', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])

        for packet in capture:
            try:
                # Common data processing
                packet_data = {
                    'number': packet.number,
                    'source': packet.ip.src if hasattr(packet, 'ip') else 'N/A',
                    'destination': packet.ip.dst if hasattr(packet, 'ip') else 'N/A',
                    'protocol': packet.highest_layer,
                    'length': packet.length,
                    'info': packet.info if hasattr(packet, 'info') else 'N/A',
                }
                protocol = packet_data['protocol']
                packet_size = int(packet_data['length'])

                # CSV and JSON generation
                csv_writer.writerow([packet_data['number'], packet_data['source'], packet_data['destination'], protocol, packet_data['length'], packet_data['info']])
                json_data.append(packet_data)

                # XML generation
                packet_element = ET.SubElement(xml_root, "Packet")
                for key, value in packet_data.items():
                    ET.SubElement(packet_element, key.capitalize()).text = str(value)

                # Plain text generation
                text_output += f"Packet Number: {packet_data['number']}\nSource: {packet_data['source']}\nDestination: {packet_data['destination']}\nProtocol: {protocol}\nLength: {packet_data['length']}\nInfo: {packet_data['info']}\n\n"

                # Protocol stats calculation
                protocol_stats[protocol]['count'] += 1
                protocol_stats[protocol]['size'] += packet_size

                # TCP and UDP packet processing
                if protocol == 'TCP':
                    tcp_packets.append(packet)
                elif protocol == 'UDP':
                    udp_packets.append(packet)

                # FTP and HTTP object generation
                if 'FTP-DATA' in packet:
                    ftp_writer.writerow([packet_data['number'], packet_data['destination'], 'FTP file', f"{packet_size} bytes", packet.ftp_data.split()[-1] if hasattr(packet, 'ftp_data') else 'Unknown'])

                if 'HTTP' in packet:
                    http_writer.writerow([packet_data['number'], packet_data['source'], packet_data['destination'], packet.http.host, packet.http.request_uri, packet.http.request_method, packet.http.user_agent])

                # TLS keys generation
                if 'TLS' in packet and hasattr(packet.tls, 'handshake_session_id'):
                    tls_keys += f"Session ID: {packet.tls.handshake_session_id}\n"
                    if hasattr(packet.tls, 'handshake_session_ticket'):
                        tls_keys += f"Session Ticket: {packet.tls.handshake_session_ticket}\n"

            except AttributeError:
                continue

        # Save generated files
        instance.csv_file.save(f"csv_{instance.id}.csv", ContentFile(csv_output.getvalue()))
        instance.json_file.save(f"json_{instance.id}.json", ContentFile(json.dumps(json_data, indent=4)))
        instance.xml_file.save(f"xml_{instance.id}.xml", ContentFile(ET.tostring(xml_root, encoding='unicode')))
        instance.text_file.save(f"text_{instance.id}.txt", ContentFile(text_output))
        
        if ftp_objects.getvalue():
            instance.ftp_data_file.save(f"ftp_{instance.id}.csv", ContentFile(ftp_objects.getvalue()))
        else:
            instance.ftp_data_file.save(f"ftp_{instance.id}.txt", ContentFile("Không có data ftp objects"))

        if http_objects.getvalue():
            instance.http_data_file.save(f"http_{instance.id}.csv", ContentFile(http_objects.getvalue()))
        else:
            instance.http_data_file.save(f"http_{instance.id}.txt", ContentFile("Không có data HTTP objects"))

        instance.tls_session_key.save(f"tls_{instance.id}.txt", ContentFile(tls_keys or "Không có TLS Session Key"))

        # Generate and save report
        generate_report(protocol_stats, len(json_data), sum(int(packet['length']) for packet in json_data), tcp_packets, udp_packets, instance)

        instance.status_completed = True
        instance.save()

        print(f"------------------DONE {pcap_id}----------------------")
