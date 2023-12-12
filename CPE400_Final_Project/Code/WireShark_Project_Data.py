from scapy.all import rdpcap, IP, IPv6, TCP, UDP, DNS
from collections import Counter

def extract_tcp_events(file_path, laptop_ipv4, laptop_ipv6_temp):
    try:
        # Read the pcap file
        packets = rdpcap(file_path)

        # Extract TCP events and packet types
        tcp_events = Counter()
        packet_types = Counter()
        dns_queries = Counter()

        for packet in packets:
            if IP in packet and (packet[IP].src == laptop_ipv4 or packet[IP].dst == laptop_ipv4 or
                                 packet[IP].src == laptop_ipv6_temp or packet[IP].dst == laptop_ipv6_temp):

                if TCP in packet:
                    tcp_flags = packet[TCP].flags
                    tcp_events["Dup ACK"] += 1 if tcp_flags & 0x10 != 0 else 0
                    tcp_events["TCP Out of Order"] += 1 if tcp_flags & 0x04 != 0 else 0
                    tcp_events["TCP Previous Segment Not Captured"] += 1 if tcp_flags & 0x20 != 0 else 0
                    tcp_events["Application Data"] += 1 if packet[TCP].payload else 0
                    tcp_events["PSH Packet"] += 1 if tcp_flags & 0x08 != 0 else 0

                    if packet[TCP].sport == 80 or packet[TCP].dport == 80:
                        packet_types["HTTP Packet"] += 1

                    if packet[TCP].flags & 0x02 != 0:
                        packet_types["SYN Request Packet"] += 1

                    if packet[TCP].flags & 0x12 == 0x12:
                        packet_types["SYN-ACK Packet"] += 1

                    if packet[TCP].flags & 0x11 == 0x11:
                        packet_types["FIN-ACK Packet"] += 1

                    if packet[TCP].payload and "ClientKeyExchange" in str(packet[TCP].payload):
                        packet_types["Client Key Exchange"] += 1

                    if packet[TCP].payload and "ChangeCipherSpec" in str(packet[TCP].payload):
                        packet_types["Change Cipher Spec"] += 1

                    if packet[TCP].payload and "EncryptedHandshakeMessage" in str(packet[TCP].payload):
                        packet_types["Encrypted Handshake Message"] += 1

                    if packet[TCP].payload and "ProtectedPayload" in str(packet[TCP].payload):
                        packet_types["Protected Payload"] += 1

                elif UDP in packet and DNS in packet:
                    # Check if it's a DNS query (QR=0)
                    dns_flags = packet[DNS].qr
                    if dns_flags == 0:
                        dns_queries["DNS Query"] += 1

        return tcp_events, packet_types, dns_queries

    except Exception as e:
        print(f"Error during packet extraction: {e}")
        return None, None, None

def extract_packet_info(file_path, laptop_ipv4, laptop_ipv6_temp):
    try:
        # Read the pcap file
        packets = rdpcap(file_path)

        # Extract packet information including source and destination IP addresses, protocol, length, timestamps, and packet number
        data_ipv4 = [(packet[IP].src, packet[IP].dst, packet[IP].proto,
                      packet.sport if TCP in packet else packet.dport if UDP in packet else None,
                      packet.dport if TCP in packet else packet.sport if UDP in packet else None,
                      packet.seq if TCP in packet and hasattr(packet, 'seq') else None,
                      packet.ack if TCP in packet and hasattr(packet, 'ack') else None,
                      len(packet),
                      packet.time, i)
                     for i, packet in enumerate(packets)
                     if IP in packet and (packet[IP].src == laptop_ipv4 or packet[IP].dst == laptop_ipv4 or
                                           packet[IP].src == laptop_ipv6_temp or packet[IP].dst == laptop_ipv6_temp)]
        
        data_ipv6 = [(packet[IPv6].src, packet[IPv6].dst, packet[IPv6].nh,
                      packet.sport if TCP in packet else packet.dport if UDP in packet else None,
                      packet.dport if TCP in packet else packet.sport if UDP in packet else None,
                      packet.seq if TCP in packet and hasattr(packet, 'seq') else None,
                      packet.ack if TCP in packet and hasattr(packet, 'ack') else None,
                      len(packet),
                      packet.time, i)
                     for i, packet in enumerate(packets)
                     if IPv6 in packet and (packet[IPv6].src == laptop_ipv6_temp or packet[IPv6].dst == laptop_ipv6_temp or
                                            packet[IPv6].src == laptop_ipv4 or packet[IPv6].dst == laptop_ipv4)]

        # Combine IPv4 and IPv6 data
        data = data_ipv4 + data_ipv6

        # Sort the data by packet number
        data.sort(key=lambda x: x[9])

        # Calculate time since the reference frame (first frame)
        time_since_reference = [timestamp - data[0][8] for _, _, _, _, _, _, _, _, timestamp, _ in data]

        # Identify responses and acknowledgments
        response_ack_info = []
        for i in range(1, len(data)):
            if data[i][5] is not None and data[i - 1][5] is not None and data[i][5] > data[i - 1][5]:
                response_ack_info.append((data[i - 1][9] + 1, data[i][9] + 1, "Response"))
            if data[i][6] is not None and data[i - 1][5] is not None and data[i][6] > data[i - 1][5]:
                response_ack_info.append((data[i - 1][9] + 1, data[i][9] + 1, "Acknowledgment"))

        return list(zip(data, time_since_reference)), response_ack_info

    except Exception as e:
        print(f"Error during packet extraction: {e}")
        return None, None

def protocol_name(protocol_num):
    protocol_names = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        58: "ICMPv6",
        # Add more protocols as needed
    }
    return protocol_names.get(protocol_num, f"Unknown ({protocol_num})")

if __name__ == "__main__":
    # Specify the path to your pcap file
    pcap_file_path = "C:\\Users\\polar\\OneDrive\\Desktop\\CPE400_Final_Project\\Data\\MarvelSnap.pcap"

    # Specify the IPv4 and temporary IPv6 addresses of your laptop
    laptop_ipv4 = "10.141.133.79"
    laptop_ipv6_temp = "2605:ad80:fff0:b011:74f6:75d9:2b62:8e85"

    # Extract packet information including source and destination IP addresses, protocol, length, time since the reference frame, and packet number
    packet_info, response_ack_info = extract_packet_info(pcap_file_path, laptop_ipv4, laptop_ipv6_temp)

    # Display packet information
    if packet_info is not None:
        print("\nPacket Info:")
        print("Source IP\tDestination IP\tProtocol\tSrc Port\tDst Port\tSeq Number\tAck Number\tLength\tPacket Number\tTime since reference frame:")
        total_length = 0
        protocol_counts = Counter()  # To store counts for each unique protocol name

        for (src_ip, dst_ip, protocol, src_port, dst_port, seq_num, ack_num, length, timestamp, packet_no), time_diff in packet_info:
            total_length += length
            protocol_name_str = protocol_name(protocol)
            protocol_counts[protocol_name_str] += 1  # Increment the count for the protocol name
            print(f"{src_ip}\t\t{dst_ip}\t\t{protocol_name_str}\t\t{src_port}\t\t{dst_port}\t\t{seq_num}\t\t{ack_num}\t\t{length}\t\t{packet_no + 1}\t\t{time_diff}")

        # Display response and acknowledgment information
        print("\nResponse and Acknowledgment Information:")
        for start_packet, end_packet, info_type in response_ack_info:
            print(f"Packet {start_packet} to Packet {end_packet}: {info_type}")

        print(f"\nPacket info:")

        # Count and print the total rows of data
        total_rows = len(packet_info)
        print(f"\nTotal Rows of Data: {total_rows}")

        # Calculate and print the average length of packets
        average_length = total_length / total_rows if total_rows > 0 else 0
        print(f"\nAverage Length of Packets: {average_length:.2f} bytes")

        # Count and print the number of acknowledgments and requests
        num_acknowledgments = sum(1 for _, _, info_type in response_ack_info if info_type == "Acknowledgment")
        num_requests = total_rows - num_acknowledgments
        print(f"\nNumber of Acknowledgments: {num_acknowledgments}")
        print(f"Number of Requests: {num_requests}")

        print(f"\nUnique Protocol Names:")
        for protocol_name_str, count in protocol_counts.items():
            print(f"{protocol_name_str}: {count}")

        # Extract TCP events, packet types, and DNS queries
        tcp_events, packet_types, dns_queries = extract_tcp_events(pcap_file_path, laptop_ipv4, laptop_ipv6_temp)

        # Display TCP events
        print("\nTCP Events:")
        for event, count in tcp_events.items():
            print(f"{event}: {count}")

        # Display packet types
        print("\nPacket Types:")
        for packet_type, count in packet_types.items():
            print(f"{packet_type}: {count}")

        # Display DNS queries
        print("\nDNS Queries:")
        for dns_query, count in dns_queries.items():
            print(f"{dns_query}: {count}")

        # Specify the output file path
        output_file_path = "C:\\Users\\polar\\OneDrive\\Desktop\\CPE400_Final_Project\\OutPut\\MarvelSnap_Data.txt"

        # Write the information to the file
        with open(output_file_path, 'w') as output_file:
            # Write packet information
            output_file.write("\nPacket Info:\n")
            output_file.write("Source IP\tDestination IP\tProtocol\tSrc Port\tDst Port\tSeq Number\tAck Number\tLength\tPacket Number\tTime since reference frame:\n")
            total_length = 0
            for (src_ip, dst_ip, protocol, src_port, dst_port, seq_num, ack_num, length, timestamp, packet_no), time_diff in packet_info:
                total_length += length
                protocol_name_str = protocol_name(protocol)
                output_file.write(f"{src_ip}\t\t{dst_ip}\t\t{protocol_name_str}\t\t{src_port}\t\t{dst_port}\t\t{seq_num}\t\t{ack_num}\t\t{length}\t\t{packet_no + 1}\t\t{time_diff}\n")

            # Write response and acknowledgment information
            output_file.write("\nResponse and Acknowledgment Information:\n")
            for start_packet, end_packet, info_type in response_ack_info:
                output_file.write(f"Packet {start_packet} to Packet {end_packet}: {info_type}\n")

            # Write packet info summary
            output_file.write(f"\nPacket info:\n")
            output_file.write(f"Total Rows of Data: {len(packet_info)}\n")
            average_length = total_length / len(packet_info) if len(packet_info) > 0 else 0
            output_file.write(f"Average Length of Packets: {average_length:.2f} bytes\n")
            num_acknowledgments = sum(1 for _, _, info_type in response_ack_info if info_type == "Acknowledgment")
            num_requests = len(packet_info) - num_acknowledgments
            output_file.write(f"Number of Acknowledgments: {num_acknowledgments}\n")
            output_file.write(f"Number of Requests: {num_requests}\n")

            # Write TCP events
            output_file.write("\nTCP Events:\n")
            for event, count in tcp_events.items():
                output_file.write(f"{event}: {count}\n")

            # Write packet types
            output_file.write("\nPacket Types:\n")
            for packet_type, count in packet_types.items():
                output_file.write(f"{packet_type}: {count}\n")

            # Write DNS queries
            output_file.write("\nDNS Queries:\n")
            for dns_query, count in dns_queries.items():
                output_file.write(f"{dns_query}: {count}\n")