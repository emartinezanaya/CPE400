from scapy.all import rdpcap, IP, IPv6
from collections import Counter

def extract_source_and_destination_addresses(file_path, laptop_ipv4, laptop_ipv6_temp):
    try:
        # Read the pcap file
        packets = rdpcap(file_path)

        # Extract source and destination IP addresses based on the laptop's IPv4 and IPv6 addresses
        src_addresses_ipv4 = [packet[IP].src
                              for packet in packets
                              if IP in packet and (
                                  packet[IP].dst == laptop_ipv4
                              )]

        src_addresses_ipv6 = [packet[IPv6].src
                              for packet in packets
                              if IPv6 in packet and (
                                  packet[IPv6].dst == laptop_ipv6_temp
                              )]

        dest_addresses_ipv4 = [packet[IP].dst
                               for packet in packets
                               if IP in packet and (
                                   packet[IP].src == laptop_ipv4
                               )]

        dest_addresses_ipv6 = [packet[IPv6].dst
                               for packet in packets
                               if IPv6 in packet and (
                                   packet[IPv6].src == laptop_ipv6_temp
                               )]

        return src_addresses_ipv4, src_addresses_ipv6, dest_addresses_ipv4, dest_addresses_ipv6

    except Exception as e:
        print(f"Error: {e}")
        return None, None, None, None

if __name__ == "__main__":
    # Specify the path to your pcap file
    pcap_file_path = "C:\\Users\\polar\\OneDrive\\Desktop\\CPE400_Final_Project\\Data\\MarvelSnap.pcap"

    # Specify the IPv4 and temporary IPv6 addresses of your laptop
    laptop_ipv4 = "10.141.133.79"
    laptop_ipv6_temp = "2605:ad80:fff0:b011:74f6:75d9:2b62:8e85"

    # Extract source and destination IP addresses for both IPv4 and IPv6
    src_addresses_ipv4, src_addresses_ipv6, dest_addresses_ipv4, dest_addresses_ipv6 = \
        extract_source_and_destination_addresses(pcap_file_path, laptop_ipv4, laptop_ipv6_temp)

    # Combine the source and destination addresses for both IPv4 and IPv6
    all_src_addresses = src_addresses_ipv4 + src_addresses_ipv6
    all_dest_addresses = dest_addresses_ipv4 + dest_addresses_ipv6

    # Count occurrences of each unique source and destination address for both IPv4 and IPv6 combined
    src_address_counts_all = Counter(all_src_addresses)
    dest_address_counts_all = Counter(all_dest_addresses)

    # Sort the source addresses and their counts by the highest count to the lowest count
    sorted_src_address_counts = sorted(src_address_counts_all.items(), key=lambda x: x[1], reverse=True)

    # Display the sorted counts of unique source addresses for both IPv4 and IPv6 combined
    print("\nSorted Source Address\tCount")
    for src_address, count in sorted_src_address_counts:
        print(f"{src_address}\t\t\t{count}")

    # Display the overall total number of source packets
    total_source_packets = len(all_src_addresses)
    print(f"\nOverall Total Source Packets: {total_source_packets}")

    # Sort the destination addresses and their counts by the highest count to the lowest count
    sorted_dest_address_counts = sorted(dest_address_counts_all.items(), key=lambda x: x[1], reverse=True)

    # Display the sorted counts of unique destination addresses for both IPv4 and IPv6 combined
    print("\n\n\nSorted Destination Address\tCount")
    for dest_address, count in sorted_dest_address_counts:
        print(f"{dest_address}\t\t\t{count}")

    # Display the overall total number of destination packets
    total_dest_packets = len(all_dest_addresses)
    print(f"\nOverall Total Destination Packets: {total_dest_packets}\n\n")

    # Write data to the file
    output_file_path = "C:\\Users\\polar\\OneDrive\\Desktop\\CPE400_Final_Project\\OutPut\\MarvelSnap_IPAddress_Data.txt"
    with open(output_file_path, 'w') as output_file:
        # Write source addresses
        output_file.write("Sorted Source Address\tCount\n")
        for src_address, count in sorted_src_address_counts:
            output_file.write(f"{src_address}\t\t\t{count}\n")

        # Write overall total number of source packets
        total_source_packets = len(all_src_addresses)
        output_file.write(f"\nOverall Total Source Packets: {total_source_packets}\n\n")

        # Sort the destination addresses and their counts by the highest count to the lowest count
        sorted_dest_address_counts = sorted(dest_address_counts_all.items(), key=lambda x: x[1], reverse=True)

        # Write destination addresses
        output_file.write("\n\nSorted Destination Address\tCount\n")
        for dest_address, count in sorted_dest_address_counts:
            output_file.write(f"{dest_address}\t\t\t{count}\n")

        # Write overall total number of destination packets
        total_dest_packets = len(all_dest_addresses)
        output_file.write(f"\nOverall Total Destination Packets: {total_dest_packets}\n\n")