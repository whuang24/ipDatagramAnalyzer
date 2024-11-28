import struct
import sys
from collections import defaultdict
import math

connections = {}

def extract_udp_from_icmp(ip_data, icmp_offset):
    original_ip_data_offset = icmp_offset + 8
    
    original_ip_header = ip_data[original_ip_data_offset:]
    original_version_ihl = original_ip_header[0]
    original_ihl = (original_version_ihl & 0x0F) * 4
    
    udp_offset = original_ip_data_offset + original_ihl
    udp_header = ip_data[udp_offset:udp_offset + 8]

    # Parse the UDP header
    src_port, dst_port = struct.unpack("!HH", udp_header[:4])
    return src_port

def analyze_traceroute(file_path):

    source_ip = None
    destination_ip = None
    intermediate_ips = []
    protocols = set()
    fragments = defaultdict(list)
    timestamp_data = defaultdict(list)
    rtt_data = defaultdict(list)

    def parse_pcap(file_path):
        nonlocal source_ip, destination_ip

        with open(file_path, 'rb') as f:

            # Obtaining global header and identifying big/small endianese
            global_header = f.read(24)

            magic_number = global_header[:4]

            if b'\xc3\xd4' in magic_number:
                ordering = ">"
            elif b'\xb2\xa1' in magic_number :
                ordering = "<"
            else:
                raise ValueError("Unsupported pcap format")
            
            start_time = 0

            packet_no = 1
            
            # Extract packets
            while True:
                packet_header = f.read(16)
                if not packet_header:
                    break

                if len(packet_header) < 16:
                    continue

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(ordering + 'IIII', packet_header)
                packet_data = f.read(incl_len)
                if len(packet_data) < incl_len:
                    continue


                ethernet_offset = 14
                ip_data = packet_data[ethernet_offset:]

                # Parse IP Header
                version_ihl = ip_data[0]
                ihl = (version_ihl & 0x0F) * 4
                ttl = ip_data[8]
                protocol = ip_data[9]
                src_ip = ".".join(map(str, ip_data[12:16]))
                dst_ip = ".".join(map(str, ip_data[16:20]))

                # Fragmentation flags and offset
                flags_offset = struct.unpack(ordering + 'H', ip_data[6:8])[0]
                more_fragments = (flags_offset & 0x2000) >> 13
                fragment_offset = (flags_offset & 0x1FFF) * 8

                # RTT (mock calculation based on timestamp)
                timestamp = ts_sec + ts_usec * 1e-6

                udp_header = ip_data[ihl:ihl + 8]
                src_port, dst_port = struct.unpack("!HH", udp_header[:4])

                # Record source and destination IPs
                
                if protocol == 17: #UDP packets aka probing packets
                    if source_ip is None and ttl == 1:
                        source_ip = src_ip
                        destination_ip = dst_ip

                        if start_time == 0:
                            start_time = ts_sec + ts_usec * 1e-6

                    if dst_ip == destination_ip:
                        timestamp_data[src_port].append(timestamp)

                elif protocol == 1 and (not start_time is None): #ICMP returning packets
                    icmp_type = ip_data[ihl]

                    icmp_src_port = extract_udp_from_icmp(ip_data, ihl)
                    if icmp_type == 11:
                        for time in timestamp_data[icmp_src_port]:
                            rtt_time = timestamp - time
                            rtt_data[src_ip].append(rtt_time)
                            
                        if src_ip not in intermediate_ips:
                            intermediate_ips.append(src_ip)

                    elif icmp_type == 3:
                        for time in timestamp_data[icmp_src_port]:
                            rtt_time = timestamp - time
                            rtt_data[src_ip].append(rtt_time)

                # Record protocols
                protocols.add(protocol)

                # Analyze fragmentation
                if more_fragments or fragment_offset > 0:
                    fragments[src_ip].append(fragment_offset)

    parse_pcap(file_path)

    # Post-process the data
    print(f"The IP address of the source node: {source_ip}")
    print(f"The IP address of the ultimate destination node: {destination_ip}")
    
    print("The IP addresses of intermediate destination nodes:")
    for idx, ip in enumerate(intermediate_ips):
        print(f"  router {idx + 1}: {ip},")

    print("\nThe values in the protocol field of IP headers:")
    for protocol in protocols:
        if protocol == 1:
            print(f"  {protocol}: ICMP")
        elif protocol == 17:
            print(f"  {protocol}: UDP")

    # Fragmentation analysis
    total_fragments = sum(len(offsets) for offsets in fragments.values())
    last_offset = max((max(offsets) for offsets in fragments.values()), default=0)
    print(f"\nThe number of fragments created from the original datagram is: {total_fragments}")
    print(f"The offset of the last fragment is: {last_offset}")

    # RTT statistics
    print("\nRound trip time statistics:")

    rtt_strings = []
    for ip, times in rtt_data.items():
        if times:
            avg, std_dev = calculate_stats(times)
            rtt_strings.append((ip, avg, std_dev))

    rtt_strings = sorted(rtt_strings, key=lambda x:x[1])
    for rtt in rtt_strings:
        print(f"  The avg RTT between {source_ip} and {rtt[0]} is: {rtt[1]:.2f} ms, the s.d. is: {rtt[2]:.2f} ms")

# Helper function to calculate RTT statistics
def calculate_stats(times):
    if not times:
        return 0, 0
    avg = sum(times) / len(times)
    variance = sum((x - avg) ** 2 for x in times) / len(times)
    return avg, math.sqrt(variance)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("No file supplied, please add a .cap file as input.")
        sys.exit(1)
        
    traceFile = sys.argv[1]
    analyze_traceroute(traceFile)