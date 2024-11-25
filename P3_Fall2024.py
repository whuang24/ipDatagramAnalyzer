import struct
import sys
from packet_struct import IP_Header, TCP_Header, Packet_Data, Connection
from collections import defaultdict
import math

connections = {}

def analyze_traceroute(file_path):

    source_ip = None
    destination_ip = None
    intermediate_ips = defaultdict(list)
    protocols = set()
    fragments = defaultdict(list)
    rtt_data = defaultdict(list)

    def parse_pcap(file_path):
        with open(file_path, 'rb') as f:

            # Obtaining global header and identifying big/small endianese
            global_header = f.read(24)

            magic_number = global_header[:4]

            if magic_number == b'\xa1\xb2\xc3\xd4':
                ordering = ">"
            elif magic_number == b'\xd4\xc3\xb2\xa1':
                ordering = "<"
            else:
                raise ValueError("Unsupported pcap format")
            
            start_time = 0
            
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

                    if start_time == 0:
                        start_time = ts_sec + ts_usec * 1e-6

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
                    rtt = timestamp - start_time

                    # Record source and destination IPs
                    if source_ip is None:
                        source_ip = src_ip
                    destination_ip = dst_ip

                    # Record intermediate nodes based on TTL
                    if src_ip != source_ip and src_ip != destination_ip:
                        intermediate_ips[ttl].append(src_ip)

                    # Record protocols
                    protocols.add(protocol)

                    # Analyze fragmentation
                    if more_fragments or fragment_offset > 0:
                        fragments[src_ip].append(fragment_offset)

                    # Record RTTs
                    rtt_data[dst_ip].append(rtt)

    parse_pcap(file_path)

    # Post-process the data
    print(f"The IP address of the source node: {source_ip}")
    print(f"The IP address of the ultimate destination node: {destination_ip}")
    
    print("The IP addresses of intermediate destination nodes:")
    for hop_count, ips in sorted(intermediate_ips.items()):
        for idx, ip in enumerate(sorted(ips)):
            print(f"  router {hop_count}-{idx + 1}: {ip}")

    print("\nThe values in the protocol field of IP headers:")
    for protocol in protocols:
        print(f"  {protocol}: {protocol}")

    # Fragmentation analysis
    total_fragments = sum(len(offsets) for offsets in fragments.values())
    last_offset = max((max(offsets) for offsets in fragments.values()), default=0)
    print(f"\nThe number of fragments created from the original datagram is: {total_fragments}")
    print(f"The offset of the last fragment is: {last_offset}")

    # RTT statistics
    print("\nRound trip time statistics:")
    for ip, times in rtt_data.items():
        avg, std_dev = calculate_stats(times)
        print(f"  The avg RTT between {source_ip} and {ip} is: {avg:.2f} ms, the s.d. is: {std_dev:.2f} ms")

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