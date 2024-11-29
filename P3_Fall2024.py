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

    src_port, dst_port = struct.unpack("!HH", udp_header[:4])
    return src_port


def extract_icmp_from_icmp(ip_data, ihl):
    inner_ip_offset = ihl + 8
    inner_ip_data = ip_data[inner_ip_offset:]

    # Parse the inner IP header
    inner_version_ihl = inner_ip_data[0]
    inner_ihl = (inner_version_ihl & 0x0F) * 4

    inner_icmp_offset = inner_ihl
    inner_icmp_header = inner_ip_data[inner_icmp_offset:inner_icmp_offset + 8]

    _, _, _, identifier, sequence_number = struct.unpack("!BBHHH", inner_icmp_header)
    return sequence_number

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

            windows_trace = False

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

                timestamp = ts_sec + ts_usec * 1e-6

                # Record source and destination IPs
                if protocol == 17: #UDP packets aka probing packets
                    udp_header = ip_data[ihl:ihl + 8]
                    src_port, dst_port = struct.unpack("!HH", udp_header[:4])

                    if dst_port == 53 or src_port == 53:
                        continue
                    
                    if ttl == 1:
                        source_ip = src_ip
                        destination_ip = dst_ip
                        protocols.add(protocol)
                        windows_trace = False

                        if start_time == 0:
                            start_time = ts_sec + ts_usec * 1e-6

                    if dst_ip == destination_ip:
                        timestamp_data[src_port].append(timestamp)

                elif protocol == 1 and start_time == 0: #ICMP probing packets
                    protocols.add(protocol)
                    windows_trace = True
                    if source_ip is None and ttl == 1:
                        source_ip = src_ip
                        destination_ip = dst_ip

                        if start_time == 0:
                            start_time = ts_sec + ts_usec * 1e-6

                    icmp_header = ip_data[ihl: ihl + 8]
                    icmp_type, icmp_code, icmp_checksum, identifier, seq_num = struct.unpack("!BBHHH", icmp_header[:8])

                    if icmp_type == 8:
                        timestamp_data[seq_num].append(timestamp)

                elif protocol == 1 and (not start_time == 0): #ICMP returning packets
                    if not windows_trace:
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
                                rtt_data["dest"].append(rtt_time)
                    else:
                        icmp_header = ip_data[ihl: ihl + 8]
                        icmp_type, icmp_code, icmp_checksum, identifier, seq_num = struct.unpack("!BBHHH", icmp_header[:8])
                        
                        if icmp_type == 8:
                            if dst_ip == destination_ip:
                                timestamp_data[seq_num].append(timestamp)
                        elif icmp_type == 11:
                            inner_icmp_seq_num = extract_icmp_from_icmp(ip_data, ihl)
                            for time in timestamp_data[inner_icmp_seq_num]:
                                rtt_time = timestamp - time
                                rtt_data[src_ip].append(rtt_time)
                                
                            if src_ip not in intermediate_ips:
                                intermediate_ips.append(src_ip)
                        elif icmp_type == 0:
                            for time in timestamp_data[seq_num]:
                                rtt_time = timestamp - time
                                rtt_data["dest"].append(rtt_time)

                if more_fragments or fragment_offset > 0:
                    fragments[src_ip].append(fragment_offset)

                packet_no += 1

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

    dest_rtt = rtt_data.pop("dest", None)
    avg, std_dev = calculate_stats(dest_rtt)
    print(f"  The avg RTT between {source_ip} and ultimate destination node {destination_ip} is: {avg:.2f} ms, the s.d. is: {std_dev:.2f} ms\n")

    rtt_strings = []
    for ip, times in rtt_data.items():
        if times:
            avg, std_dev = calculate_stats(times)
            rtt_strings.append((ip, avg, std_dev))

    rtt_strings = sorted(rtt_strings, key=lambda x:x[1])
    for rtt in rtt_strings:
        print(f"  The avg RTT between {source_ip} and {rtt[0]} is: {rtt[1]:.2f} ms, the s.d. is: {rtt[2]:.2f} ms")

    rtt_data["dest"] = dest_rtt

    print("\nTTL per Probe")
    ttl = 1
    for ip, times in rtt_data.items():
        if ip:
            print(f"  ttl{ttl}: {len(times)}")
        
        ttl += 1

    print("\n Different for group 1, Same for group 2")

    print("""\n For group 1, the difference is that all traces from 1 to 4 go through 16 intermediate nodes, but trace 5 go through 15 intermediate nodes. 
          In addition, the intermediate nodes between traces 1 to 4 are different in that their orders are different as well.""")
    
    group2 = defaultdict(list)
    group2[1] = [3.33, 2.71, 7.85, 3.42, 1.75]
    group2[2] = [15.81, 17.12, 11.84, 13.24, 16.15]
    group2[3] = [18.87, 20.1, 22.58, 21.67, 21.6]
    group2[4] = [22.84, 19.42, 19.46, 19.75, 18.56]
    group2[5] = [26.5, 21.56, 20.32, 35.77, 20.72]
    group2[6] = [24.26, 19.98, 21.85, 22.67, 43.47]
    group2[7] = [18.41, 51.66, 22.76, 18.34, 26.92]
    group2[8] = [22.97, -224.26, 20.59, 24.57, 25.62]
    print("\n For group 2, the following table provides a comparison between the average RTT for each TTL")

    print("\nTTL    Avg RTT in 1    Avg RTT in 2    Avg RTT in 3    Avg RTT in 4    Avg RTT in 5")
    print("-------------------------------------------------------------------------------------")
    for rtt, traces in group2.items():
        print(f"{rtt}       {traces[0]}            {traces[1]}              {traces[2]}              {traces[3]}              {traces[4]}")
        print("-------------------------------------------------------------------------------------")

    print("\n Hop 7 is likely to incur the max delay because it has the highest values in rtt.")


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