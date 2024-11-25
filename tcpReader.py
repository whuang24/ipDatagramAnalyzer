import struct
import sys
from packet_struct import IP_Header, TCP_Header, Packet_Data, Connection

connections = {}

# Helper function to parse pcap file headers
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
        
        packet_no = 0
        start_time = 0
        
        # Extract packets
        while True:
            # Reads the packet header, and ends checking if the packet_header does not exist
            packet_header = f.read(16)
            if not packet_header:
                break

            # Skips over incomplete packet header if it is incomplete
            if len(packet_header) < 16:
                continue
            
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(ordering + 'IIII', packet_header)

            # Reads the packet data
            packet_data = f.read(incl_len)
            if len(packet_data) < incl_len:
                continue

            if start_time == 0:
                start_time = ts_sec + ts_usec * 1e-6

            pkt = Packet_Data()
            pkt.buffer = packet_data
            pkt.packet_No_set(packet_no)
            pkt.timestamp_set(struct.pack('I', ts_sec), struct.pack('I', ts_usec), start_time)

            ethernet_offset = 14

            ip_data = packet_data[ethernet_offset:]

            # Reads the IP header
            ip_header = IP_Header()
            ip_header.get_IP(ip_data[12:16], ip_data[16:20])
            ip_header.get_header_len(bytes([ip_data[0] & 0x0F]))

            ip_header_offset = ip_header.ip_header_len

            tcp_data = packet_data[(ethernet_offset + ip_header_offset):]

            # Reads the TCP header
            tcp_header = TCP_Header()
            tcp_header.get_src_port(tcp_data[0:2])
            tcp_header.get_dst_port(tcp_data[2:4])
            tcp_header.get_seq_num(tcp_data[4:8])
            tcp_header.get_ack_num(tcp_data[8:12])
            tcp_header.get_data_offset(tcp_data[12:13])
            tcp_header.get_flags(tcp_data[13:14])
            tcp_header.get_window_size(tcp_data[14:15], tcp_data[15:16])

            pkt.IP_header = ip_header
            pkt.TCP_header = tcp_header

            source_ip = ip_header.src_ip
            dest_ip = ip_header.dst_ip

            source_port = tcp_header.src_port
            dest_port = tcp_header.dst_port

            data_offset = tcp_header.data_offset
            
            tcp_segment_len = incl_len - (14 + ip_header.ip_header_len + data_offset)

            pkt.get_TCP_segment(tcp_segment_len)

            if (source_ip, source_port) < (dest_ip, dest_port):
                connection_id = ((source_ip, source_port), (dest_ip, dest_port))
            else:
                connection_id = ((dest_ip, dest_port), (source_ip, source_port))

            if connection_id not in connections:
                connections[connection_id] = Connection(pkt)

            connection = connections[connection_id]
            connection.record_packet(pkt)

            packet_no += 1

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("No file supplied, please add a .cap file as input.")
        sys.exit(1)
        
    capFile = sys.argv[1]
    packets = parse_pcap(capFile)

    complete_connections = 0
    reset_connections = 0
    unclosed_connections = 0
    preestablished_connections = 0

    time_durations = []

    rtt_values = []

    number_of_packets = []

    window_sizes = []

    separator = "________________________________________________\n"

    print("A) Total number of connections: " + str(len(connections)))
    print(separator)
    print("B) Connection's details\n")

    for i, (conn_id, connection) in enumerate(connections.items(), 1):
        if connection.rst_flag:
            reset_connections += 1
        
        if connection.is_preestablished:
            preestablished_connections += 1
        
        if connection.fin_count == 0:
            unclosed_connections += 1
        else:
            complete_connections += 1
            time_durations.append(round(connection.end_time - connection.start_time, 6))

            rtt_values.extend(connection.rtts)
            
            number_of_packets.append(len(connection.packets))

            window_sizes.extend(connection.windows)

        print(connection.generate_report(i))

    print(separator)
    print("C) General\n")
    print("Number of reset TCP connections: " + str(reset_connections))
    print("Number of TCP connections that were still open when the trace capture ended: " + str(unclosed_connections))
    print("Number of TCP connections that were established before the trace capture started: " + str(preestablished_connections))
    print("Total number of complete TCP connections: " + str(complete_connections))
    print(separator)
    print("D) Complete TCP connections")
    print("Minimum time duration: " + str(min(time_durations)) + " seconds\n" +
          "Mean time duration: " + str(sum(time_durations)/len(time_durations)) + " seconds\n" +
          "Maximum time duration: " + str(max(time_durations)) + "seconds\n\n" +
          "Minimum RTT value: " + str(min(rtt_values)) + "\n" +
          "Mean RTT value: " + str(sum(rtt_values)/len(rtt_values)) + "\n" +
          "Maximum RTT value: " + str(max(rtt_values)) + "\n\n" +
          "Minimum number of packets including both send/received: " + str(min(number_of_packets)) + "\n" +
          "Mean number of packets including both send/received: " + str(sum(number_of_packets)/len(number_of_packets)) + "\n" +
          "Maximum number of packets including both send/received: " + str(max(number_of_packets)) + "\n\n" +
          "Minimum receive window size including both send/received: " + str(min(window_sizes)) + " bytes\n" +
          "Mean receive window size including both send/received: " + str(sum(window_sizes)/len(window_sizes)) + " bytes\n" +
          "Maximum receive window size including both send/received: " + str(max(window_sizes)) + " bytes")
    print(separator)




