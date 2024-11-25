import struct

class IP_Header:
    src_ip = None #<type 'str'>
    dst_ip = None #<type 'str'>
    ip_header_len = None #<type 'int'>
    total_len = None    #<type 'int'>
    
    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0
    
    def ip_set(self,src_ip,dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
    
    def header_len_set(self,length):
        self.ip_header_len = length
    
    def total_len_set(self, length):
        self.total_len = length    
        
    def get_IP(self,buffer1,buffer2):
        src_addr = struct.unpack('BBBB',buffer1)
        dst_addr = struct.unpack('BBBB',buffer2)
        s_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
        d_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])
        self.ip_set(s_ip, d_ip)
        
    def get_header_len(self,value):
        result = struct.unpack('B', value)[0]
        length = (result & 15)*4
        self.header_len_set(length)

    def get_total_len(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.total_len_set(length)
 
class TCP_Header:
    src_port = 0
    dst_port = 0
    seq_num = 0
    ack_num = 0
    data_offset = 0
    flags = {}
    window_size =0
    checksum = 0
    ugp = 0
    
    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.data_offset = 0
        self.flags = {}
        self.window_size =0
        self.checksum = 0
        self.ugp = 0
    
    def src_port_set(self, src):
        self.src_port = src
        
    def dst_port_set(self,dst):
        self.dst_port = dst
        
    def seq_num_set(self,seq):
        self.seq_num = seq
        
    def ack_num_set(self,ack):
        self.ack_num = ack
        
    def data_offset_set(self,data_offset):
        self.data_offset = data_offset
        
    def flags_set(self,ack, rst, syn, fin):
        self.flags["ACK"] = ack
        self.flags["RST"] = rst
        self.flags["SYN"] = syn
        self.flags["FIN"] = fin
    
    def win_size_set(self,size):
        self.window_size = size
        
    def get_src_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.src_port_set(port)
        #print(self.src_port)
        return None
    
    def get_dst_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.dst_port_set(port)
        #print(self.dst_port)
        return None
    
    def get_seq_num(self,buffer):
        seq = struct.unpack(">I",buffer)[0]
        self.seq_num_set(seq)
        #print(seq)
        return None
    
    def get_ack_num(self,buffer):
        ack = struct.unpack('>I',buffer)[0]
        self.ack_num_set(ack)
        return None
    
    def get_flags(self,buffer):
        value = struct.unpack("B",buffer)[0]
        fin = value & 1
        syn = (value & 2)>>1
        rst = (value & 4)>>2
        ack = (value & 16)>>4
        self.flags_set(ack, rst, syn, fin)
        return None
    def get_window_size(self,buffer1,buffer2):
        buffer = buffer2+buffer1
        size = struct.unpack('H',buffer)[0]
        self.win_size_set(size)
        return None
        
    def get_data_offset(self,buffer):
        value = struct.unpack("B",buffer)[0]
        length = ((value & 240)>>4)*4
        self.data_offset_set(length)
        #print(self.data_offset)
        return None
    
    def relative_seq_num(self,orig_num):
        if(self.seq_num>=orig_num):
            relative_seq = self.seq_num - orig_num
            self.seq_num_set(relative_seq)
        #print(self.seq_num)
        
    def relative_ack_num(self,orig_num):
        if(self.ack_num>=orig_num):
            relative_ack = self.ack_num-orig_num+1
            self.ack_num_set(relative_ack)
   

class Packet_Data():
    
    #pcap_hd_info = None
    IP_header = None
    TCP_header = None
    timestamp = 0
    packet_No = 0
    RTT_value = 0
    RTT_flag = False
    buffer = None
    tcp_segment = 0
    
    
    def __init__(self):
        self.IP_header = IP_Header()
        self.TCP_header = TCP_Header()
        #self.pcap_hd_info = pcap_ph_info()
        self.timestamp = 0
        self.packet_No =0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None
        self.tcp_segment = 0
        
    def timestamp_set(self,buffer1,buffer2,orig_time):
        seconds = struct.unpack('I',buffer1)[0]
        microseconds = struct.unpack('<I',buffer2)[0]
        self.timestamp = round(seconds+microseconds*0.000001-orig_time,6)
        #print(self.timestamp,self.packet_No)
    def packet_No_set(self,number):
        self.packet_No = number
        #print(self.packet_No)
        
    def get_RTT_value(self,p):
        rtt = p.timestamp-self.timestamp
        self.RTT_value = round(rtt,8)

    def get_TCP_segment(self, segment):
        self.tcp_segment = segment


class Connection:
    
    
    def __init__(self, pkt):
        self.src_ip = pkt.IP_header.src_ip
        self.dst_ip = pkt.IP_header.dst_ip
        self.src_port = pkt.TCP_header.src_port
        self.dst_port = pkt.TCP_header.dst_port
        self.start_time = pkt.timestamp
        self.end_time = pkt.timestamp
        self.packets_src_to_dst = 0
        self.packets_dst_to_src = 0
        self.data_src_to_dst = 0
        self.data_dst_to_src = 0
        self.syn_count = 0
        self.fin_count = 0
        self.rst_flag = False
        self.is_preestablished = not pkt.TCP_header.flags["SYN"]
        self.packets = []
        self.rtts = []
        self.windows = []

    def record_packet(self, pkt):
        src_ip = pkt.IP_header.src_ip
        dst_ip = pkt.IP_header.dst_ip

        self.end_time = pkt.timestamp

        if pkt.TCP_header.flags["SYN"]:
            self.syn_count += 1
            
        if pkt.TCP_header.flags["FIN"]:
            self.fin_count += 1

        if self.rst_flag != True:
            self.rst_flag = pkt.TCP_header.flags["RST"]

        if src_ip == self.src_ip and dst_ip == self.dst_ip:
            self.packets_src_to_dst += 1
            self.data_src_to_dst += pkt.tcp_segment
        elif src_ip == self.dst_ip and dst_ip == self.src_ip:
            self.packets_dst_to_src += 1
            self.data_dst_to_src += pkt.tcp_segment

        if pkt.TCP_header.flags["ACK"]:
            for packet in self.packets:
                if (packet.TCP_header.seq_num + packet.tcp_segment) == pkt.TCP_header.ack_num:
                    packet.get_RTT_value(pkt)
                    self.rtts.append(packet.RTT_value)
                    break

        self.packets.append(pkt)

        self.windows.append(pkt.TCP_header.window_size)

        


    def generate_report(self, conn_id):
        if self.rst_flag:
            status = "S" + str(self.syn_count) + "F" + str(self.fin_count) + "/R"
        else:
            status = "S" + str(self.syn_count) + "F" + str(self.fin_count)

        if self.fin_count == 0:
            return ("Connection " + str(conn_id) + ":\n" +
                        "Source Address: " + str(self.src_ip) + "\n" +
                        "Destination Address: " + str(self.dst_ip) + "\n" +
                        "Source Port: " + str(self.src_port) + "\n" +
                        "Destination Port: " + str(self.dst_port) + "\n" +
                        "Status: " + str(status) + "\n" +
                        "++++++++++++++++++++++++++++++++")
        else:
            duration = round(self.end_time - self.start_time, 6)
            total_packets = self.packets_src_to_dst + self.packets_dst_to_src
            total_data = self.data_src_to_dst + self.data_dst_to_src
            return ("Connection " + str(conn_id) + ":\n"
                    "Source Address: " + str(self.src_ip) + "\n"
                    "Destination Address: " + str(self.dst_ip) + "\n"
                    "Source Port: " + str(self.src_port) + "\n"
                    "Destination Port: " + str(self.dst_port) + "\n"
                    "Status: " + str(status) + "\n"
                    "Start Time: " + str(self.start_time) + "\n"
                    "End Time: " + str(self.end_time) + "\n"
                    "Duration: " + str(duration) + " seconds\n"
                    "Number of packets sent from Source to Destination: " + str(self.packets_src_to_dst) + "\n"
                    "Number of packets sent from Destination to Source: " + str(self.packets_dst_to_src) + "\n"
                    "Total number of packets: " + str(total_packets) + "\n"
                    "Number of data bytes sent from Source to Destination: " + str(self.data_src_to_dst) + "\n"
                    "Number of data bytes sent from Destination to Source: " + str(self.data_dst_to_src) + "\n"
                    "Total number of data bytes: " + str(total_data) + "\nEND\n"
                    "++++++++++++++++++++++++++++++++")
            