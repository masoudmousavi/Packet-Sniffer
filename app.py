from socket import socket, AF_PACKET, SOCK_RAW, ntohs
from struct import unpack, pack
from time import time

class pcap_file:
    def __init__(self, file_name):
        self.file = open(f'{file_name}.pcap', 'wb')
        self.file.write(pack('@ I H H i I I I', 0xfacdb837, 2, 4, 0, 0, 65535, 1))

    def write(self, data):
        time_sec, time_usec = map(int, str(time()).split('.'))
        data_length = len(data)
        self.file.write(pack('@ I I I I', time_sec, time_usec, data_length, data_length))
        self.file.write(data)

    def Close(self):
        self.file.close()


class Ethernet:
    def __init__(self, data):
        self.frame = self.parse_ethernet_frame(data) # 0: destination_MAC_address, 1: source_MAC_address, 2: Ether_type, 3: frame_payload
        self.raw_data = data

    def parse_ethernet_frame(self, data):
        destination_MAC_address, source_MAC_address, Ether_type = unpack('! 6s 6s H', data[:14])
        return destination_MAC_address, source_MAC_address, Ether_type, data[14:]

    def print(self):
        print('Ethernet Frame:')
        print(f'\t-Destination: {self.format_MAC_address(self.frame[0])} -Source: {self.format_MAC_address(self.frame[1])} -Protocol: {self.frame[2]}')

    def format_MAC_address(self, MAC_address):
        formatted_address = map('{:02x}'.format, MAC_address)
        return ':'.join(formatted_address).upper()

    def Ether_type_is_IPv4(self):
        return self.frame[2] == 2048 # 0x0800 EtherType value for IPv4

    def Ether_type_is_ARP(self):
        return self.frame[2] == 2054 # 0x0806 EtherType value for ARP

class IPv4:
    def __init__(self, data):
        self.datagram = self.parse_ipv4_datagram(data) # 0: version, 1: IHL, 2: DSCP, 3: ECN, 4: total_length, 5: identification, 6: DF, 7: MF, 8: offset, 9: TTL, 10: Protocol,  11: checksum, 12: source_IP_address, 13: destination_IP_address, 14: datagram_payload
        self.raw_data = data

    def parse_ipv4_datagram(self, data):
        version_and_ihl, DSCP_and_ECN, total_length, identification, flags_and_fragment_offset, TTL, Protocol, checksum, source_IP_address, destination_IP_address = unpack('! B B H H H B B H 4s 4s', data[:20])
        version = version_and_ihl >> 4
        IHL = (version_and_ihl & 15) * 4 #Internet Header Length is the low_order 4 bits and determines the number of 32-bit fields
        DSCP = DSCP_and_ECN >> 2
        ECN = (DSCP_and_ECN & 0x03)
        DF = (flags_and_fragment_offset & 0x4000) << 14
        MF = (flags_and_fragment_offset & 0x2000) << 13
        offset = (flags_and_fragment_offset & 0x1FFF) * 8
        return version, IHL, DSCP, ECN, total_length, identification, DF, MF, offset, TTL, Protocol, checksum, source_IP_address, destination_IP_address, data[IHL:]

    def print(self):
        print("IPv4 Datagram:")
        print(f'\t-Version: {self.datagram[0]} -Header Length: {self.datagram[1]} -DSCP: {self.datagram[2]} -ECN: {self.datagram[3]} -Total Length: {self.datagram[4]} ')
        print(f'\t-Identification: {self.datagram[5]} -DF: {self.datagram[6]} -MF: {self.datagram[7]} -Offset: {self.datagram[8]} -TTL: {self.datagram[9]} -Protocol: {self.datagram[10]}')
        print(f'\t-Checksum: {self.datagram[11]} -Source Address: {self.format_IP_address(self.datagram[12])} -Destination Address: {self.format_IP_address(self.datagram[13])}')

    def format_IP_address(self, IP_address):
        formatted_address = '.'.join(map(str ,IP_address))
        return formatted_address

    def protocol_is_UDP(self):
        return self.datagram[10] == 17 # 0x11 IP protocol number for UDP

    def protocol_is_TCP(self):
        return self.datagram[10] == 6 # 0x06 IP protocol number for TCP

    def protocol_is_ICMP(self):
        return self.datagram[10] == 1 # 0x01 IP protocol number for ICMP

class UDP:
    def __init__(self, data):
        self.segment = self.parse_udp_segment(data) # 0: source_port_number, 1: destination_port_number, 2: length, 3: checksum, 4: segment_payload
        self.raw_data = data

    def parse_udp_segment(self, data):
        source_port_number, destination_port_number, length, checksum = unpack('! H H H H', data[:8])
        return source_port_number, destination_port_number, length, checksum, data[8:]

    def print(self):
        print('UDP Segment:')
        print(f'\t-Source Port: {self.segment[0]}, -Destination Port : {self.segment[1]} -Length: {self.segment[2]} -Checksum: {self.segment[3]}')

    def is_DNS(self):
        return self.segment[0] == 53 or self.segment[1] == 53 #port number for DNS protocol

class DNS:
    def __init__(self, data):
        self.message = self.parse_dns_message(data) # 0: identification, 1: QR, 2: OPCODE, 3: AA, 4: TC, 5: RD, 6: RA, 7: Z, 8: RCODE, 9: number_of_questions, 10: number_of_answer_RRs, 11: number_of_authority_RRs, 12: number_of_additional_RRs
        self.raw_data = data

    def parse_dns_message(self, data):
        identification, flags, number_of_questions, number_of_answer_RRs, number_of_authority_RRs, number_of_additional_RRs = unpack('! H H H H H H', data[:12])
        # flags
        QR = flags >> 15  # last bit
        OPCODE = (flags & 0x7800) >> 11  # The type can be QUERY (standard query, 0), IQUERY (inverse query, 1), or STATUS (server status request, 2)
        AA = (flags & 0x0400) >> 10  # Authoritative Answer, in a response, indicates if the DNS server is authoritative for the queried hostname
        TC = (flags & 0x0200) >> 9  # TrunCation, indicates that this message was truncated due to excessive length
        RD = (flags & 0x0100) >> 8  # Recursion Desired, indicates if the client means a recursive query
        RA = (flags & 0x0080) >> 7  # Recursion Available, in a response, indicates if the replying DNS server supports recursion
        Z = (flags & 0x0070) >> 4  # Zero, reserved for future use
        RCODE = flags & 0x000F  # Response code, can be NOERROR (0), FORMERR (1, Format error), SERVFAIL (2), NXDOMAIN (3, Nonexistent domain), etc.

        return identification, QR, OPCODE, AA, TC, RD, RA, Z, RCODE, number_of_questions, number_of_answer_RRs, number_of_authority_RRs, number_of_additional_RRs

    def print(self):
        print('DNS Message:')
        print(f'\t-Identification: {self.message[0]} -QR: {self.message[1]} -OPCODE: {self.message[2]} -AA: {self.message[3]} -TC: {self.message[4]} -RD: {self.message[5]} -RA:{self.message[6]} -Z: {self.message[7]} -RCODE: {self.message[8]}')
        print(f'\t-Number of Questions: {self.message[9]} -Number of Answer RRs: {self.message[10]}')
        print(f'\t-Number of authority RRs: {self.message[11]} -Number of Additional RRs: {self.message[12]}')

class TCP:
    def __init__(self, data):
        self.segment = self.parse_tcp_segment(data) # 0: source_port_number, 1: destination_port_number, 2: sequence_number, 3: acknowledgement_number, 4: data_offset, 5: NS, 6: CWR, 7: ECE, 8: URG, 9: ACK, 10: PSH, 11: RST, 12: SYN, 13: FIN, 14: window_size, 15: checksum, 16: urgent_pointer, 17: payload
        self.raw_data =data

    def parse_tcp_segment(self, data):
        source_port_number, destination_port_number, sequence_number, acknowledgement_number, offset_and_flags, window_size, checksum, urgent_pointer = unpack('! H H L L H H H H', data[:20])
        data_offset = (offset_and_flags >> 12)
        NS = (offset_and_flags & 0x100) >> 8
        CWR = (offset_and_flags & 0x80) >> 7
        ECE = (offset_and_flags & 0x40) >> 6
        URG = (offset_and_flags & 0x20) >> 5
        ACK = (offset_and_flags & 0x10) >> 4
        PSH = (offset_and_flags & 0x8) >> 3
        RST = (offset_and_flags & 0x4) >> 2
        SYN = (offset_and_flags & 0x2) >> 1
        FIN = (offset_and_flags & 0x1)
        payload = data[data_offset * 4:] if len(data) > data_offset else None
        return source_port_number, destination_port_number, sequence_number, acknowledgement_number, data_offset, NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN, window_size, checksum, urgent_pointer, payload

    def print(self):
        print('TCP Segment:')
        print(f'\t-Source Port: {self.segment[0]} -Destination Port: {self.segment[1]} -Sequence Number: {self.segment[2]} -Acknowledge Number; {self.segment[3]}')
        print(f'\t-Data Offset: {self.segment[4]} -NS: {self.segment[5]} -CWR: {self.segment[6]} -ECE: {self.segment[7]} -URG: {self.segment[8]} -ACK: {self.segment[9]} -PSH: {self.segment[10]} -RST: {self.segment[11]} -SYN: {self.segment[12]} -FIN: {self.segment[13]}')
        print(f'\t-Window Size: {self.segment[14]} -Checksum: {self.segment[15]} -Urgent Pointer: {self.segment[16]}')

    def is_DNS(self):
        return self.segment[0] == 53 or self.segment[1] == 53 #port number for DNS protocol

    def is_HTTP(self):
        return self.segment[0] == 80 or self.segment[1] == 80  # port number for HTTP protocol

class HTTP:
    def __init__(self, data):
        self.message_header = self.parse_http_message(data)
        self.raw_data = data

    def parse_http_message(self, data):
        header_delimiter_index = data.rfind(b'\r\n')
        header_string = str(data[:header_delimiter_index], "ascii")
        return header_string

    def print(self):
        print('HTTP Message:')
        first_line_delimiter_index = self.message_header.find('\r\n')
        print(f'\t{self.message_header[:first_line_delimiter_index]}')
        for line in self.message_header.split('\r\n')[1:-1]:
            print(f'\t-{line}')

class ICMP:
    def __init__(self, data):
        self.packet = self.parse_icmp_packet(data) # 0: type, 1: code, 2: checksum, 3: data
        self.raw_data = data

    def parse_icmp_packet(self, data):
        type, code, checksum = unpack('! B B H', data[:4])
        return type, code, checksum, data[4:]

    def print(self):
        print('ICMP Packet:')
        print(f'\t-Type: {self.packet[0]} -Code: {self.packet[1]} -Checksum: {self.packet[2]}')

class ARP:
    def __init__(self, data):
        self.packet = self.parse_arp_packet(data) # 0: hardware_type, 1: protocol_type, 2: hardware_address_length, 3: protocol_address_length, 4: operation, 5: sender_hardware_address, 6: sender_protocl_address, 7: target_hardware_address, 8: target_protocol_address
        self.raw_data = data

    def parse_arp_packet(self, data):
        hardware_type, protocol_type, hardware_address_length, protocol_address_length, operation, sender_hardware_address, sender_protocl_address, target_hardware_address, target_protocol_address = unpack('! H H B B H 6s 4s 6s 4s', data[:28])
        return  hardware_type, protocol_type, hardware_address_length, protocol_address_length, operation, sender_hardware_address, sender_protocl_address, target_hardware_address, target_protocol_address

    def print(self):
        print('ARP Packet:')
        print(f'\t-Hardware Type: {self.packet[0]} -Protocol Type: {self.packet[1]} -Hardware Address Length: {self.packet[2]} -Protocol Address Length: {self.packet[3]} -Opedration: {self.packet[4]}')
        print(f'\t-Sender MAC Address: {self.format_MAC_address(self.packet[5])} -Sender IP Address: {self.format_IP_address(self.packet[6])} -Target MAC Address: {self.format_MAC_address(self.packet[7])} -Target IP Address: {self.format_IP_address(self.packet[8])}')


    def format_IP_address(self, IP_address):
        formatted_address = '.'.join(map(str ,IP_address))
        return formatted_address

    def format_MAC_address(self, MAC_address):
        formatted_address = map('{:02x}'.format, MAC_address)
        return ':'.join(formatted_address).upper()

def capture():
    file_name = input('Enter .pcap file name: ')
    capturing_socket = socket(AF_PACKET, SOCK_RAW, ntohs(3))
    number_of_packets = 0
    try:
        saving_file = pcap_file(file_name)
        while True:
            raw_data, address = capturing_socket.recvfrom(65535)
            saving_file.write(raw_data)
            number_of_packets += 1
            print(f"Packet {number_of_packets}:")
            Ethernet_packet = Ethernet(raw_data)
            Ethernet_packet.print()
            Ethernet_frame_payload = Ethernet_packet.frame[-1]
            # different protocols: IPv4, ARP
            if Ethernet_packet.Ether_type_is_IPv4():
                IP_packet = IPv4(Ethernet_frame_payload)
                IP_packet.print()
                IP_datagram_payload = IP_packet.datagram[-1]
                #different protocols: UDP, TCP, ICMP
                if IP_packet.protocol_is_UDP():
                    UDP_packet = UDP(IP_datagram_payload)
                    UDP_packet.print()
                    UDP_segment_payload = UDP_packet.segment[-1]
                    if UDP_segment_payload: #There is an application
                        if UDP_packet.is_DNS():
                            DNS_packet = DNS(UDP_segment_payload)
                            DNS_packet.print()
                        else:
                            print("Unknown Application Layer Protocol")

                elif IP_packet.protocol_is_TCP():
                    TCP_packet = TCP(IP_datagram_payload)
                    TCP_packet.print()
                    TCP_segment_payload = TCP_packet.segment[-1]
                    if TCP_segment_payload: #There is an application
                        if TCP_packet.is_DNS():
                            DNS_packet = DNS(TCP_segment_payload)
                            DNS_packet.print()
                        elif TCP_packet.is_HTTP():
                            HTTP_packet = HTTP(TCP_segment_payload)
                            HTTP_packet.print()
                        else:
                            print("Unknown Application Layer Protocol")

                elif IP_packet.protocol_is_ICMP():
                    ICMP_packet = ICMP(IP_datagram_payload)
                    ICMP_packet.print()

            elif Ethernet_packet.Ether_type_is_ARP():
                ARP_packet = ARP(Ethernet_frame_payload)
                ARP_packet.print()

            else:
                print("Unknown Ethertype")
            print('~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~MASOUD MOUSAVI~.~.~.~.~.~.~..~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~')
    except KeyboardInterrupt:
            print('Capturing was stopped')
            saving_file.Close()
            print(f'File {file_name}.pcap was saved')

capture()




