"""
Simple Network Packet Sniffer
- Run as root/Administrator
- Works on Linux/macOS (AF_PACKET) and attempts a Windows capture using raw sockets
- Usage examples:
    sudo python3 sniffer.py
    sudo python3 sniffer.py --proto tcp --port 80 --pcap out.pcap
"""
import signal
import socket
import struct
import argparse
import os
import sys
import ctypes
from datetime import datetime

running = True

def signal_handler(signum, frame):
    global running
    print("\nStopping sniffer...")
    running = False

def parse_ethernet_header(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    return ':'.join(format(b, '02x') for b in bytes_addr)

def parse_ip_header(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 0x0F) * 4
    ttl, proto, src, target = struct.unpack('!8xBB2x4s4s', data[:20])
    return version, header_length, ttl, proto, socket.inet_ntoa(src), socket.inet_ntoa(target), data[header_length:]

def parse_tcp_header(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('!HHLLH', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dest_port, sequence, acknowledgment, offset, data[offset:]

def parse_udp_header(data):
    src_port, dest_port, size = struct.unpack('!HH2xH', data[:8])
    return src_port, dest_port, size, data[8:]

def write_pcap_global_header(pcap_file):
    pcap_file.write(struct.pack('@ I H H i I I I ',
                                0xa1b2c3d4,  # magic number
                                2,           # version major
                                4,           # version minor
                                0,           # thiszone
                                0,           # sigfigs
                                65535,       # snaplen
                                1))          # network (Ethernet)

def write_pcap_packet(pcap_file, packet_data):
    ts = datetime.now()
    ts_sec = int(ts.timestamp())
    ts_usec = int(ts.microsecond)
    incl_len = len(packet_data)
    orig_len = len(packet_data)
    pcap_file.write(struct.pack('@ I I I I',
                                ts_sec,
                                ts_usec,
                                incl_len,
                                orig_len))
    pcap_file.write(packet_data)

def main():
    # Check for administrator privileges
    if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
        print("This script requires administrator privileges. Please run as administrator.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Simple Network Packet Sniffer")
    parser.add_argument('--proto', type=str, help='Filter by protocol (tcp/udp/icmp)', default=None)
    parser.add_argument('--port', type=int, help='Filter by port number', default=None)
    parser.add_argument('--pcap', type=str, help='Output pcap file', default=None)
    args = parser.parse_args()

    try:
        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
            print("Created raw socket successfully")
            
            # On Windows, we need to set up promiscuous mode
            try:
                sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                print("Set IP_HDRINCL option successfully")
            except Exception as e:
                print(f"Failed to set IP_HDRINCL: {e}")
                sys.exit(1)

            # Bind to the host
            try:
                host = socket.gethostbyname(socket.gethostname())
                sniffer.bind((host, 0))
                print(f"Bound to interface: {host}")
            except Exception as e:
                print(f"Failed to bind: {e}")
                sys.exit(1)

            # Enable promiscuous mode
            try:
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                print("Enabled promiscuous mode successfully")
            except Exception as e:
                print(f"Failed to set promiscuous mode: {e}")
                print("Make sure you're running as Administrator.")
                sys.exit(1)
        else:
            socket_protocol = socket.ntohs(0x0003)
            sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket_protocol)
            try:
                sniffer.bind(('0.0.0.0', 0))
            except Exception as e:
                print(f"Socket could not be created. Error: {e}")
                sys.exit(1)
    except Exception as e:
        print(f"Failed to initialize sniffer: {e}")
        sys.exit(1) 

   

    pcap_file = None
    if args.pcap:
        pcap_file = open(args.pcap, 'wb')
        write_pcap_global_header(pcap_file)

    # Set up signal handler for graceful exit
    signal.signal(signal.SIGINT, signal_handler)
    print("Sniffer started... Press Ctrl+C to stop.")
    
    global running
    running = True
    
    try:
        while running:
            raw_data, addr = sniffer.recvfrom(65535)
            eth_dest, eth_src, eth_proto, data = parse_ethernet_header(raw_data)

            if eth_proto == 8:  # IP Packet
                version, header_length, ttl, proto, src_ip, dest_ip, data = parse_ip_header(data)

                if args.proto and ((args.proto.lower() == 'tcp' and proto != 6) or
                                   (args.proto.lower() == 'udp' and proto != 17) or
                                   (args.proto.lower() == 'icmp' and proto != 1)):
                    continue

                if proto == 6:  # TCP
                    src_port, dest_port, sequence, acknowledgment, offset, data = parse_tcp_header(data)
                    if args.port and src_port != args.port and dest_port != args.port:
                        continue
                    print(f"TCP Packet: {src_ip}:{src_port} -> {dest_ip}:{dest_port}")

                elif proto == 17:  # UDP
                    src_port, dest_port, size, data = parse_udp_header(data)
                    if args.port and src_port != args.port and dest_port != args.port:
                        continue
                    print(f"UDP Packet: {src_ip}:{src_port} -> {dest_ip}:{dest_port}")

                else:
                    print(f"Other IP Packet: {src_ip} -> {dest_ip} (Protocol: {proto})")
            else:
                print(f"Non-IP Packet: Ethertype {eth_proto}")
            if pcap_file:
                write_pcap_packet(pcap_file, raw_data)
    except KeyboardInterrupt:
        print("\nSniffer stopped.")
    finally:
        if pcap_file:
            pcap_file.close()
        sniffer.close()

if __name__ == "__main__":
    main()