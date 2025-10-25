#!/usr/bin/env python3
"""
Advanced Network Packet Sniffer
------------------------------

A robust network packet sniffer that captures and analyzes network traffic in real-time.
Supports packet filtering, PCAP file output, and cross-platform operation.

Features:
- Cross-platform support (Linux/macOS/Windows)
- Protocol filtering (TCP/UDP/ICMP)
- Port filtering
- IP address filtering
- PCAP file output
- Promiscuous mode support
- Graceful shutdown handling

Security features:
- Privilege validation
- Input validation
- Error handling
- Resource cleanup

Usage examples:
    sudo python3 sniffer.py
    sudo python3 sniffer.py --proto tcp --port 80 --pcap out.pcap
    sudo python3 sniffer.py --ip 192.168.1.100

Author: xytex-s
License: MIT
"""

import argparse
import ctypes
import logging
import os
import psutil
import signal
import socket
import struct
import sys
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Tuple, Union, BinaryIO

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Constants
PACKET_SIZE = 65535
ETHERNET_HEADER_LENGTH = 14
IP_HEADER_LENGTH = 20
TCP_HEADER_LENGTH = 20
UDP_HEADER_LENGTH = 8

@dataclass
class PacketFilter:
    """Configuration for packet filtering."""
    protocol: Optional[str] = None
    port: Optional[int] = None
    ip: Optional[str] = None

    def matches(self, proto: int, src_port: int, dest_port: int, src_ip: str, dest_ip: str) -> bool:
        """Check if a packet matches the filter criteria."""
        if self.protocol:
            proto_map = {'tcp': 6, 'udp': 17, 'icmp': 1}
            if proto != proto_map.get(self.protocol.lower()):
                return False
        
        if self.port and src_port != self.port and dest_port != self.port:
            return False
            
        if self.ip and src_ip != self.ip and dest_ip != self.ip:
            return False
            
        return True

class SecurityError(Exception):
    """Custom exception for security-related errors."""
    pass

@contextmanager
def create_sniffer_socket(args: argparse.Namespace):
    """
    Create and configure a raw socket for packet sniffing.
    
    Args:
        args: Command line arguments
        
    Yields:
        socket.socket: Configured raw socket for packet sniffing
        
    Raises:
        SecurityError: If privileges are insufficient
        OSError: If socket creation fails
    """
    sniffer = None
    try:
        if os.name == 'nt':  # Windows
            if not ctypes.windll.shell32.IsUserAnAdmin():
                raise SecurityError("Administrator privileges required on Windows")
            
            valid_ips = get_network_interfaces()
            
            if not valid_ips:
                raise SecurityError("No valid network interfaces found")
            
            # Select interface based on command line argument
            if args.interface:
                # Try to match by interface name first
                matching_interfaces = [
                    (iface, ip) for iface, ip in valid_ips 
                    if iface.lower() == args.interface.lower()
                ]
                
                if not matching_interfaces:
                    # Try by number
                    try:
                        index = int(args.interface) - 1
                        if 0 <= index < len(valid_ips):
                            matching_interfaces = [valid_ips[index]]
                    except ValueError:
                        pass
                
                if not matching_interfaces:
                    raise SecurityError(
                        f"Interface '{args.interface}' not found. "
                        "Use one of the listed interface names or numbers."
                    )
                
                host = matching_interfaces[0][1]
            else:
                # Use first non-loopback interface by default
                host = valid_ips[0][1]
                
            logger.info(f"Using interface with IP: {host}")
            logger.info(f"Using interface: {host}")
            
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sniffer.bind((host, 0))
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            logger.info(f"Windows sniffer bound to interface: {host}")
            
        else:  # Unix-like systems
            if os.geteuid() != 0:
                raise SecurityError("Root privileges required on Unix-like systems")
                
            sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sniffer.bind(('0.0.0.0', 0))
            logger.info("Unix-like sniffer initialized in promiscuous mode")
            
        yield sniffer
        
    except socket.error as e:
        raise OSError(f"Failed to create raw socket: {e}")
        
    finally:
        if sniffer:
            try:
                if os.name == 'nt':
                    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                sniffer.close()
            except Exception as e:
                logger.error(f"Error during socket cleanup: {e}")

def parse_ethernet_header(data: bytes) -> Tuple[str, str, int, bytes]:
    """
    Parse Ethernet frame header.
    
    Args:
        data: Raw packet data
        
    Returns:
        Tuple containing destination MAC, source MAC, protocol, and remaining data
    """
    try:
        dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:ETHERNET_HEADER_LENGTH])
        return (
            get_mac_addr(dest_mac),
            get_mac_addr(src_mac),
            socket.htons(proto),
            data[ETHERNET_HEADER_LENGTH:]
        )
    except struct.error as e:
        raise ValueError(f"Invalid Ethernet header format: {e}")

def get_mac_addr(bytes_addr: bytes) -> str:
    """Convert bytes to MAC address string."""
    return ':'.join(format(b, '02x') for b in bytes_addr)

def parse_ip_header(data: bytes) -> Tuple[int, int, int, int, str, str, bytes]:
    """
    Parse IP packet header.
    
    Args:
        data: IP packet data
        
    Returns:
        Tuple containing version, header length, TTL, protocol, source IP,
        destination IP, and remaining data
    """
    try:
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 0x0F) * 4
        ttl, proto, src, target = struct.unpack('!8xBB2x4s4s', data[:IP_HEADER_LENGTH])
        return (
            version,
            header_length,
            ttl,
            proto,
            socket.inet_ntoa(src),
            socket.inet_ntoa(target),
            data[header_length:]
        )
    except (struct.error, IndexError) as e:
        raise ValueError(f"Invalid IP header format: {e}")

def parse_tcp_header(data: bytes) -> Tuple[int, int, int, int, int, bytes]:
    """
    Parse TCP segment header.
    
    Args:
        data: TCP segment data
        
    Returns:
        Tuple containing source port, destination port, sequence number,
        acknowledgment number, header length, and remaining data
    """
    try:
        src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = (
            struct.unpack('!HHLLH', data[:TCP_HEADER_LENGTH])
        )
        offset = (offset_reserved_flags >> 12) * 4
        return src_port, dest_port, sequence, acknowledgment, offset, data[offset:]
    except struct.error as e:
        raise ValueError(f"Invalid TCP header format: {e}")

def parse_udp_header(data: bytes) -> Tuple[int, int, int, bytes]:
    """
    Parse UDP datagram header.
    
    Args:
        data: UDP datagram data
        
    Returns:
        Tuple containing source port, destination port, size, and remaining data
    """
    try:
        src_port, dest_port, size = struct.unpack('!HH2xH', data[:UDP_HEADER_LENGTH])
        return src_port, dest_port, size, data[UDP_HEADER_LENGTH:]
    except struct.error as e:
        raise ValueError(f"Invalid UDP header format: {e}")

class PCAPWriter:
    """Handle PCAP file writing operations."""
    
    def __init__(self, filename: str):
        """Initialize PCAP writer with output file."""
        self.file = open(filename, 'wb')
        self._write_global_header()
        
    def _write_global_header(self):
        """Write PCAP file global header."""
        self.file.write(struct.pack('@ I H H i I I I',
            0xa1b2c3d4,  # magic number
            2,           # version major
            4,           # version minor
            0,           # thiszone
            0,           # sigfigs
            PACKET_SIZE, # snaplen
            1))         # network (Ethernet)
            
    def write_packet(self, packet_data: bytes):
        """Write a packet to the PCAP file."""
        ts = datetime.now()
        ts_sec = int(ts.timestamp())
        ts_usec = int(ts.microsecond)
        length = len(packet_data)
        
        self.file.write(struct.pack('@ I I I I',
            ts_sec,
            ts_usec,
            length,
            length))
        self.file.write(packet_data)
        
    def close(self):
        """Close the PCAP file."""
        if self.file:
            self.file.close()

def validate_ip(ip: str) -> bool:
    """
    Validate IP address format.
    
    Args:
        ip: IP address string
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def get_network_interfaces() -> list:
    """Get list of available network interfaces."""
    valid_ips = []
    
    # Get all network interfaces using psutil
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            # Get only IPv4 addresses
            if addr.family == socket.AF_INET:
                ip = addr.address
                if not ip.startswith('127.'):  # Skip loopback
                    valid_ips.append((iface, ip))
    
    return sorted(valid_ips)

def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    interfaces = get_network_interfaces()
    
    parser = argparse.ArgumentParser(description="Advanced Network Packet Sniffer")
    parser.add_argument('--proto', type=str, help='Filter by protocol (tcp/udp/icmp)')
    parser.add_argument('--port', type=int, help='Filter by port number')
    parser.add_argument('--pcap', type=str, help='Output pcap file')
    parser.add_argument('--ip', type=str, help='Filter by IP address')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--interface', '-i', type=str,
                      help='Network interface to use for capture. Use interface name or number from the list.')
    
    # Print available interfaces before parsing
    print("\nAvailable network interfaces:")
    for i, (iface, ip) in enumerate(interfaces, 1):
        print(f"{i}. {iface}: {ip}")
    print()
    
    args = parser.parse_args()
    
    if args.ip and not validate_ip(args.ip):
        parser.error(f"Invalid IP address format: {args.ip}")
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    return args

def check_for_exit(running: list) -> None:
    """Thread function to check for 'exit' command."""
    while running[0]:
        try:
            if input().strip().lower() == 'exit':
                logger.info("\nExit command received. Stopping sniffer...")
                running[0] = False
                break
        except EOFError:
            # This can happen when running with redirected input
            continue

def main():
    """Main program entry point."""
    args = parse_args()
    packet_filter = PacketFilter(args.proto, args.port, args.ip)
    pcap_writer = None
    running = [True]  # Using list for mutable state across threads

    def signal_handler(signum, frame):
        running[0] = False
        logger.info("\nStopping sniffer...")

    signal.signal(signal.SIGINT, signal_handler)
    
    # Start thread to check for exit command
    exit_thread = threading.Thread(target=check_for_exit, args=(running,), daemon=True)
    exit_thread.start()
    
    try:
        if args.pcap:
            pcap_writer = PCAPWriter(args.pcap)
            
        with create_sniffer_socket(args) as sniffer:
            logger.info("Sniffer started... Type 'exit' or press Ctrl+C to stop.")
            
            # Set a timeout so we can check the running flag
            sniffer.settimeout(1.0)
            
            while running[0]:
                try:
                    raw_data, addr = sniffer.recvfrom(PACKET_SIZE)
                except socket.timeout:
                    continue
                except socket.error as e:
                    logger.error(f"Socket error: {e}")
                    break
                    
                try:
                    eth_dest, eth_src, eth_proto, data = parse_ethernet_header(raw_data)
                    
                    if eth_proto == 8:  # IP
                        version, header_length, ttl, proto, src_ip, dest_ip, data = parse_ip_header(data)
                        
                        if proto == 6:  # TCP
                            src_port, dest_port, sequence, acknowledgment, offset, data = parse_tcp_header(data)
                            if packet_filter.matches(proto, src_port, dest_port, src_ip, dest_ip):
                                logger.info(f"TCP: {src_ip}:{src_port} -> {dest_ip}:{dest_port}")
                                
                        elif proto == 17:  # UDP
                            src_port, dest_port, size, data = parse_udp_header(data)
                            if packet_filter.matches(proto, src_port, dest_port, src_ip, dest_ip):
                                logger.info(f"UDP: {src_ip}:{src_port} -> {dest_ip}:{dest_port}")
                                
                        elif packet_filter.matches(proto, 0, 0, src_ip, dest_ip):
                            logger.info(f"Other IP: {src_ip} -> {dest_ip} (Protocol: {proto})")
                            
                    else:
                        logger.debug(f"Non-IP Packet: Ethertype {eth_proto}")
                        
                    if pcap_writer:
                        pcap_writer.write_packet(raw_data)
                        
                except (ValueError, struct.error) as e:
                    logger.error(f"Error parsing packet: {e}")
                    continue
                    
    except SecurityError as e:
        logger.error(f"Security Error: {e}")
        sys.exit(1)
        
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)
        
    finally:
        if pcap_writer:
            pcap_writer.close()
        logger.info("Sniffer stopped.")

if __name__ == "__main__":
    main()