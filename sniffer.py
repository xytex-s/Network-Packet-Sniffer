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
        
    Raises:
        ValueError: If data is too small or header format is invalid
    """
    if len(data) < IP_HEADER_LENGTH:
        raise ValueError(f"IP header too small: {len(data)} bytes")
        
    try:
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 0x0F) * 4
        
        # Validate header length
        if header_length < IP_HEADER_LENGTH or len(data) < header_length:
            raise ValueError(f"Invalid IP header length: {header_length}")
            
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
        
    Raises:
        ValueError: If data is too small or header format is invalid
    """
    if len(data) < TCP_HEADER_LENGTH:
        raise ValueError(f"TCP header too small: {len(data)} bytes")
        
    try:
        src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = (
            struct.unpack('!HHLLH', data[:TCP_HEADER_LENGTH])
        )
        offset = (offset_reserved_flags >> 12) * 4
        
        # Validate offset size
        if offset < TCP_HEADER_LENGTH or len(data) < offset:
            raise ValueError(f"Invalid TCP header length: {offset}")
            
        return src_port, dest_port, sequence, acknowledgment, offset, data[offset:]
    except struct.error as e:
        raise ValueError(f"Invalid TCP header format: {e}")

def analyze_packet_content(data: bytes) -> str:
    """
    Analyze packet content to identify protocol and packet type.
    """
    # Check for common protocol signatures
    if len(data) >= 2:
        # Look at first few bytes for protocol identification
        first_bytes = data[:4] if len(data) >= 4 else data
        hex_bytes = ' '.join(f'{b:02x}' for b in first_bytes)
        
        # Common protocol signatures
        if data[:2] == b'\xff\xff':
            return f"Broadcast packet (0xFFFF header), first bytes: {hex_bytes}"
        elif data[:2] == b'\x08\x00':
            return f"IPv4 packet, first bytes: {hex_bytes}"
        elif data[:2] == b'\x08\x06':
            return f"ARP packet, first bytes: {hex_bytes}"
        elif data[:2] == b'\x86\xdd':
            return f"IPv6 packet, first bytes: {hex_bytes}"
        elif data[:2] == b'\x80\x35':
            return f"RARP packet, first bytes: {hex_bytes}"
    
    # If no specific protocol identified, return generic info
    return f"Unknown protocol, first bytes: {' '.join(f'{b:02x}' for b in data[:8])}"

def parse_udp_header(data: bytes) -> Tuple[int, int, int, bytes]:
    """
    Parse UDP datagram header.
    
    Args:
        data: UDP datagram data
        
    Returns:
        Tuple containing source port, destination port, size, and remaining data
        
    Raises:
        ValueError: If data is too small or header format is invalid
    """
    if len(data) < UDP_HEADER_LENGTH:
        raise ValueError(f"UDP header too small: {len(data)} bytes")
        
    try:
        src_port, dest_port, length = struct.unpack('!HH2xH', data[:UDP_HEADER_LENGTH])
        
        # If we get a large length, try to analyze the packet content
        if length > 65507:  # Max UDP datagram size (65535 - 20 IP header - 8 UDP header)
            analysis = analyze_packet_content(data)
            raise ValueError(f"Large packet detected ({length} bytes): {analysis}")
            
        # UDP length field includes the header (8 bytes) plus data
        if length < UDP_HEADER_LENGTH:
            raise ValueError(f"UDP length too small: {length} bytes")
        if length > len(data):
            raise ValueError(f"UDP length ({length}) larger than received data ({len(data)} bytes)")
            
        return src_port, dest_port, length, data[UDP_HEADER_LENGTH:length]
    except struct.error as e:
        # Try to analyze the content if we can't parse it as UDP
        analysis = analyze_packet_content(data)
        raise ValueError(f"Not a UDP packet: {analysis}")

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
    
    logger.debug("Retrieving network interfaces...")
    try:
        # Get all network interfaces using psutil
        interfaces = psutil.net_if_addrs()
        logger.debug(f"Found {len(interfaces)} total interfaces")
        
        for iface, addrs in interfaces.items():
            logger.debug(f"Checking interface: {iface}")
            for addr in addrs:
                # Get only IPv4 addresses that are active
                if (addr.family == socket.AF_INET and 
                    not addr.address.startswith('127.') and  # Skip loopback
                    not addr.address.startswith('169.254.')):  # Skip link-local
                    try:
                        # Try to create a test socket to verify the interface is usable
                        test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        test_socket.bind((addr.address, 0))
                        test_socket.close()
                        
                        logger.debug(f"Found valid interface: {iface} ({addr.address})")
                        valid_ips.append((iface, addr.address))
                    except socket.error:
                        logger.debug(f"Interface {iface} ({addr.address}) is not usable")
                        continue
        
        if not valid_ips:
            logger.error("No usable network interfaces found")
            logger.error("Please ensure at least one network interface is connected and has a valid IP address")
            raise SecurityError("No usable network interfaces found")
            
        logger.debug(f"Found {len(valid_ips)} valid interfaces")
        return sorted(valid_ips)
    except Exception as e:
        logger.exception("Error retrieving network interfaces:")
        raise

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
                    if os.name == 'nt':  # Windows
                        # Windows raw sockets receive packets directly
                        # First try to analyze it as a raw packet
                        analysis = analyze_packet_content(raw_data)
                        
                        try:
                            version, header_length, ttl, proto, src_ip, dest_ip, data = parse_ip_header(raw_data)
                            
                            if proto == 6:  # TCP
                                try:
                                    src_port, dest_port, sequence, acknowledgment, offset, data = parse_tcp_header(data)
                                    if packet_filter.matches(proto, src_port, dest_port, src_ip, dest_ip):
                                        logger.info(f"TCP: {src_ip}:{src_port} -> {dest_ip}:{dest_port}")
                                except ValueError as e:
                                    logger.info(f"Non-standard TCP packet from {src_ip}: {e}")
                                    continue
                                    
                            elif proto == 17:  # UDP
                                try:
                                    src_port, dest_port, size, data = parse_udp_header(data)
                                    if packet_filter.matches(proto, src_port, dest_port, src_ip, dest_ip):
                                        logger.info(f"UDP: {src_ip}:{src_port} -> {dest_ip}:{dest_port}")
                                except ValueError as e:
                                    logger.info(f"Non-standard UDP packet from {src_ip}: {e}")
                                    continue
                                    
                            elif packet_filter.matches(proto, 0, 0, src_ip, dest_ip):
                                logger.info(f"Other IP: {src_ip} -> {dest_ip} (Protocol: {proto})")
                                
                        except ValueError as e:
                            # If we can't parse it as IP, log the raw packet analysis
                            logger.info(f"Non-IP packet: {analysis}")
                            if len(raw_data) >= 14:  # Minimum size for useful hex dump
                                hex_dump = ' '.join(f'{b:02x}' for b in raw_data[:14])
                                logger.debug(f"Packet hex dump (first 14 bytes): {hex_dump}")
                            continue
                    else:
                        # Unix-like systems parse Ethernet frame first
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
    try:
        # Set up logging to file in addition to console
        file_handler = logging.FileHandler('sniffer_debug.log')
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        logger.debug("Starting sniffer...")
        main()
    except Exception as e:
        logger.exception("Fatal error occurred:")
        # Keep window open to read error
        input("Press Enter to exit...")