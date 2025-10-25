#!/usr/bin/env python3
"""
Network Packet Sniffer (kinda advanced)
---------------------------------------

This is my take on a multi-platform packet sniffer.  
It captures live packets, filters them, and (optionally) saves them into a PCAP file.  
Still a work in progress — especially the Windows socket bits.

I borrowed the general structure from a few sources but customized filtering & cleanup.

Features so far:
- Cross-platform (Linux/macOS/Windows... sort of)
- Protocol filtering (TCP, UDP, ICMP)
- IP & port filtering
- Can write PCAPs
- Promiscuous mode if supported
- Ctrl+C / 'exit' handling

TODO:
- Possibly add color output?
- Make interface selection less clunky.

Usage examples:
    sudo python3 sniffer.py
    sudo python3 sniffer.py --proto tcp --port 80 --pcap out.pcap
    sudo python3 sniffer.py --ip 192.168.1.100

Author: xytex-s
License: MIT
"""

import os
import sys
import socket
import struct
import signal
import argparse
import threading
from datetime import datetime
from dataclasses import dataclass
import psutil
import ctypes
import logging
from contextlib import contextmanager

# --- Logging setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("sniffer")

# --- Constants (I always forget these numbers) ---
PACKET_SIZE = 65535
ETH_HEADER_LEN = 14
IP_HEADER_LEN = 20
TCP_HEADER_LEN = 20
UDP_HEADER_LEN = 8

@dataclass
class PacketFilter:
    """Holds filtering options (protocol, port, ip)"""
    proto: str | None = None
    port: int | None = None
    ip: str | None = None

    def matches(self, proto_num: int, s_port: int, d_port: int, s_ip: str, d_ip: str) -> bool:
        """Check if current packet matches our filters."""
        proto_map = {'tcp': 6, 'udp': 17, 'icmp': 1}
        if self.proto:
            if proto_num != proto_map.get(self.proto.lower(), -1):
                return False

        if self.port and self.port not in (s_port, d_port):
            return False

        if self.ip and self.ip not in (s_ip, d_ip):
            return False

        return True


class SecurityError(Exception):
    """Used for privilege or permission problems."""
    pass


@contextmanager
def make_sniffer_socket(args):
    """
    Creates and configures a raw socket.
    I really should separate Windows and *nix code into different helpers,
    but keeping them inline for now.
    """
    sock = None
    try:
        if os.name == 'nt':
            if not ctypes.windll.shell32.IsUserAnAdmin():
                raise SecurityError("Need admin rights on Windows.")

            # Grab available interfaces
            from psutil import net_if_addrs
            ifaces = [(n, a.address)
                      for n, addrs in net_if_addrs().items()
                      for a in addrs if a.family == socket.AF_INET]
            if not ifaces:
                raise SecurityError("No active interfaces found!")

            chosen_ip = ifaces[0][1]  # lazy default
            logger.info(f"Using interface: {chosen_ip}")

            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((chosen_ip, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            logger.debug("Windows sniffer ready")

        else:
            # *nix case (Linux, macOS)
            if os.geteuid() != 0:
                raise SecurityError("Root privileges required for raw sockets.")
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            logger.debug("Sniffer socket created (AF_PACKET mode).")

        yield sock

    finally:
        if sock:
            try:
                if os.name == 'nt':
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                sock.close()
                logger.debug("Socket closed cleanly.")
            except Exception as e:
                logger.warning(f"Socket cleanup failed: {e}")
                
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def validate_ip(ip_str):
    try:
        parts = ip_str.split('.')
        return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
    except (AttributeError, TypeError, ValueError):
        return False

def get_mac_str(byte_addr: bytes) -> str:
    """Turns a MAC address (in bytes) into human-readable form."""
    return ':'.join(f"{b:02x}" for b in byte_addr)

def parse_ethernet_header(data):
    dest_mac = data[:6]
    src_mac = data[6:12]
    proto = data[12:14]
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), int.from_bytes(proto, 'big'), data[14:]

def parse_ether_header(data: bytes):
    """Parse the Ethernet part of the packet."""
    try:
        dest, src, proto = struct.unpack('!6s6sH', data[:ETH_HEADER_LEN])
        return get_mac_str(dest), get_mac_str(src), socket.htons(proto), data[ETH_HEADER_LEN:]
    except Exception as e:
        logger.warning(f"Ethernet parse failed: {e}")
        raise


def parse_ip_header(data: bytes):
    """Extract IP-level details. (Yeah, this one’s touchy about offsets.)"""
    if len(data) < IP_HEADER_LEN:
        raise ValueError("Too short for IP header")
    try:
        version_ihl = data[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4
        if ihl < IP_HEADER_LEN:
            raise ValueError("Invalid IP header length")
        ttl, proto, src, dst = struct.unpack('!8xBB2x4s4s', data[:IP_HEADER_LEN])
        return version, ihl, ttl, proto, socket.inet_ntoa(src), socket.inet_ntoa(dst), data[ihl:]
    except Exception as e:
        logger.debug(f"IP header parse problem: {e}")
        raise


def parse_tcp_header(data: bytes):
    """Parse TCP header. Note: assumes standard 20-byte base header."""
    if len(data) < TCP_HEADER_LEN:
        raise ValueError("TCP header too small")
    try:
        src_p, dst_p, seq, ack, flags = struct.unpack('!HHLLH', data[:TCP_HEADER_LEN])
        off = (flags >> 12) * 4
        return src_p, dst_p, seq, ack, off, data[off:]
    except Exception as e:
        logger.debug(f"TCP header parse error: {e}")
        raise


def parse_udp_header(data: bytes):
    """Simple UDP header parser (no checksum validation)."""
    if len(data) < UDP_HEADER_LEN:
        raise ValueError("UDP header too small")
    try:
        src_p, dst_p, length = struct.unpack('!HH2xH', data[:UDP_HEADER_LEN])
        if length < UDP_HEADER_LEN:
            raise ValueError(f"UDP length {length} too short")
        return src_p, dst_p, length, data[UDP_HEADER_LEN:length]
    except struct.error as e:
        logger.warning(f"UDP parse failed: {e}")
        raise


class PCAPWriter:
    """Super basic PCAP writer. Doesn’t handle truncation or endian weirdness."""

    def __init__(self, filename):
        self.filename = filename
        self.file = open(filename, 'wb')
        self._write_header()
        logger.info(f"Writing packets to {filename}")

    def _write_header(self):
        # Not proud of memorizing these constants...
        self.file.write(struct.pack('@ I H H i I I I',
            0xa1b2c3d4, 2, 4, 0, 0, PACKET_SIZE, 1))

    def write_packet(self, pkt):
        now = datetime.now()
        ts_sec, ts_usec = int(now.timestamp()), now.microsecond
        size = len(pkt)
        self.file.write(struct.pack('@ I I I I', ts_sec, ts_usec, size, size))
        self.file.write(pkt)

    def close(self):
        try:
            self.file.close()
        except Exception:
            pass
        logger.debug("Closed PCAP file cleanly.")


def get_interfaces():
    """List system interfaces — mostly for reference when selecting."""
    found = []
    for iface, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family == socket.AF_INET and not a.address.startswith('127.'):
                found.append((iface, a.address))
    if not found:
        raise SecurityError("No active network interfaces found.")
    return found


def parse_args():
    """Handle CLI arguments and a bit of validation."""
    ifaces = get_interfaces()
    print("\nAvailable interfaces:")
    for i, (iface, ip) in enumerate(ifaces, 1):
        print(f"  {i}. {iface} ({ip})")
    print()

    p = argparse.ArgumentParser(description="Network Sniffer")
    p.add_argument('--proto', help='Filter by protocol (tcp/udp/icmp)')
    p.add_argument('--port', type=int, help='Filter by port')
    p.add_argument('--ip', help='Filter by IP address')
    p.add_argument('--pcap', help='Output to PCAP file')
    p.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    p.add_argument('-i', '--interface', help='Interface name or number')

    args = p.parse_args()
    if args.ip:
        try:
            socket.inet_aton(args.ip)
        except socket.error:
            p.error("Invalid IP address format")

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    return args


def packet_summary(proto, src_ip, dst_ip, src_port=None, dst_port=None):
    """Tiny helper for readable output lines."""
    if src_port and dst_port:
        return f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} ({proto})"
    else:
        return f"{src_ip} -> {dst_ip} (proto={proto})"


def watch_for_exit(flag_list):
    """Thread that listens for 'exit' in stdin (I keep forgetting to stop otherwise)."""
    while flag_list[0]:
        try:
            cmd = input().strip().lower()
            if cmd == 'exit':
                logger.info("Exit command received.")
                flag_list[0] = False
        except EOFError:
            continue


def main():
    args = parse_args()
    filters = PacketFilter(args.proto, args.port, args.ip)
    writer = None
    running = [True]  # mutable reference hack

    if args.pcap:
        writer = PCAPWriter(args.pcap)

    signal.signal(signal.SIGINT, lambda s, f: running.__setitem__(0, False))

    # little background watcher for typing "exit"
    t = threading.Thread(target=watch_for_exit, args=(running,), daemon=True)
    t.start()

    try:
        with make_sniffer_socket(args) as sn:
            sn.settimeout(1.0)
            logger.info("Sniffer started... press Ctrl+C or type 'exit' to stop.")
            while running[0]:
                try:
                    data, addr = sn.recvfrom(PACKET_SIZE)
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Socket error: {e}")
                    break

                try:
                    if os.name != 'nt':
                        d_mac, s_mac, eth_proto, payload = parse_ether_header(data)
                        if eth_proto != 8:  # not IPv4
                            continue
                        version, ihl, ttl, proto, src_ip, dst_ip, ip_data = parse_ip_header(payload)
                    else:
                        version, ihl, ttl, proto, src_ip, dst_ip, ip_data = parse_ip_header(data)

                    # protocol logic
                    if proto == 6:  # TCP
                        s_port, d_port, *_ = parse_tcp_header(ip_data)
                        if filters.matches(proto, s_port, d_port, src_ip, dst_ip):
                            logger.info(packet_summary("TCP", src_ip, dst_ip, s_port, d_port))

                    elif proto == 17:  # UDP
                        s_port, d_port, _, _ = parse_udp_header(ip_data)
                        if filters.matches(proto, s_port, d_port, src_ip, dst_ip):
                            logger.info(packet_summary("UDP", src_ip, dst_ip, s_port, d_port))

                    else:
                        # Just log something for unknown protocols
                        if filters.matches(proto, 0, 0, src_ip, dst_ip):
                            logger.info(packet_summary(proto, src_ip, dst_ip))

                    if writer:
                        writer.write_packet(data)

                except Exception as e:
                    # Sometimes packets are malformed — just skip
                    logger.debug(f"Parse error: {e}")
                    continue

    except SecurityError as e:
        logger.error(f"Permission issue: {e}")
    except Exception as e:
        logger.exception("Unexpected failure:")
    finally:
        if writer:
            writer.close()
        logger.info("Sniffer stopped. Goodbye!")
        # uncomment next line if you want to pause window in console mode
        # input("Press Enter to exit...")


if __name__ == '__main__':
    logger.debug("Starting packet sniffer main()")
    main()
