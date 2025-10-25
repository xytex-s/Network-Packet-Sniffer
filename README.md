# Network Packet Sniffer

A robust network packet sniffer written in Python that captures and analyzes network traffic in real-time. This tool supports cross-platform operation, protocol filtering, and detailed packet analysis.

## Features

- 🌐 Cross-platform support (Windows/Linux/macOS)
- 📊 Protocol analysis (TCP/UDP/ICMP)
- 🔍 Advanced packet inspection
- 💾 PCAP file output
- 🛡️ Built-in security features
- 📝 Comprehensive logging
- 🖥️ Network interface selection
- 🚦 Protocol filtering
- 🔒 Administrator privilege validation

## Requirements

- Python 3.6+
- Administrator/root privileges
- Required Python packages:
  ```
  psutil
  ```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/xytex-s/Network-Packet-Sniffer.git
   cd Network-Packet-Sniffer
   ```

2. Create a virtual environment (optional but recommended):
   ```bash
   python -m venv .venv
   # Windows
   .venv\Scripts\activate
   # Linux/macOS
   source .venv/bin/activate
   ```

3. Install required packages:
   ```bash
   pip install psutil
   ```

## Usage

### Basic Usage

Run with administrator/root privileges:

```bash
# Windows (PowerShell Admin)
python sniffer.py

# Linux/macOS
sudo python3 sniffer.py
```

### Command Line Options

- `-v, --verbose`: Enable verbose output
- `-i, --interface`: Select network interface
- `--proto`: Filter by protocol (tcp/udp/icmp)
- `--port`: Filter by port number
- `--ip`: Filter by IP address
- `--pcap`: Save output to PCAP file

### Examples

1. Capture all traffic on a specific interface:
   ```bash
   python sniffer.py -i "Ethernet"
   ```

2. Filter TCP traffic on port 80:
   ```bash
   python sniffer.py --proto tcp --port 80
   ```

3. Save capture to PCAP file:
   ```bash
   python sniffer.py --pcap capture.pcap
   ```

4. Filter traffic from specific IP:
   ```bash
   python sniffer.py --ip 192.168.1.100
   ```

## Features in Detail

### Protocol Analysis
- TCP packet analysis with flag detection
- UDP datagram inspection
- ICMP message parsing
- Support for various Ethernet protocols (ARP, RARP, IPv6)

### Security Features
- Privilege validation
- Input sanitization
- Resource cleanup
- Error handling

### Logging Capabilities
- Detailed debug logging
- Packet analysis information
- Error tracking
- Network interface details

## Common Issues and Solutions

1. **Permission Denied**
   - Ensure you're running with administrator/root privileges
   - Check firewall settings

2. **No Interfaces Found**
   - Verify network interfaces are active
   - Check network adapter settings
   - Ensure proper drivers are installed

3. **No Packets Captured**
   - Verify interface selection
   - Check network activity
   - Confirm firewall settings

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Thanks to contributors and testers
- Built with Python's socket library
- Uses psutil for cross-platform compatibility

## Author

xytex-s

## Version History

- 1.0.0: Initial release
  - Basic packet capture
  - Protocol filtering
  - Cross-platform support