# Network Security Monitor

A real-time network intrusion detection system (NIDS) that monitors network traffic, detects potential security threats, and provides a web-based monitoring interface.

## In Progress Improvements
1. Improved Threat Detection  
   - Basic Anomaly Detection: Introduce simple anomaly detection based on traffic patterns, such as detecting large spikes in traffic, unusual packet sizes, or changes in traffic flow (e.g., sudden flood of SYN packets for SYN flood detection).  
   - Rate Limiting for Suspicious Traffic: Implement rate-limiting rules (e.g., multiple requests to the same port/IP in a short period) to detect potential brute force attacks or scans.  
   - GeoIP Lookup: Integrate lightweight IP geolocation to track the source of suspicious traffic. This can help detect unusual activity from foreign countries or regions where you don’t expect traffic.  


## Features

### Core Components

1. **Network Sensor (sensor.py)**
   - Real-time packet capture using Scapy
   - Network interface detection and selection
   - Packet analysis and threat detection
   - Traffic statistics monitoring
   - Configurable detection rules

2. **Monitoring Server (server.py)**
   - Web-based monitoring interface
   - Real-time event streaming
   - Basic authentication system
   - Event filtering and display
   - Secure communication

3. **Web Interface (templates/index.html)**
   - Real-time event updates
   - Interactive event filtering
   - Visual status indicators
   - Event categorization (Info/Warning/Error)
   - Clean, modern UI design

### Security Features

- **Threat Detection**
  - Blacklisted IP monitoring
  - Suspicious port detection
  - DNS query analysis
  - Unusual domain detection
  - Real-time alerts

- **Logging System**
  - Detailed event logging
  - Timestamp-based organization
  - Log rotation support
  - Event categorization
  - Searchable logs

- **Authentication**
  - Basic HTTP authentication
  - Secure password hashing
  - Session management
  - Default credentials:
    - Username: admin
    - Password: changeme!

## Technical Details

### Requirements

- Python 3.x
- Windows OS (currently Windows-specific)
- Administrator privileges (for packet capture)

### Dependencies

```
scapy==2.5.0
flask==2.0.1
wmi==1.5.1
werkzeug==2.0.1
requests==2.26.0
python-whois==0.7.3
```

### Configuration

The system is configured through `config.json`:
- Log directory path
- Blacklisted IP addresses
- Suspicious port numbers
- DNS blacklist entries

## Installation

1. Clone the repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Ensure you have administrator privileges
4. Configure `config.json` as needed

## Usage

1. Start the sensor:
   ```
   python sensor.py
   ```
   - Select a network interface when prompted
   - Monitor packet capture statistics

2. Start the web server:
   ```
   python server.py
   ```
   - Server runs on http://localhost:8338
   - Log in with default credentials

3. Access the web interface:
   - Open http://localhost:8338 in your browser
   - Monitor real-time events
   - Filter and search through events
   - View security alerts

## Recent Updates

### Interface Detection Fix
- Fixed Windows network interface detection issues
- Now properly using Scapy's IFACES for interface discovery
- Correctly formatting interface names with `\Device\NPF_{GUID}` pattern
- Improved error handling and debugging information
- Resolved the "Error opening adapter" issue on Windows

### Known Issues
- Must run as Administrator for packet capture
- Requires Npcap installation with WinPcap compatibility mode

### Troubleshooting
If you encounter interface detection issues:
1. Ensure you're running as Administrator
2. Verify Npcap is properly installed
3. Make sure the selected network interface is enabled
4. Check if the interface name follows the correct format: `\Device\NPF_{GUID}`

## Security Considerations

1. **Authentication**
   - Change default credentials immediately
   - Use strong passwords
   - Implement proper session management

2. **Network Access**
   - Restrict server access to trusted networks
   - Use firewall rules as needed
   - Monitor server logs

3. **Privileges**
   - Run with minimum required privileges
   - Secure configuration files
   - Protect log files

## Current Limitations

- Windows-specific implementation
- Basic threat detection rules
- Manual configuration required
- Limited to IP-based detection

## Future Improvements

1. Cross-platform compatibility
2. Machine learning-based detection
3. Advanced threat detection rules
4. Automated response capabilities
5. Enhanced authentication system
6. API integration capabilities
7. Custom rule creation interface
8. Performance optimizations

## Contributing

Contributions are welcome! Please follow these steps:
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Scapy project for packet capture capabilities
- Flask framework for web interface
- Python community for various dependencies
