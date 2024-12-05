# Windsurf Network Security Monitor

A comprehensive Network Intrusion Detection System (NIDS) with real-time packet monitoring and threat detection capabilities.

## Features

- Real-time network traffic monitoring
- Advanced packet capture and analysis
- Dynamic, color-coded CLI interface
- Thread-safe logging and display
- Intelligent DNS query caching
- Robust signal handling and clean shutdown

### Threat Detection

- Blacklisted IP detection
- Suspicious port monitoring
- DNS query tracking
- Unusual domain name detection (DGA)
- Real-time alert system

## Requirements

- Python 3.11 or higher
- Windows OS (cross-platform support in development)
- Administrator privileges
- Npcap with WinPcap API compatibility

### Dependencies

```
scapy==2.5.0
colorama==0.4.6
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/rafaelmehdiyev/intrusion-detection-system.git
cd intrusion-detection-system
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Install Npcap from the [official website](https://npcap.com/#download)
   - Ensure "WinPcap API compatibility" is selected during installation

## Usage

Run the monitor with administrator privileges:

```bash
python sensor.py
```

### Command Line Options

- `--debug`: Enable debug output for troubleshooting

## Configuration

Edit `config.json` to customize:
- Blacklisted IPs
- Suspicious ports
- DNS blacklist
- Logging preferences

Example configuration:
```json
{
    "BLACKLISTED_IPS": ["192.168.1.100", "10.0.0.5"],
    "SUSPICIOUS_PORTS": [22, 23, 3389],
    "DNS_BLACKLIST": ["malware.com", "suspicious.net"]
}
```

## Display Interface

```
┌─ Monitoring Statistics ────────────┐
│ Packets: 1180     Rate: 34.52/s   │
│ Alerts: 5      DNS Queries: 10    │
└────────────────────────────────────┘

Recent Events:
──────────────────────────────────────
[01:38:17] DNS Query: example.com
[01:38:24] Alert: Suspicious port access
```

## Features in Development

- Enhanced cross-platform support
- Advanced threat detection algorithms
- Configurable alert history
- Enhanced filtering mechanisms
- External threat intelligence integration

## Known Limitations

- Windows-focused implementation
- Requires administrator privileges
- Depends on Npcap for packet capture

## Troubleshooting

1. **Permission Denied**
   - Run the program with administrator privileges
   - Verify user permissions

2. **Interface Not Found**
   - Ensure Npcap is properly installed
   - Check network interface availability
   - Verify WinPcap API compatibility

3. **Display Issues**
   - Ensure terminal supports ANSI colors
   - Check console window size
   - Verify colorama installation

## Logging

Logs are stored in the `logs` directory with the format `YYYY-MM-DD.log`. Each log entry includes:
- Timestamp
- Event type (INFO/WARNING/ERROR)
- Detailed event description

## Security Considerations

- Run with minimal required privileges
- Monitor only authorized networks
- Review logs regularly
- Keep configuration files secure
- Update dependencies regularly

## Developer

Rafael Mehdiyev

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Acknowledgments

- Scapy development team
- Npcap project contributors
- Python networking community
