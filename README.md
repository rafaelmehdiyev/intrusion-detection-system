# Network Security Monitor

A comprehensive web-based network security monitoring and configuration system.

## Features

### Dashboard
- Real-time network status monitoring
- Threat detection statistics
- Blocked IP tracking
- System health monitoring
- Recent activity log

### Configuration Interface
- Section-based configuration management
- Detailed help text for each setting
- Real-time validation
- Automatic configuration persistence

## Configuration Sections

### General Settings
- Log Directory: Specify where log files are stored
- Log Level: Set logging detail (DEBUG/INFO/WARNING/ERROR)
- Network Interface: Select interface to monitor
- Capture Timeout: Set packet capture duration

### IP Rules
- Blacklisted IPs: Block specific IP addresses
- Whitelisted IPs: Allow trusted IP addresses
- IP Ranges: Monitor specific network ranges (CIDR notation)
- Connection Limits: Control per-IP connection count
- Timeout Settings: Manage connection timeouts

### Port Rules
- Suspicious Ports: Define potentially malicious ports
- Allowed Ports: Specify permitted service ports
- Port Scan Detection:
  * Enable/disable detection
  * Set detection threshold
  * Configure time window

### DNS Rules
- Domain Blacklist: Block specific domains
- DGA Detection:
  * Enable/disable detection
  * Set entropy threshold
  * Configure length requirements
  * Adjust consonant ratio detection
- DNS Monitoring:
  * Set cache timeout
  * Limit queries per domain
  * Track suspicious TLDs

## Recent Updates

### Version 1.1.0
- Added consistent navigation across all pages
- Implemented section-based configuration saving
- Added detailed configuration explanations
- Fixed configuration persistence issues
- Enhanced error handling
- Improved mobile responsiveness

### Version 1.0.0
- Initial release with basic monitoring
- Configuration management system
- Dashboard implementation
- Security rule management

## Technical Stack
- Python 3.11
- Flask web framework
- Bootstrap 5 UI framework
- JSON-based configuration

## Installation

1. Clone the repository:
```bash
git clone [repository-url]
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python server.py
```

4. Access the interface:
```
http://localhost:5000
```

Default credentials:
- Username: admin
- Password: 123

## Configuration Structure

The system uses a JSON-based configuration file (`config.json`) with the following structure:

```json
{
    "GENERAL_SETTINGS": {
        "LOG_DIR": "logs",
        "LOG_LEVEL": "INFO",
        "INTERFACE": "auto",
        "CAPTURE_TIMEOUT": 0
    },
    "IP_RULES": {
        "BLACKLISTED_IPS": [],
        "WHITELISTED_IPS": [],
        "IP_RANGES_TO_MONITOR": ["192.168.0.0/16"],
        "MAX_CONNECTIONS_PER_IP": 50,
        "CONNECTION_TIMEOUT": 300
    },
    "PORT_RULES": {
        "SUSPICIOUS_PORTS": [22, 23, 445, 1433, 3389, 4444, 5554],
        "ALLOWED_PORTS": [80, 443, 53],
        "PORT_SCAN_DETECTION": {
            "ENABLED": true,
            "THRESHOLD": 20,
            "TIME_WINDOW": 60
        }
    },
    "DNS_RULES": {
        "DNS_BLACKLIST": [],
        "DGA_DETECTION": {
            "ENABLED": true,
            "MIN_ENTROPY": 3.5,
            "MIN_LENGTH": 10,
            "CONSONANT_THRESHOLD": 0.7
        },
        "DNS_MONITORING": {
            "CACHE_TIMEOUT": 300,
            "MAX_QUERIES_PER_DOMAIN": 100,
            "SUSPICIOUS_TLD": [".xyz", ".top"]
        }
    }
}
```

## Security Considerations

1. Authentication
   - Basic authentication implemented
   - Password hashing enabled
   - Session management included

2. Configuration Security
   - Section-based updates
   - Type validation
   - Error handling
   - Configuration backup

3. Network Security
   - Flexible IP blocking
   - Port scanning detection
   - DNS threat monitoring
   - DGA detection

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
