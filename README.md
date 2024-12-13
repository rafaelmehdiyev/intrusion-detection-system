# Network Security Monitoring System

## Project Structure

```
IDS/
├── .git/                      # Git repository
├── __pycache__/              # Python cache directory
├── logs/                     # Log files directory
├── templates/                # HTML templates
│   ├── config.html          # Configuration page
│   ├── index.html           # Main dashboard
│   └── logs.html            # Log viewer page
├── utils/                    # Utility functions and helpers
│   └── detailed_logger.py   # Detailed logging implementation
├── config.json              # Configuration file
├── requirements.txt         # Python dependencies
├── sensor.py               # Network sensor implementation  
└── server.py             # Main server application
```

## Key Components

1. **server.py**: Main application server that handles:
   - Web interface and routing
   - Event streaming
   - Log management
   - Real-time monitoring

2. **sensor.py**: Network traffic sensor that:
   - Captures packets
   - Analyzes network traffic
   - Detects suspicious activities
   - Generates events

3. **utils/detailed_logger.py**: Logging system for:
   - Structured event logging
   - System events
   - Network traffic events

4. **templates/**: Web interface files
   - Main dashboard (index.html)
   - Configuration interface (config.html)
   - Log viewer (logs.html)

5. **docs/**: Project documentation
   - Installation and setup guides
   - Configuration documentation
   - API documentation
   - Web interface guide
   - Sensor functionality details
   - Project report

6. **logs/**: Directory containing:
   - System logs
   - Network traffic logs
   - Event logs

7. **config.json**: Configuration settings for:
   - Network interfaces
   - Blacklisted IPs
   - Suspicious ports
   - System parameters

## Dependencies

See `requirements.txt` for a complete list of Python dependencies.

## Setup and Usage

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Configure settings in `config.json`

3. Start the server:
   ```bash
   python server.py
   ```

4. Start the sensor:
   ```bash
   python sensor.py
   ```

5. Access the web interface at `http://localhost:5000`

## Features

- Real-time network traffic monitoring
- Suspicious activity detection
- Structured logging
- Web-based user interface
- Event filtering and search
- Export capabilities
- System event tracking

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
