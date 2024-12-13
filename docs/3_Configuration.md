# Configuration Guide

## Overview
The system uses a JSON-based configuration file (`config.json`) that controls all aspects of the monitoring system. This guide explains each configuration section and its parameters.

## Configuration Sections

### 1. General Settings
```json
"GENERAL_SETTINGS": {
    "LOG_DIR": "logs",
    "LOG_LEVEL": "INFO",
    "INTERFACE": "auto",
    "CAPTURE_TIMEOUT": 0
}
```
- `LOG_DIR`: Directory for storing logs
- `LOG_LEVEL`: Logging detail level (DEBUG, INFO, WARNING, ERROR)
- `INTERFACE`: Network interface to monitor
- `CAPTURE_TIMEOUT`: Packet capture timeout (0 for continuous)

### 2. IP Rules
```json
"IP_RULES": {
    "BLACKLISTED_IPS": [],
    "WHITELISTED_IPS": [],
    "IP_RANGES_TO_MONITOR": ["192.168.0.0/16"],
    "MAX_CONNECTIONS_PER_IP": 50,
    "CONNECTION_TIMEOUT": 300
}
```
- `BLACKLISTED_IPS`: List of blocked IP addresses
- `WHITELISTED_IPS`: List of trusted IP addresses
- `IP_RANGES_TO_MONITOR`: CIDR ranges to monitor
- `MAX_CONNECTIONS_PER_IP`: Connection limit per IP
- `CONNECTION_TIMEOUT`: Connection timeout in seconds

### 3. Port Rules
```json
"PORT_RULES": {
    "SUSPICIOUS_PORTS": [22, 23, 445, 1433, 3389],
    "ALLOWED_PORTS": [80, 443, 53],
    "PORT_SCAN_DETECTION": {
        "ENABLED": true,
        "THRESHOLD": 20,
        "TIME_WINDOW": 60
    }
}
```
- `SUSPICIOUS_PORTS`: Ports to monitor closely
- `ALLOWED_PORTS`: Known legitimate ports
- `PORT_SCAN_DETECTION`: Port scan detection settings

### 4. DNS Rules
```json
"DNS_RULES": {
    "DNS_BLACKLIST": [],
    "DGA_DETECTION": {
        "ENABLED": true,
        "MIN_ENTROPY": 3.5,
        "MIN_LENGTH": 10
    }
}
```
- `DNS_BLACKLIST`: Blocked domain list
- `DGA_DETECTION`: Domain Generation Algorithm detection settings

## Best Practices

1. **Security Settings**
   - Regularly update blacklists
   - Set appropriate thresholds
   - Monitor logs for tuning

2. **Performance**
   - Adjust capture timeout
   - Set appropriate log levels
   - Monitor system resources

3. **Maintenance**
   - Regular configuration backups
   - Log rotation setup
   - Update detection rules
