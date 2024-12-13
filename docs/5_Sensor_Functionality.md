# Network Sensor Documentation

## Core Functionality

### 1. Packet Capture
The sensor (`sensor.py`) uses Scapy to capture and analyze network packets in real-time. Key features include:

- Interface auto-detection
- Promiscuous mode capture
- Protocol analysis (TCP, UDP, DNS)
- Packet statistics tracking
- Real-time packet processing

### 2. Threat Detection

#### Port Scan Detection
```python
# Detection logic:
- Tracks connection attempts per IP
- Monitors time between attempts
- Configurable thresholds
- Alert generation for violations
```

#### DNS Analysis
- Query monitoring
- Domain entropy calculation
- DGA (Domain Generation Algorithm) detection
- Suspicious TLD tracking

#### IP Monitoring
- Connection tracking per IP
- Blacklist/whitelist enforcement
- Geographic location analysis
- Rate limiting

### 3. Alert System

#### Alert Types
1. **CRITICAL**
   - Port scan detected
   - DGA domain detected
   - Blacklisted IP connection

2. **SECURITY**
   - Suspicious port access
   - Multiple failed connections
   - Unusual DNS patterns

3. **WARNING**
   - High traffic volume
   - Connection rate exceeded
   - Unusual protocol usage

4. **INFO**
   - Normal traffic events
   - System status updates
   - Configuration changes

### 4. Logging System

#### Log Types
1. **Event Logs**
   - Timestamp
   - Event type
   - Severity
   - Source/Destination
   - Protocol details

2. **Traffic Logs**
   - Packet counts
   - Protocol distribution
   - Connection statistics
   - Bandwidth usage

3. **System Logs**
   - Sensor status
   - Configuration changes
   - Error conditions
   - Performance metrics

## Advanced Features

### 1. Traffic Analysis
```python
def analyze_traffic(packet):
    # Protocol identification
    # Statistical analysis
    # Pattern recognition
    # Anomaly detection
```

### 2. Connection Tracking
- Session duration monitoring
- Connection state tracking
- Protocol verification
- Rate monitoring

### 3. Performance Optimization
- Efficient packet processing
- Memory management
- Thread safety
- Resource monitoring

## Integration Points

### 1. Web Interface
- Real-time data streaming
- Configuration updates
- Alert notifications
- Status reporting

### 2. External Systems
- Syslog integration
- SMTP notifications
- API endpoints
- Database logging

## Customization

### 1. Detection Rules
- Custom rule creation
- Threshold adjustment
- Alert customization
- Filter modification

### 2. Logging Options
- Log format customization
- Rotation policies
- Storage options
- Compression settings

## Best Practices

### 1. Deployment
- Interface selection
- Resource allocation
- Permission setup
- Initial configuration

### 2. Maintenance
- Regular updates
- Log management
- Rule refinement
- Performance monitoring

### 3. Troubleshooting
- Debug logging
- Error handling
- Status checking
- Performance tuning
