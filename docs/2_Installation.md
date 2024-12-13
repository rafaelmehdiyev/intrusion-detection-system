# Installation Guide

## System Requirements
- Python 3.11 or higher
- Network interface with promiscuous mode support
- Administrator/root privileges for packet capture
- Minimum 4GB RAM recommended
- 1GB free disk space for logs

## Dependencies
The project requires several Python packages:
```
Flask==2.0.1
scapy==2.4.5
colorama==0.4.4
```

Full list available in `requirements.txt`

## Installation Steps

### 1. System Preparation
#### Windows
1. Install Python 3.11 from python.org
2. Install Npcap for packet capture
3. Run Command Prompt as Administrator

#### Linux
```bash
sudo apt update
sudo apt install python3.11 python3-pip tcpdump
```

### 2. Project Setup
1. Clone or download the project
2. Navigate to project directory
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### 3. Configuration
1. Copy `config.json.example` to `config.json`
2. Modify settings according to your environment:
   - Network interface
   - Log directory
   - Alert thresholds
   - IP rules

### 4. First Run
1. Start the server:
   ```bash
   python server.py
   ```
2. Access web interface:
   ```
   http://localhost:8338
   ```
3. Default credentials:
   - Username: admin
   - Password: 123

## Troubleshooting

### Common Issues
1. **Permission Denied**
   - Run as administrator/root
   - Check interface permissions

2. **Interface Not Found**
   - Verify interface name
   - Check Npcap/libpcap installation

3. **Port Already in Use**
   - Check if another service uses port 8338
   - Modify port in configuration

### Getting Help
- Check logs in `logs` directory
- Review configuration
- Consult documentation
- Submit issue on project repository
