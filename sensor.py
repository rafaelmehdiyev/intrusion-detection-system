from scapy.all import sniff, IP, TCP, UDP, DNS, conf, IFACES
import socket
import threading
import logging
import json
import os
from datetime import datetime
import time

class Sensor:
    def __init__(self, interface=None, config_path="config.json"):
        self.interface = interface
        self.load_config(config_path)
        self.setup_logging()
        self.packet_count = 0
        self.start_time = None
        
    def load_config(self, config_path):
        try:
            with open(config_path, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            self.config = {
                "LOG_DIR": "logs",
                "BLACKLISTED_IPS": ["8.8.8.8"],  # Example blacklisted IP
                "SUSPICIOUS_PORTS": [22, 23, 445, 1433, 3389],
                "DNS_BLACKLIST": ["malware.com"]
            }
            os.makedirs("logs", exist_ok=True)
            with open(config_path, 'w') as f:
                json.dump(self.config, f, indent=4)

    def setup_logging(self):
        log_dir = self.config.get("LOG_DIR", "logs")
        os.makedirs(log_dir, exist_ok=True)
        
        # Set up file handler
        log_file = os.path.join(log_dir, f"{datetime.now().strftime('%Y-%m-%d')}.log")
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        
        # Set up console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)
        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)

    def get_network_adapters(self):
        adapters = []
        print("\nDebug - All Scapy interfaces:")
        for iface_name, iface in IFACES.items():
            print(f"Interface: {iface_name}")
            print(f"  Description: {getattr(iface, 'description', 'No description')}")
            print(f"  Name: {getattr(iface, 'name', 'No name')}")
            print(f"  Network name: {getattr(iface, 'network_name', 'No network name')}")
            print(f"  GUID: {getattr(iface, 'guid', 'No GUID')}\n")
            
            if isinstance(iface_name, str):  # Skip numeric indices
                name = getattr(iface, 'description', iface_name)
                description = getattr(iface, 'network_name', getattr(iface, 'name', 'No description'))
                adapters.append({
                    'name': name,
                    'description': description,
                    'interface': iface_name,  # Store the actual interface name
                    'guid': getattr(iface, 'guid', None)
                })
        return adapters

    def list_interfaces(self):
        adapters = self.get_network_adapters()
        print("\nAvailable Network Interfaces:")
        print("-" * 100)
        print(f"{'Index':<6} {'Name':<30} {'Description':<50}")
        print("-" * 100)
        
        for idx, adapter in enumerate(adapters):
            print(f"{idx:<6} {adapter['name'][:27]:<30} {adapter['description'][:47]:<50}")
        
        return adapters

    def select_interface(self):
        adapters = self.list_interfaces()
        while True:
            try:
                choice = input("\nEnter the index number of the interface to monitor (or 'q' to quit): ")
                if choice.lower() == 'q':
                    return None
                idx = int(choice)
                if 0 <= idx < len(adapters):
                    # Get the interface object from IFACES
                    selected_interface = adapters[idx]['interface']
                    if selected_interface in IFACES:
                        # Use the actual interface object's network_name
                        iface_obj = IFACES[selected_interface]
                        selected_interface = iface_obj.network_name
                        print(f"\nSelected interface: {adapters[idx]['name']}")
                        print(f"Interface ID: {selected_interface}")
                        return selected_interface
                    else:
                        print("Interface not found in Scapy's interface list")
                else:
                    print("Invalid index number. Please try again.")
            except ValueError:
                print("Please enter a valid number.")
            except AttributeError as e:
                print(f"Error accessing interface properties: {e}")
                print("Please make sure Npcap is properly installed")

    def print_stats(self):
        while True:
            if self.start_time:
                elapsed_time = time.time() - self.start_time
                packets_per_second = self.packet_count / elapsed_time if elapsed_time > 0 else 0
                print(f"\rPackets captured: {self.packet_count} | Rate: {packets_per_second:.2f} packets/sec", end='')
            time.sleep(1)

    def start_capture(self):
        try:
            if self.interface is None:
                self.interface = self.select_interface()
                if self.interface is None:
                    print("No interface selected. Exiting...")
                    return

            # Debug information
            print("\nDebug - Selected interface details:")
            print(f"Interface name: {self.interface}")
            if self.interface in IFACES:
                iface = IFACES[self.interface]
                print(f"Interface object: {iface}")
                print(f"Interface description: {getattr(iface, 'description', 'No description')}")
                print(f"Interface name: {getattr(iface, 'name', 'No name')}")
                print(f"Network name: {getattr(iface, 'network_name', 'No network name')}")
                print(f"GUID: {getattr(iface, 'guid', 'No GUID')}")

            print(f"\nStarting packet capture on interface: {self.interface}")
            logging.info(f"Started packet capture on interface: {self.interface}")
            
            # Start statistics printing thread
            stats_thread = threading.Thread(target=self.print_stats, daemon=True)
            stats_thread.start()
            
            self.start_time = time.time()
            
            # Log initial status
            logging.info("Network Security Monitor started")
            logging.info(f"Monitoring interface: {self.interface}")
            logging.info(f"Blacklisted IPs: {', '.join(self.config['BLACKLISTED_IPS'])}")
            logging.info(f"Suspicious ports: {', '.join(map(str, self.config['SUSPICIOUS_PORTS']))}")
            
            try:
                # Add basic filter to reduce noise
                sniff(iface=self.interface, 
                      prn=self.packet_callback, 
                      store=0,
                      filter="ip"  # Only capture IP packets
                      )
            except Exception as sniff_error:
                error_msg = (
                    f"Failed to start packet capture on interface: {self.interface}\n"
                    f"Error Type: {type(sniff_error).__name__}\n"
                    f"Error Details: {str(sniff_error)}\n"
                    "Possible causes:\n"
                    "1. Interface name format is incorrect\n"
                    "2. Insufficient permissions (Try running as Administrator)\n"
                    "3. Npcap/WinPcap is not properly installed\n"
                    "4. Interface is disabled or not properly configured\n"
                    f"Interface Details:\n"
                    f"- Name: {self.interface}\n"
                    f"- Available interfaces: {', '.join(str(k) for k in IFACES.keys())}\n"
                    f"- Interface in IFACES: {self.interface in IFACES}\n"
                    f"- Scapy conf.iface: {conf.iface}"
                )
                logging.error(error_msg)
                print("\nError Details:")
                print(error_msg)
                return
            
        except KeyboardInterrupt:
            print("\nCapture stopped by user")
            logging.info("Capture stopped by user")
        except Exception as e:
            error_msg = (
                f"Unexpected error during capture:\n"
                f"Error Type: {type(e).__name__}\n"
                f"Error Details: {str(e)}\n"
                f"Interface: {self.interface}"
            )
            logging.error(error_msg)
            print(f"\nError: {error_msg}")
            
    def packet_callback(self, packet):
        try:
            self.packet_count += 1
            
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Check against blacklisted IPs
                if src_ip in self.config["BLACKLISTED_IPS"] or dst_ip in self.config["BLACKLISTED_IPS"]:
                    alert_msg = f"Detected traffic from/to blacklisted IP - Src: {src_ip}, Dst: {dst_ip}"
                    logging.warning(alert_msg)
                    print(f"\nALERT: {alert_msg}")
                    return

                # TCP Analysis
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    
                    # Check for suspicious ports
                    if dst_port in self.config["SUSPICIOUS_PORTS"]:
                        alert_msg = f"Suspicious port access detected - Src: {src_ip}:{src_port}, Dst: {dst_ip}:{dst_port}"
                        logging.warning(alert_msg)
                        print(f"\nALERT: {alert_msg}")

                # UDP and DNS Analysis
                elif UDP in packet:
                    if DNS in packet:
                        self.analyze_dns(packet[DNS])
                        
        except Exception as e:
            logging.error(f"Error processing packet: {str(e)}")

    def analyze_dns(self, dns_packet):
        try:
            if dns_packet.qr == 0:  # DNS query
                query_name = dns_packet.qd.qname.decode('utf-8').rstrip('.')
                
                # Log all DNS queries for monitoring
                logging.info(f"DNS Query: {query_name}")
                
                # Check against DNS blacklist
                if any(blocked in query_name for blocked in self.config["DNS_BLACKLIST"]):
                    alert_msg = f"Suspicious DNS query detected: {query_name}"
                    logging.warning(alert_msg)
                    print(f"\nALERT: {alert_msg}")
                
                # Check for unusually long domain names (potential DGA)
                if len(query_name) > 50:
                    alert_msg = f"Unusually long domain name detected: {query_name}"
                    logging.warning(alert_msg)
                    print(f"\nALERT: {alert_msg}")
                    
        except Exception as e:
            logging.error(f"Error analyzing DNS packet: {str(e)}")

if __name__ == "__main__":
    print("Network Security Monitor")
    print("Press Ctrl+C to stop capturing")
    sensor = Sensor()
    sensor.start_capture()
