import warnings
import sys
import signal
from cryptography.utils import CryptographyDeprecationWarning
from scapy.all import sniff, IP, TCP, UDP, DNS, conf, IFACES
import socket
import threading
import logging
import json
import os
import argparse
from datetime import datetime
import time
from colorama import init, Fore, Back, Style
from collections import deque
from utils.detailed_logger import DetailedLogger

# Suppress specific warnings
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
warnings.filterwarnings("ignore", message="Wireshark is installed")

# Initialize colorama for Windows color support
init()

class Sensor:
    def __init__(self, interface=None, config_path="config.json", debug=False):
        self.interface = interface
        self.debug = debug
        self.packet_count = 0
        self.alert_count = 0
        self.dns_query_count = 0
        self.start_time = None
        self.alert_history = deque(maxlen=5)
        self.display_lock = threading.Lock()
        self.recent_dns_queries = {}
        self.connection_tracker = {}
        self.port_scan_tracker = {}
        self.blocked_ips = set()
        self.running = True
        self.stats_thread = None
        
        # Load configuration
        try:
            with open(config_path, 'r') as f:
                self.config = json.load(f)
            # Set up logging based on config
            log_level = getattr(logging, self.config.get("GENERAL_SETTINGS", {}).get("LOG_LEVEL", "INFO"))
            log_dir = self.config.get("LOG_DIR", "logs")
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
            log_file = os.path.join(log_dir, f"{datetime.now().strftime('%Y-%m-%d')}.log")
            logging.basicConfig(
                filename=log_file,
                level=log_level,
                format='%(asctime)s - %(levelname)s - %(message)s'
            )
            
            # Initialize detailed logger
            self.detailed_logger = DetailedLogger(os.path.join(log_dir, "detailed"))
            
        except Exception as e:
            print(f"Error loading config: {str(e)}")
            self.config = {
                "IP_RULES": {"BLACKLISTED_IPS": []},
                "PORT_RULES": {"SUSPICIOUS_PORTS": [22, 23, 3389]},
                "DNS_RULES": {"DNS_BLACKLIST": []}
            }

        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.stop_capture()

    def stop_capture(self):
        """Stop all capture activities"""
        self.running = False
        print(f"\n{Fore.YELLOW}Stopping packet capture...{Style.RESET_ALL}")
        logging.info("Packet capture stopped by user")
        
        # Wait for stats thread to finish
        if self.stats_thread and self.stats_thread.is_alive():
            self.stats_thread.join(timeout=1.0)
        
        # Force exit if needed
        sys.exit(0)

    def print_stats(self):
        """Print and update statistics"""
        while self.running:
            if self.start_time:
                try:
                    with self.display_lock:
                        elapsed_time = time.time() - self.start_time
                        packets_per_second = self.packet_count / elapsed_time if elapsed_time > 0 else 0
                        
                        # Move cursor to home position and clear screen
                        sys.stdout.write('\033[H')
                        sys.stdout.write('\033[2J')
                        
                        # Print banner and status
                        self.print_banner()
                        print(f"{Fore.GREEN}[*] Monitoring Network Traffic{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop capturing{Style.RESET_ALL}\n")
                        
                        # Print statistics box
                        print(f"{Fore.CYAN}┌─ Monitoring Statistics ────────────┐")
                        print(f"│{Style.RESET_ALL} Packets: {self.packet_count:<8} Rate: {packets_per_second:>6.2f}/s {Fore.CYAN}  │")
                        print(f"│{Style.RESET_ALL} Alerts: {Fore.RED}{self.alert_count:<6}{Style.RESET_ALL} DNS Queries: {Fore.BLUE}{self.dns_query_count:<6}{Style.RESET_ALL} {Fore.CYAN}│")
                        print(f"└────────────────────────────────────┘{Style.RESET_ALL}\n")
                        
                        if self.alert_history:
                            print(f"{Fore.CYAN}Recent Events:{Style.RESET_ALL}")
                            print("─" * 50)
                            for alert in self.alert_history:
                                print(alert)
                        
                        sys.stdout.flush()
                except Exception as e:
                    logging.error(f"Error updating display: {str(e)}")
                
            time.sleep(0.5)

    def print_banner(self):
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║             Network Security Monitor v1.0                    ║
║                By: Rafael Mehdiyev                           ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
        print(banner)

    def add_alert(self, alert_msg, alert_type="INFO"):
        """Enhanced alert handling with configurable actions"""
        try:
            with self.display_lock:
                timestamp = datetime.now().strftime('%H:%M:%S')
                alert_settings = self.config.get("ALERT_SETTINGS", {})
                alert_level = alert_settings.get("ALERT_LEVELS", {}).get(alert_type, {})
                
                # Get color based on alert type
                color = getattr(Fore, alert_level.get("COLOR", "WHITE"))
                formatted_alert = f"{color}[{timestamp}] {alert_msg}{Style.RESET_ALL}"
                
                # Add to history and increment counter
                self.alert_history.append(formatted_alert)
                self.alert_count += 1
                
                # Log if enabled
                if alert_level.get("LOG", True):
                    logging.warning(alert_msg)
                
                # Handle notifications
                if alert_level.get("NOTIFY", False):
                    self.handle_notification(alert_msg, alert_type)
                
                # Handle auto-blocking
                if alert_type == "ALERT" and alert_settings.get("ALERT_ACTIONS", {}).get("AUTO_BLOCK", {}).get("ENABLED", False):
                    self.handle_auto_block(alert_msg)
                
        except Exception as e:
            logging.error(f"Error updating display: {str(e)}")

    def handle_notification(self, alert_msg, alert_type):
        """Handle alert notifications (email, etc.)"""
        email_config = self.config.get("ALERT_SETTINGS", {}).get("ALERT_ACTIONS", {}).get("EMAIL_NOTIFICATIONS", {})
        if email_config.get("ENABLED", False):
            # Implement email notification here
            pass

    def handle_auto_block(self, alert_msg):
        """Handle automatic IP blocking"""
        auto_block = self.config.get("ALERT_SETTINGS", {}).get("ALERT_ACTIONS", {}).get("AUTO_BLOCK", {})
        if auto_block.get("ENABLED", False):
            # Extract IP from alert message and add to blocked list
            # Implementation depends on your blocking mechanism
            pass

    def check_ip_rules(self, src_ip, dst_ip):
        """Check IP against configured rules"""
        ip_rules = self.config.get("IP_RULES", {})
        
        # Check blacklisted IPs
        if src_ip in ip_rules.get("BLACKLISTED_IPS", []) or dst_ip in ip_rules.get("BLACKLISTED_IPS", []):
            self.add_alert(f"Detected traffic from/to blacklisted IP - Src: {src_ip}, Dst: {dst_ip}", "ALERT")
            return True

        # Check IP ranges
        for ip_range in ip_rules.get("IP_RANGES_TO_MONITOR", []):
            if self.ip_in_range(src_ip, ip_range) or self.ip_in_range(dst_ip, ip_range):
                self.add_alert(f"Detected traffic in monitored IP range - Src: {src_ip}, Dst: {dst_ip}", "INFO")
                return True

        return False

    def check_port_rules(self, src_ip, dst_ip, src_port, dst_port):
        """Check ports against configured rules"""
        port_rules = self.config.get("PORT_RULES", {})
        
        # Check suspicious ports
        if dst_port in port_rules.get("SUSPICIOUS_PORTS", []):
            self.add_alert(f"Suspicious port access detected - Src: {src_ip}:{src_port}, Dst: {dst_ip}:{dst_port}", "WARNING")
            return True

        # Port scan detection
        if port_rules.get("PORT_SCAN_DETECTION", {}).get("ENABLED", False):
            self.check_port_scan(src_ip, dst_port)

        return False

    def check_port_scan(self, src_ip, dst_port):
        """Detect potential port scanning"""
        port_rules = self.config.get("PORT_RULES", {}).get("PORT_SCAN_DETECTION", {})
        threshold = port_rules.get("THRESHOLD", 20)
        time_window = port_rules.get("TIME_WINDOW", 60)
        
        current_time = time.time()
        if src_ip not in self.port_scan_tracker:
            self.port_scan_tracker[src_ip] = {"ports": set(), "start_time": current_time}
        
        tracker = self.port_scan_tracker[src_ip]
        tracker["ports"].add(dst_port)
        
        if current_time - tracker["start_time"] <= time_window:
            if len(tracker["ports"]) >= threshold:
                self.add_alert(f"Possible port scan detected from {src_ip} - {len(tracker['ports'])} ports in {time_window}s", "ALERT")
                return True
        else:
            # Reset tracker after time window
            tracker["ports"] = {dst_port}
            tracker["start_time"] = current_time
        
        return False

    def check_dns_rules(self, packet, dns_packet):
        """Enhanced DNS analysis with new rules"""
        dns_rules = self.config.get("DNS_RULES", {})
        
        if dns_packet.qr == 0:  # DNS query
            query = dns_packet.qd.qname.decode('utf-8').lower().rstrip('.')
            
            # Check DNS blacklist
            if query in dns_rules.get("DNS_BLACKLIST", []):
                self.add_alert(f"Query to blacklisted domain detected: {query}", "ALERT")
                return True
            
            # Check suspicious TLDs
            for tld in dns_rules.get("DNS_MONITORING", {}).get("SUSPICIOUS_TLD", []):
                if query.endswith(tld):
                    self.add_alert(f"Query to suspicious TLD detected: {query}", "WARNING")
                    return True
            
            # DGA detection
            if dns_rules.get("DGA_DETECTION", {}).get("ENABLED", False):
                if self.check_dga(query):
                    self.add_alert(f"Possible DGA domain detected: {query}", "WARNING")
                    return True
        
        return False

    def check_dga(self, domain):
        """Check if domain appears to be generated by DGA"""
        dga_rules = self.config.get("DNS_RULES", {}).get("DGA_DETECTION", {})
        min_entropy = dga_rules.get("MIN_ENTROPY", 3.5)
        min_length = dga_rules.get("MIN_LENGTH", 10)
        consonant_threshold = dga_rules.get("CONSONANT_THRESHOLD", 0.7)
        
        if len(domain) < min_length:
            return False
            
        # Calculate entropy
        entropy = self.calculate_entropy(domain)
        if entropy < min_entropy:
            return False
            
        # Calculate consonant ratio
        consonants = sum(1 for c in domain if c.isalpha() and c.lower() not in 'aeiou')
        consonant_ratio = consonants / len(domain)
        if consonant_ratio > consonant_threshold:
            return True
            
        return False

    def calculate_entropy(self, string):
        """Calculate Shannon entropy of a string"""
        import math
        prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
        entropy = - sum(p * math.log(p) / math.log(2.0) for p in prob)
        return entropy

    def ip_in_range(self, ip, ip_range):
        """Check if IP is in CIDR range"""
        try:
            from ipaddress import ip_address, ip_network
            return ip_address(ip) in ip_network(ip_range)
        except Exception:
            return False

    def clear_screen(self):
        """Clear the entire screen"""
        if os.name == 'nt':  
            os.system('cls')
        else:  
            os.system('clear')

    def get_network_adapters(self):
        adapters = []
        if self.debug:
            print("\nDebug - All Scapy interfaces:")
            
        for iface_name, iface in IFACES.items():
            if self.debug:
                print(f"Interface: {iface_name}")
                print(f"  Description: {getattr(iface, 'description', 'No description')}")
                print(f"  Name: {getattr(iface, 'name', 'No name')}")
                print(f"  Network name: {getattr(iface, 'network_name', 'No network name')}")
                print(f"  GUID: {getattr(iface, 'guid', 'No GUID')}\n")
            
            if isinstance(iface_name, str):  
                name = getattr(iface, 'description', iface_name)
                description = getattr(iface, 'network_name', getattr(iface, 'name', 'No description'))
                adapters.append({
                    'name': name,
                    'description': description,
                    'interface': iface_name,
                    'guid': getattr(iface, 'guid', None)
                })
        return adapters

    def list_interfaces(self):
        adapters = self.get_network_adapters()
        print(f"\n{Fore.CYAN}┌─ Available Network Interfaces ───────────────────────────────┐{Style.RESET_ALL}")
        print(f"{Fore.CYAN}│{Style.RESET_ALL}")
        
        for idx, adapter in enumerate(adapters):
            name = adapter['name'][:27]
            desc = adapter['description'][:47]
            print(f"{Fore.CYAN}│{Style.RESET_ALL} [{Fore.GREEN}{idx}{Style.RESET_ALL}] {Fore.YELLOW}{name:<28}{Style.RESET_ALL} {desc:<48}")
        
        print(f"{Fore.CYAN}│{Style.RESET_ALL}")
        print(f"{Fore.CYAN}└────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")
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
                    selected_interface = adapters[idx]['interface']
                    if selected_interface in IFACES:
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

    def start_capture(self):
        try:
            if self.interface is None:
                self.interface = self.select_interface()
                if self.interface is None:
                    print(f"{Fore.RED}No interface selected. Exiting...{Style.RESET_ALL}")
                    return

            self.clear_screen()
            self.print_banner()
            
            self.stats_thread = threading.Thread(target=self.print_stats)
            self.stats_thread.daemon = True
            self.stats_thread.start()

            logging.info("Network Security Monitor started")
            logging.info(f"Monitoring interface: {self.interface}")
            logging.info(f"Blacklisted IPs: {', '.join(self.config['IP_RULES']['BLACKLISTED_IPS'])}")
            logging.info(f"Suspicious ports: {', '.join(map(str, self.config['PORT_RULES']['SUSPICIOUS_PORTS']))}")

            self.start_time = time.time()
            
            # Log capture start in detailed format
            self.detailed_logger.log_event(
                event_type="CAPTURE_START",
                data={
                    "interface": self.interface,
                    "blacklisted_ips": self.config["IP_RULES"]["BLACKLISTED_IPS"],
                    "suspicious_ports": self.config["PORT_RULES"]["SUSPICIOUS_PORTS"]
                },
                source="system"
            )
            
            try:
                sniff(iface=self.interface,
                      prn=self.packet_callback,
                      store=0,
                      stop_filter=lambda _: not self.running)
            except KeyboardInterrupt:
                self.stop_capture()
            except Exception as e:
                print(f"\n{Fore.RED}Error during packet capture: {str(e)}{Style.RESET_ALL}")
                logging.error(f"Error during packet capture: {str(e)}")
                self.stop_capture()
                
        except Exception as e:
            print(f"{Fore.RED}Error starting capture: {str(e)}{Style.RESET_ALL}")
            logging.error(f"Error starting capture: {str(e)}")
            self.stop_capture()

    def packet_callback(self, packet):
        """Enhanced packet callback with new detection rules"""
        if not self.running:
            return

        try:
            if IP in packet:
                self.packet_count += 1
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Log network event in detailed format
                protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
                src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else None
                dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else None
                
                # Fix TCP flags handling
                if TCP in packet:
                    tcp_flags = packet[TCP].flags
                    flags_dict = {
                        "FIN": bool(tcp_flags & 0x01),
                        "SYN": bool(tcp_flags & 0x02),
                        "RST": bool(tcp_flags & 0x04),
                        "PSH": bool(tcp_flags & 0x08),
                        "ACK": bool(tcp_flags & 0x10),
                        "URG": bool(tcp_flags & 0x20),
                        "ECE": bool(tcp_flags & 0x40),
                        "CWR": bool(tcp_flags & 0x80)
                    }
                else:
                    flags_dict = None
                
                self.detailed_logger.log_event(
                    event_type="NETWORK_TRAFFIC",
                    data={
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "protocol": protocol,
                        "source_port": src_port,
                        "destination_port": dst_port,
                        "payload_size": len(packet),
                        "flags": flags_dict
                    },
                    source="sensor"
                )

                # Check IP rules
                alert = self.check_ip_rules(src_ip, dst_ip)
                if alert:
                    self.detailed_logger.log_event(
                        event_type="SECURITY_ALERT",
                        data={
                            "alert_type": "BLACKLIST_MATCH",
                            "severity": "HIGH",
                            "description": "Traffic detected from/to blacklisted IP",
                            "source_ip": src_ip,
                            "destination_ip": dst_ip
                        },
                        source="security"
                    )

                # Check for DNS queries
                if DNS in packet:
                    qname = packet[DNS].qd.qname.decode('utf-8')
                    if qname:
                        self.dns_query_count += 1
                        logging.info(f"DNS Query: {qname.rstrip('.')}")
                        self.detailed_logger.log_event(
                            event_type="NETWORK_TRAFFIC",
                            data={
                                "source_ip": src_ip,
                                "destination_ip": dst_ip,
                                "protocol": "DNS",
                                "payload_size": len(packet),
                                "query": qname.rstrip('.')
                            },
                            source="dns"
                        )

                # Port scanning detection
                if TCP in packet or UDP in packet:
                    port = packet[TCP].dport if TCP in packet else packet[UDP].dport
                    if self.check_port_scan(src_ip, port):
                        self.detailed_logger.log_event(
                            event_type="SECURITY_ALERT",
                            data={
                                "alert_type": "PORT_SCAN",
                                "severity": "HIGH",
                                "description": f"Potential port scanning detected from {src_ip}",
                                "source_ip": src_ip,
                                "target_port": port
                            },
                            source="security"
                        )

        except Exception as e:
            logging.error(f"Error processing packet: {str(e)}")
            self.detailed_logger.log_event(
                event_type="ERROR",
                data={
                    "error_type": "PACKET_PROCESSING_ERROR",
                    "description": str(e)
                },
                source="system"
            )

if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')
    
    parser = argparse.ArgumentParser(description='Network Security Monitor')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    args = parser.parse_args()

    sensor = Sensor(debug=args.debug)
    sensor.print_banner()
    print(f"{Fore.GREEN}[*] Starting Network Security Monitor...{Style.RESET_ALL}")
    if args.debug:
        print(f"{Fore.YELLOW}[*] Debug mode enabled{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop capturing{Style.RESET_ALL}\n")
    sensor.start_capture()
