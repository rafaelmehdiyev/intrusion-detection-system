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
        self.dns_cache_timeout = 1.0
        self.running = True
        self.stats_thread = None
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        # Load configuration
        try:
            with open(config_path, 'r') as f:
                self.config = json.load(f)
        except Exception as e:
            print(f"Error loading config: {str(e)}")
            self.config = {
                "BLACKLISTED_IPS": [],
                "SUSPICIOUS_PORTS": [22, 23, 3389],
                "DNS_BLACKLIST": []
            }

        # Setup logging
        log_dir = "logs"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        log_file = os.path.join(log_dir, f"{datetime.now().strftime('%Y-%m-%d')}.log")
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

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
        """Add a security alert (not DNS queries)"""
        try:
            with self.display_lock:
                timestamp = datetime.now().strftime('%H:%M:%S')
                color = Fore.YELLOW if alert_type == "WARNING" else Fore.RED if alert_type == "ALERT" else Fore.WHITE
                formatted_alert = f"{color}[{timestamp}] {alert_msg}{Style.RESET_ALL}"
                self.alert_history.append(formatted_alert)
                self.alert_count += 1
                logging.warning(f"Alert: {alert_msg}")  
        except Exception as e:
            logging.error(f"Error adding alert: {str(e)}")

    def analyze_dns(self, packet, dns_packet):
        """Analyze DNS packet with proper counting"""
        try:
            if dns_packet.qr != 0:  
                return

            query_name = dns_packet.qd.qname.decode('utf-8').rstrip('.')
            current_time = time.time()

            with self.display_lock:
                if query_name in self.recent_dns_queries:
                    last_seen = self.recent_dns_queries[query_name]
                    if current_time - last_seen < self.dns_cache_timeout:
                        return  

                self.recent_dns_queries[query_name] = current_time
                
                self.recent_dns_queries = {
                    k: v for k, v in self.recent_dns_queries.items()
                    if current_time - v < self.dns_cache_timeout
                }

                self.dns_query_count += 1
                timestamp = datetime.now().strftime('%H:%M:%S')
                formatted_msg = f"{Fore.BLUE}[{timestamp}] DNS Query: {query_name}{Style.RESET_ALL}"
                self.alert_history.append(formatted_msg)
                logging.info(f"DNS Query: {query_name}")
                
                if any(blocked in query_name for blocked in self.config["DNS_BLACKLIST"]):
                    self.add_alert(f"Suspicious DNS query detected: {query_name}", "ALERT")
                
                if len(query_name) > 50:
                    self.add_alert(f"Unusually long domain name detected: {query_name}", "WARNING")
                    
        except Exception as e:
            logging.error(f"Error analyzing DNS packet: {str(e)}")

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
            logging.info(f"Blacklisted IPs: {', '.join(self.config['BLACKLISTED_IPS'])}")
            logging.info(f"Suspicious ports: {', '.join(map(str, self.config['SUSPICIOUS_PORTS']))}")

            self.start_time = time.time()
            
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
        try:
            with self.display_lock:
                self.packet_count += 1
            
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                if src_ip in self.config["BLACKLISTED_IPS"] or dst_ip in self.config["BLACKLISTED_IPS"]:
                    self.add_alert(f"Detected traffic from/to blacklisted IP - Src: {src_ip}, Dst: {dst_ip}", "ALERT")
                    return

                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    
                    if dst_port in self.config["SUSPICIOUS_PORTS"]:
                        self.add_alert(f"Suspicious port access detected - Src: {src_ip}:{src_port}, Dst: {dst_ip}:{dst_port}", "WARNING")

                elif UDP in packet and DNS in packet:
                    self.analyze_dns(packet, packet[DNS])
                    
        except Exception as e:
            logging.error(f"Error in packet callback: {str(e)}")

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
