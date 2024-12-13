import os
from datetime import datetime
import re
from typing import Dict, Any, Optional
import threading

class DetailedLogger:
    def __init__(self, log_dir: str = "logs"):
        """
        Initialize Detailed Logger
        
        Args:
            log_dir (str): Directory to store log files
        """
        self.log_dir = log_dir
        self.lock = threading.Lock()
        os.makedirs(log_dir, exist_ok=True)
        
    def _get_log_file(self) -> str:
        """Get the current log file path"""
        today = datetime.now().strftime('%Y-%m-%d')
        return os.path.join(self.log_dir, f"{today}.log")
    
    def _format_value(self, value: Any) -> str:
        """Format a value for logging"""
        if isinstance(value, (list, tuple)):
            return ', '.join(str(v) for v in value)
        return str(value)
    
    def _format_log_entry(self, 
                         event_type: str, 
                         data: Dict[str, Any], 
                         source: Optional[str] = None) -> str:
        """
        Format the log entry in a standardized way
        
        Args:
            event_type (str): Type of event (e.g., 'NETWORK_TRAFFIC', 'SECURITY_ALERT')
            data (dict): The actual event data
            source (str, optional): Source of the event (e.g., 'sensor', 'server')
            
        Returns:
            str: Formatted log entry
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
        
        # Format the data dictionary into key=value pairs
        details = []
        
        # Add source if provided
        if source:
            details.append(f"source={source}")
            
        # Format nested dictionaries and lists
        for key, value in data.items():
            if isinstance(value, dict):
                # Handle nested dictionaries
                for sub_key, sub_value in value.items():
                    formatted_key = f"{key}_{sub_key}"
                    details.append(f"{formatted_key}={self._format_value(sub_value)}")
            else:
                # Handle regular key-value pairs
                details.append(f"{key}={self._format_value(value)}")
        
        # Combine all parts into log format
        return f"{timestamp} - {event_type} - {' - '.join(details)}"
    
    def log_event(self, 
                  event_type: str, 
                  data: Dict[str, Any], 
                  source: Optional[str] = None) -> None:
        """
        Log an event to the log file
        
        Args:
            event_type (str): Type of event
            data (dict): Event data
            source (str, optional): Source of the event
        """
        entry = self._format_log_entry(event_type, data, source)
        
        with self.lock:
            log_file = self._get_log_file()
            try:
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(entry + '\n')
            except Exception as e:
                print(f"Error writing to log file: {str(e)}")
                
    def log_network_event(self,
                         source_ip: str,
                         destination_ip: str,
                         protocol: str,
                         source_port: int,
                         destination_port: int,
                         payload_size: int,
                         flags: Dict[str, bool] = None) -> None:
        """
        Log a network traffic event
        """
        data = {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": protocol,
            "source_port": source_port,
            "destination_port": destination_port,
            "payload_size": payload_size
        }
        if flags:
            data["flags"] = ','.join(flag for flag, value in flags.items() if value)
            
        self.log_event("NETWORK_TRAFFIC", data, "sensor")

    def get_log_entry_by_timestamp(self, timestamp: str) -> Optional[str]:
        """
        Get a specific log entry by its timestamp.

        Args:
            timestamp (str): The timestamp of the log entry.

        Returns:
            Optional[str]: The log entry if found, None otherwise.
        """
        date_str = timestamp.split(" ")[0]
        log_file = os.path.join(self.log_dir, f"{date_str}.log")
        if not os.path.exists(log_file):
            return None

        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    # Use a regular expression for flexible matching
                    pattern = re.escape(timestamp).replace(r"\\ ", r"[\s]*")  # Allow 0 or more spaces
                    if re.search(pattern, line):
                        return line.strip()
            return None  # Timestamp not found in the log file
        except Exception as e:
            print(f"Error reading log file: {str(e)}")
            return None