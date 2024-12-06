from flask import Flask, render_template, jsonify, request, Response, redirect, url_for, session
import os
from datetime import datetime
import json
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
import time

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this to a secure secret key

# User credentials (in a real application, use a proper database)
USERS = {
    'admin': generate_password_hash('123')
}

class LogReader:
    def __init__(self, log_dir="logs"):
        self.log_dir = log_dir
        self.current_position = {}
        os.makedirs(log_dir, exist_ok=True)

    def get_current_log_file(self):
        return os.path.join(self.log_dir, f"{datetime.now().strftime('%Y-%m-%d')}.log")

    def read_existing_logs(self, max_lines=1000):
        """Read existing logs from the current day's log file"""
        log_file = self.get_current_log_file()
        
        if not os.path.exists(log_file):
            return []

        try:
            with open(log_file, 'r') as f:
                # Read last max_lines lines
                lines = f.readlines()[-max_lines:]
                return lines
        except Exception as e:
            print(f"Error reading existing logs: {str(e)}")
            return []

    def read_new_logs(self):
        log_file = self.get_current_log_file()
        
        if not os.path.exists(log_file):
            return []

        # Initialize position for new files
        if log_file not in self.current_position:
            self.current_position[log_file] = os.path.getsize(log_file)
            return self.read_existing_logs()  # Return existing logs on first connect

        try:
            with open(log_file, 'r') as f:
                # Get file size
                f.seek(0, 2)
                file_size = f.tell()

                # If file has been truncated, reset position
                if file_size < self.current_position[log_file]:
                    self.current_position[log_file] = 0

                # If there's new content
                if file_size > self.current_position[log_file]:
                    f.seek(self.current_position[log_file])
                    new_lines = f.readlines()
                    self.current_position[log_file] = file_size
                    return new_lines

        except Exception as e:
            print(f"Error reading log file: {str(e)}")
            return []

        return []

# Initialize LogReader
log_reader = LogReader()

# Configuration file path
CONFIG_FILE = "config.json"

def load_config():
    """Load configuration from file"""
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Config file not found: {CONFIG_FILE}")
        return {}
    except json.JSONDecodeError:
        print(f"Error decoding config file: {CONFIG_FILE}")
        return {}
    except Exception as e:
        print(f"Error loading config: {str(e)}")
        return {}

def get_default_config():
    """Get default configuration from config.json"""
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading default config: {str(e)}")
        return {}

def merge_configs(default_config, user_config):
    """Recursively merge user config with default config"""
    merged = default_config.copy()
    
    for key, value in user_config.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = merge_configs(merged[key], value)
        else:
            merged[key] = value
            
    return merged

def save_config(config):
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving config: {str(e)}")
        return False

def check_auth(username, password):
    """Check if a username / password combination is valid."""
    return username in USERS and check_password_hash(USERS.get(username), password)

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})

@app.context_processor
def utility_processor():
    return {
        'map': map,
        'str': str,
        'list': list
    }

@app.route('/')
@requires_auth
def index():
    """Render the main page"""
    return render_template('index.html')

@app.route('/events')
@requires_auth
def get_events():
    """Event stream for real-time updates"""
    def generate():
        # Initialize file position for new logs only
        log_file = log_reader.get_current_log_file()
        if log_file not in log_reader.current_position:
            log_reader.current_position[log_file] = os.path.getsize(log_file)

        while True:
            # Get new log entries
            new_logs = log_reader.read_new_logs()
            
            # Send new logs to client
            for log in new_logs:
                yield f"data: {json.dumps({'message': log.strip()})}\n\n"
            
            # If no new logs, send keep-alive comment
            if not new_logs:
                yield ": keep-alive\n\n"
            
            time.sleep(1)

    return Response(generate(), mimetype='text/event-stream')

@app.route('/config')
@requires_auth
def config():
    """Render the configuration page"""
    # Load default configuration from config.json
    default_config = get_default_config()
    
    # Load user's current configuration
    user_config = load_config()
    
    # Merge configurations, with user config taking precedence
    config_data = merge_configs(default_config, user_config)
    
    return render_template('config.html', config=config_data)

@app.route('/api/config', methods=['GET'])
@requires_auth
def get_config():
    """API endpoint to get current configuration"""
    return jsonify(load_config())

@app.route('/api/config', methods=['POST'])
@requires_auth
def update_config():
    """Update configuration"""
    try:
        # Get the current config
        current_config = load_config()
        
        # Get the form data
        form_data = request.get_json()
        
        # Determine which section is being updated based on form fields
        if 'LOG_DIR' in form_data or 'LOG_LEVEL' in form_data:
            # General Settings
            if 'LOG_DIR' in form_data:
                current_config['GENERAL_SETTINGS']['LOG_DIR'] = form_data['LOG_DIR']
            if 'LOG_LEVEL' in form_data:
                current_config['GENERAL_SETTINGS']['LOG_LEVEL'] = form_data['LOG_LEVEL']
            if 'INTERFACE' in form_data:
                current_config['GENERAL_SETTINGS']['INTERFACE'] = form_data['INTERFACE']
            if 'CAPTURE_TIMEOUT' in form_data:
                current_config['GENERAL_SETTINGS']['CAPTURE_TIMEOUT'] = int(form_data['CAPTURE_TIMEOUT'])
                
        elif 'BLACKLISTED_IPS' in form_data or 'WHITELISTED_IPS' in form_data:
            # IP Rules
            if 'BLACKLISTED_IPS' in form_data:
                current_config['IP_RULES']['BLACKLISTED_IPS'] = [ip.strip() for ip in form_data['BLACKLISTED_IPS'].split('\n') if ip.strip()]
            if 'WHITELISTED_IPS' in form_data:
                current_config['IP_RULES']['WHITELISTED_IPS'] = [ip.strip() for ip in form_data['WHITELISTED_IPS'].split('\n') if ip.strip()]
            if 'IP_RANGES' in form_data:
                current_config['IP_RULES']['IP_RANGES_TO_MONITOR'] = [ip.strip() for ip in form_data['IP_RANGES'].split('\n') if ip.strip()]
            if 'MAX_CONNECTIONS_PER_IP' in form_data:
                current_config['IP_RULES']['MAX_CONNECTIONS_PER_IP'] = int(form_data['MAX_CONNECTIONS_PER_IP'])
            if 'CONNECTION_TIMEOUT' in form_data:
                current_config['IP_RULES']['CONNECTION_TIMEOUT'] = int(form_data['CONNECTION_TIMEOUT'])
                
        elif 'SUSPICIOUS_PORTS' in form_data or 'ALLOWED_PORTS' in form_data:
            # Port Rules
            if 'SUSPICIOUS_PORTS' in form_data:
                current_config['PORT_RULES']['SUSPICIOUS_PORTS'] = [int(port.strip()) for port in form_data['SUSPICIOUS_PORTS'].split('\n') if port.strip().isdigit()]
            if 'ALLOWED_PORTS' in form_data:
                current_config['PORT_RULES']['ALLOWED_PORTS'] = [int(port.strip()) for port in form_data['ALLOWED_PORTS'].split('\n') if port.strip().isdigit()]
            if 'PORT_SCAN_ENABLED' in form_data:
                current_config['PORT_RULES']['PORT_SCAN_DETECTION']['ENABLED'] = form_data['PORT_SCAN_ENABLED'] == 'true'
            if 'PORT_SCAN_THRESHOLD' in form_data:
                current_config['PORT_RULES']['PORT_SCAN_DETECTION']['THRESHOLD'] = int(form_data['PORT_SCAN_THRESHOLD'])
            if 'TIME_WINDOW' in form_data:
                current_config['PORT_RULES']['PORT_SCAN_DETECTION']['TIME_WINDOW'] = int(form_data['TIME_WINDOW'])
                
        elif 'DNS_BLACKLIST' in form_data or 'SUSPICIOUS_TLD' in form_data:
            # DNS Rules
            if 'DNS_BLACKLIST' in form_data:
                current_config['DNS_RULES']['DNS_BLACKLIST'] = [domain.strip() for domain in form_data['DNS_BLACKLIST'].split('\n') if domain.strip()]
            if 'DGA_DETECTION_ENABLED' in form_data:
                current_config['DNS_RULES']['DGA_DETECTION']['ENABLED'] = form_data['DGA_DETECTION_ENABLED'] == 'true'
            if 'MIN_ENTROPY' in form_data:
                current_config['DNS_RULES']['DGA_DETECTION']['MIN_ENTROPY'] = float(form_data['MIN_ENTROPY'])
            if 'MIN_LENGTH' in form_data:
                current_config['DNS_RULES']['DGA_DETECTION']['MIN_LENGTH'] = int(form_data['MIN_LENGTH'])
            if 'CONSONANT_THRESHOLD' in form_data:
                current_config['DNS_RULES']['DGA_DETECTION']['CONSONANT_THRESHOLD'] = float(form_data['CONSONANT_THRESHOLD'])
            if 'CACHE_TIMEOUT' in form_data:
                current_config['DNS_RULES']['DNS_MONITORING']['CACHE_TIMEOUT'] = int(form_data['CACHE_TIMEOUT'])
            if 'MAX_QUERIES_PER_DOMAIN' in form_data:
                current_config['DNS_RULES']['DNS_MONITORING']['MAX_QUERIES_PER_DOMAIN'] = int(form_data['MAX_QUERIES_PER_DOMAIN'])
            if 'SUSPICIOUS_TLD' in form_data:
                current_config['DNS_RULES']['DNS_MONITORING']['SUSPICIOUS_TLD'] = [tld.strip() for tld in form_data['SUSPICIOUS_TLD'].split('\n') if tld.strip()]
        
        # Save the updated config
        save_config(current_config)
        
        return jsonify({'status': 'success'})
    except Exception as e:
        print(f"Error updating config: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/api/config/section/<section>', methods=['POST'])
@requires_auth
def update_config_section(section):
    """API endpoint to update a specific configuration section"""
    try:
        config = load_config()
        new_section_data = request.json
        config[section] = new_section_data
        if save_config(config):
            return jsonify({"status": "success", "message": f"{section} configuration updated successfully"})
        else:
            return jsonify({"status": "error", "message": "Failed to save configuration"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    print("Starting Network Security Monitor Server...")
    print("Access the web interface at: http://localhost:8338")
    print("Default credentials: admin / 123")
    app.run(host='0.0.0.0', port=8338, threaded=True)
