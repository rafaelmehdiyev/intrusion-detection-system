from flask import Flask, render_template, jsonify, request, Response, redirect, url_for, session, send_file
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
    def __init__(self, log_dir):
        self.log_dir = log_dir
        self.current_date = None
        self.current_file = None
        self.last_position = 0
        self._ensure_log_file()

    def _ensure_log_file(self):
        """Ensure the correct log file exists for the current date"""
        today = datetime.now().date()
        
        # If it's a new day or no file is open
        if self.current_date != today:
            # Close the current file if it's open
            if self.current_file:
                self.current_file.close()
                self.current_file = None
            
            # Update the current date
            self.current_date = today
            
            # Create new log file if it doesn't exist
            log_file = self.get_current_log_file()
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            if not os.path.exists(log_file):
                with open(log_file, 'w') as f:
                    f.write(f"--- Log file created on {today} ---\n")
            
            # Reset the position
            self.last_position = 0

    def get_current_log_file(self):
        """Get the path to the current day's log file"""
        today = datetime.now().date()
        return os.path.join(self.log_dir, f"{today}.log")

    def read_new_logs(self):
        """Read new logs from the current day's file"""
        self._ensure_log_file()  # Check if we need to create a new day's file
        
        log_file = self.get_current_log_file()
        if not os.path.exists(log_file):
            return []

        try:
            with open(log_file, 'r') as f:
                f.seek(self.last_position)
                new_logs = f.readlines()
                self.last_position = f.tell()
                return new_logs
        except Exception as e:
            print(f"Error reading logs: {e}")
            return []

    def write_log(self, level, message):
        """Write a new log entry"""
        self._ensure_log_file()  # Check if we need to create a new day's file
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
        log_entry = f"{timestamp} - {level} - {message}\n"
        
        log_file = self.get_current_log_file()
        try:
            with open(log_file, 'a') as f:
                f.write(log_entry)
        except Exception as e:
            print(f"Error writing log: {e}")

class JsonLogReader:
    def __init__(self, json_log_dir):
        self.log_dir = json_log_dir
        self.current_date = None
        self.current_position = 0
        self._ensure_log_file()

    def _ensure_log_file(self):
        today = datetime.now().date()
        if self.current_date != today:
            self.current_date = today
            self.current_position = 0
            os.makedirs(self.log_dir, exist_ok=True)

    def get_current_log_file(self):
        return os.path.join(self.log_dir, f"{self.current_date}.json")

    def read_new_logs(self):
        self._ensure_log_file()
        log_file = self.get_current_log_file()
        
        if not os.path.exists(log_file):
            return []

        try:
            with open(log_file, 'r') as f:
                data = json.load(f)
                new_events = data[self.current_position:]
                self.current_position = len(data)
                return new_events
        except Exception as e:
            print(f"Error reading JSON logs: {e}")
            return []


# Initialize LogReader
log_reader = LogReader("logs")
json_log_reader = JsonLogReader("logs/json")

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
        # Set initial position to current file size when client connects
        log_file = log_reader.get_current_log_file()
        if os.path.exists(log_file):
            log_reader.last_position = os.path.getsize(log_file)
        
        # Do the same for JSON log reader
        json_file = json_log_reader.get_current_log_file()
        if os.path.exists(json_file):
            json_log_reader.current_position = os.path.getsize(json_file)
        
        # Send initial connection message
        yield f"data: {json.dumps({'type': 'system', 'message': 'Connected to event stream'})}\n\n"
        
        while True:
            # Get regular logs
            new_logs = log_reader.read_new_logs()
            
            # Get JSON logs
            new_json_logs = json_log_reader.read_new_logs()
            
            # Send regular logs
            for log in new_logs:
                yield f"data: {json.dumps({'type': 'log', 'message': log.strip()})}\n\n"
            
            # Send JSON logs with type identifier
            for log in new_json_logs:
                yield f"data: {json.dumps({'type': 'json', 'message': log})}\n\n"
            
            # Keep-alive
            if not new_logs and not new_json_logs:
                yield ": keep-alive\n\n"
            
            time.sleep(1)

    return Response(generate(), mimetype='text/event-stream')

@app.route('/logs')
@requires_auth
def logs():
    """Render the logs page"""
    return render_template('logs.html')

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

@app.route('/api/logs/today')
@requires_auth
def get_today_logs():
    """API endpoint to get all logs from today"""
    try:
        log_file = log_reader.get_current_log_file()
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                logs = f.readlines()
                return jsonify({
                    'logs': [log.strip() for log in logs],
                    'count': len(logs)
                })
        return jsonify({'logs': [], 'count': 0})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs/download')
@requires_auth
def download_logs():
    """Download today's logs as a text file"""
    try:
        log_file = log_reader.get_current_log_file()
        if os.path.exists(log_file):
            return send_file(
                log_file,
                mimetype='text/plain',
                as_attachment=True,
                download_name=f'security_logs_{datetime.now().strftime("%Y-%m-%d")}.txt'
            )
        return jsonify({'error': 'No logs found for today'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs/dates')
@requires_auth
def get_available_log_dates():
    """Get list of dates that have log files"""
    try:
        available_dates = []
        for file in os.listdir(log_reader.log_dir):
            if file.endswith('.log'):
                date_str = file[:-4]  # Remove .log extension
                try:
                    # Validate it's a proper date
                    datetime.strptime(date_str, '%Y-%m-%d')
                    available_dates.append(date_str)
                except ValueError:
                    continue
        return jsonify({
            'dates': sorted(available_dates, reverse=True),
            'current': datetime.now().strftime('%Y-%m-%d')
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs/<date>')
@requires_auth
def get_logs_for_date(date):
    """Get logs for a specific date"""
    try:
        # Validate date format
        try:
            datetime.strptime(date, '%Y-%m-%d')
        except ValueError:
            return jsonify({'error': 'Invalid date format'}), 400

        log_file = os.path.join(log_reader.log_dir, f"{date}.log")
        if not os.path.exists(log_file):
            return jsonify({'error': 'No logs found for this date'}), 404

        with open(log_file, 'r') as f:
            logs = f.readlines()
            return jsonify({
                'logs': [log.strip() for log in logs],
                'count': len(logs)
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("Starting Network Security Monitor Server...")
    print("Access the web interface at: http://localhost:8338")
    print("Default credentials: admin / 123")
    app.run(host='0.0.0.0', port=8338, threaded=True)
