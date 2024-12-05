from flask import Flask, render_template, jsonify, request, Response, redirect, url_for
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
    'admin': generate_password_hash('changeme!')
}

class LogReader:
    def __init__(self, log_dir="logs"):
        self.log_dir = log_dir
        self.current_position = {}
        os.makedirs(log_dir, exist_ok=True)

    def get_current_log_file(self):
        return os.path.join(self.log_dir, f"{datetime.now().strftime('%Y-%m-%d')}.log")

    def read_new_logs(self):
        log_file = self.get_current_log_file()
        
        if not os.path.exists(log_file):
            return []

        # Initialize position for new files
        if log_file not in self.current_position:
            self.current_position[log_file] = 0

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

def check_auth(username, password):
    """Check if a username / password combination is valid."""
    return username in USERS and check_password_hash(USERS.get(username), password)

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

@app.route('/')
@requires_auth
def index():
    return render_template('index.html')

@app.route('/events')
@requires_auth
def get_events():
    def generate():
        while True:
            # Get new log entries
            new_logs = log_reader.read_new_logs()
            
            if new_logs:
                for line in new_logs:
                    # Format the log entry as a server-sent event
                    yield f"data: {json.dumps({'message': line.strip()})}\n\n"
            
            time.sleep(1)  # Wait before checking for new logs

    return Response(generate(), mimetype='text/event-stream')

if __name__ == '__main__':
    print("Starting Network Security Monitor Server...")
    print("Access the web interface at: http://localhost:8338")
    print("Default credentials: admin / changeme!")
    app.run(host='0.0.0.0', port=8338, threaded=True)
