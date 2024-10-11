from flask import Flask, render_template
import threading

app = Flask(__name__)

# Store logs in memory
firewall_logs = []

@app.route('/')
def index():
    return render_template('index.html', logs=firewall_logs)

def run_app():
    app.run(host='0.0.0.0', port=5000)
