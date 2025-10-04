#!/usr/bin/env python3
"""
Web-Based Network Monitor - No GUI Dependencies Required
Run this and open http://localhost:8080 in your browser
"""

import subprocess
import re
import time
import json
from datetime import datetime
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class NetworkMonitor:
    def __init__(self):
        self.devices = {}
        self.device_history = []
        self.monitoring = False
        self.scan_interval = 30
        self.network_range = "192.168.100.0/24"  # Force your correct network as default
        self.admin_email = "draguluvincent@gmail.com"
        self.email_alerts = False
        
    def ping_host(self, ip):
        """Check if host is alive"""
        try:
            result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False

    def get_mac_address(self, ip):
        """Get MAC address for an IP"""
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            pattern = rf'{re.escape(ip)}\s+([0-9a-f]{{2}}-[0-9a-f]{{2}}-[0-9a-f]{{2}}-[0-9a-f]{{2}}-[0-9a-f]{{2}}-[0-9a-f]{{2}})'
            match = re.search(pattern, result.stdout, re.IGNORECASE)
            return match.group(1) if match else "Unknown"
        except:
            return "Unknown"

    def get_hostname(self, ip):
        """Get hostname for an IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"

    def get_vendor_info(self, mac_address):
        """Get vendor information from MAC address"""
        vendor_map = {
            "00:50:56": "VMware", "08:00:27": "VirtualBox", "00:0C:29": "VMware",
            "00:1B:21": "Intel", "00:23:24": "Apple", "B8:27:EB": "Raspberry Pi",
            "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
            "00:11:22": "TP-Link", "AA:BB:CC": "D-Link", "44:55:66": "Netgear"
        }
        
        try:
            mac_clean = mac_address.replace('-', ':').upper()
            oui = mac_clean[:8]
            return vendor_map.get(oui, "Unknown")
        except:
            return "Unknown"

    def scan_network(self):
        """Scan network for active devices"""
        current_devices = {}
        network_base = self.network_range.split('/')[0].rsplit('.', 1)[0]
        
        print(f"Scanning network: {self.network_range}")
        
        for i in range(1, 255):
            ip = f"{network_base}.{i}"
            if self.ping_host(ip):
                mac = self.get_mac_address(ip)
                hostname = self.get_hostname(ip)
                vendor = self.get_vendor_info(mac)
                
                device_info = {
                    'ip': ip,
                    'mac': mac,
                    'hostname': hostname,
                    'vendor': vendor,
                    'first_seen': datetime.now().isoformat(),
                    'last_seen': datetime.now().isoformat(),
                    'status': 'online'
                }
                
                current_devices[ip] = device_info
                
                # Check if this is a new device
                if ip not in self.devices:
                    self.device_history.append({
                        'timestamp': datetime.now().isoformat(),
                        'event': 'NEW_DEVICE',
                        'device': device_info.copy()
                    })
                    print(f"NEW DEVICE DETECTED: {ip} ({hostname}) - {mac}")
                    
                    # Send email alert if enabled
                    if self.email_alerts and self.admin_email:
                        self.send_email_alert(device_info)
        
        # Update device statuses
        for ip in self.devices:
            if ip in current_devices:
                self.devices[ip].update(current_devices[ip])
                self.devices[ip]['last_seen'] = datetime.now().isoformat()
            else:
                self.devices[ip]['status'] = 'offline'
        
        # Add new devices
        for ip, device in current_devices.items():
            if ip not in self.devices:
                self.devices[ip] = device
        
        return current_devices

    def send_email_alert(self, device_info):
        """Send email alert for new device"""
        # This is a simplified version - you'd need to configure SMTP settings
        print(f"EMAIL ALERT: New device {device_info['hostname']} ({device_info['ip']}) joined network")
        
        # Add to event log
        self.device_history.append({
            'timestamp': datetime.now().isoformat(),
            'event': 'EMAIL_SENT',
            'message': f"Alert sent to {self.admin_email} for device {device_info['ip']}"
        })

    def get_status(self):
        """Get current monitoring status"""
        return {
            'monitoring': self.monitoring,
            'total_devices': len(self.devices),
            'online_devices': len([d for d in self.devices.values() if d['status'] == 'online']),
            'network_range': self.network_range,
            'last_scan': datetime.now().isoformat()
        }

class WebHandler(BaseHTTPRequestHandler):
    def __init__(self, monitor, *args, **kwargs):
        self.monitor = monitor
        super().__init__(*args, **kwargs)

    def do_GET(self):
        if self.path == '/':
            self.serve_html()
        elif self.path == '/api/devices':
            self.serve_devices()
        elif self.path == '/api/status':
            self.serve_status()
        elif self.path == '/api/scan':
            self.do_scan()
        elif self.path.startswith('/api/'):
            self.handle_api()
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path.startswith('/api/'):
            self.handle_api()
        else:
            self.send_error(404)

    def serve_html(self):
        html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Security Monitor</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh; padding: 20px;
        }
        .container { 
            max-width: 1200px; margin: 0 auto; background: rgba(255, 255, 255, 0.95);
            border-radius: 20px; box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1); overflow: hidden;
        }
        .header { 
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
            color: white; padding: 30px; text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .controls { background: #f8f9fa; padding: 25px; }
        .btn { 
            padding: 12px 24px; border: none; border-radius: 8px; font-size: 16px;
            font-weight: 600; cursor: pointer; margin: 5px; transition: all 0.3s ease;
        }
        .btn-primary { background: linear-gradient(135deg, #28a745, #20c997); color: white; }
        .btn-danger { background: linear-gradient(135deg, #dc3545, #e74c3c); color: white; }
        .btn-info { background: linear-gradient(135deg, #17a2b8, #3498db); color: white; }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 8px 20px rgba(0, 0, 0, 0.2); }
        .input-group { display: inline-block; margin: 10px; }
        .input-group label { display: block; font-weight: 600; margin-bottom: 5px; }
        .input-group input { padding: 10px; border: 2px solid #dee2e6; border-radius: 6px; width: 200px; }
        .main-content { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; padding: 25px; }
        .device-table { background: white; border-radius: 12px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1); }
        .table-header { background: linear-gradient(135deg, #6c757d, #495057); color: white; padding: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }
        th { background: #f8f9fa; font-weight: 600; }
        .device-online { background: linear-gradient(90deg, #d4edda, #c3e6cb); }
        .log-panel { background: white; border-radius: 12px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1); }
        .log-header { background: linear-gradient(135deg, #fd7e14, #e55100); color: white; padding: 20px; }
        .log-content { 
            padding: 20px; height: 400px; overflow-y: auto; background: #1a1a1a;
            color: #00ff41; font-family: 'Courier New', monospace; font-size: 14px;
        }
        .status { background: #e3f2fd; padding: 15px; border-radius: 8px; margin: 15px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Network Security Monitor</h1>
            <p>Real-time device detection and cybersecurity monitoring</p>
        </div>
        
        <div class="controls">
            <button class="btn btn-info" onclick="singleScan()">🔍 Single Scan</button>
            <button class="btn btn-primary" onclick="startMonitoring()">🚀 Start Monitoring</button>
            <button class="btn btn-danger" onclick="stopMonitoring()">⏹️ Stop</button>
            <button class="btn" onclick="exportReport()">📊 Export</button>
            
            <div class="input-group">
                <label>Network Range:</label>
                <input type="text" id="networkRange" value="192.168.100.0/24">
            </div>
            
            <div class="input-group">
                <label>Admin Email:</label>
                <input type="email" id="adminEmail" placeholder="admin@company.com">
            </div>
            
            <label style="margin: 15px;">
                <input type="checkbox" id="emailAlerts"> Enable Email Alerts
            </label>
            
            <div class="status">
                <div id="statusText">Status: Ready - Click "Single Scan" to detect devices</div>
            </div>
        </div>
        
        <div class="main-content">
            <div class="device-table">
                <div class="table-header">📱 Network Devices <span id="deviceCount">(0)</span></div>
                <table>
                    <thead>
                        <tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Vendor</th><th>Status</th><th>Seen</th></tr>
                    </thead>
                    <tbody id="deviceTable">
                        <tr><td colspan="6" style="text-align:center;padding:40px;">Click "Single Scan" to discover devices</td></tr>
                    </tbody>
                </table>
            </div>
            
            <div class="log-panel">
                <div class="log-header">🚨 Security Log</div>
                <div class="log-content" id="logContent">
[Ready] Network Monitor initialized<br>
[Info] Network set to 192.168.100.0/24<br>
[Ready] Click Single Scan to start...<br>
                </div>
            </div>
        </div>
    </div>

    <script>
        let scanning = false;
        
        function addLog(message) {
            const log = document.getElementById('logContent');
            const time = new Date().toLocaleTimeString();
            log.innerHTML += `[${time}] ${message}<br>`;
            log.scrollTop = log.scrollHeight;
        }
        
        function updateStatus(message) {
            document.getElementById('statusText').textContent = `Status: ${message}`;
        }
        
        async function singleScan() {
            if (scanning) return;
            scanning = true;
            
            updateStatus('Scanning network...');
            addLog('🔍 Starting network scan...');
            
            const networkRange = document.getElementById('networkRange').value;
            addLog(`Scanning range: ${networkRange}`);
            
            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        network_range: networkRange,
                        admin_email: document.getElementById('adminEmail').value,
                        email_alerts: document.getElementById('emailAlerts').checked
                    })
                });
                
                const data = await response.json();
                updateDeviceTable(data.devices);
                updateStatus(`Found ${Object.keys(data.devices).length} devices`);
                addLog(`✅ Scan complete - Found ${Object.keys(data.devices).length} devices`);
                
                if (data.new_devices && data.new_devices.length > 0) {
                    data.new_devices.forEach(device => {
                        addLog(`🚨 NEW DEVICE: ${device.ip} (${device.hostname})`);
                    });
                }
                
            } catch (error) {
                addLog(`❌ Scan error: ${error.message}`);
                updateStatus('Scan failed');
            }
            
            scanning = false;
        }
        
        function updateDeviceTable(devices) {
            const tbody = document.getElementById('deviceTable');
            const count = document.getElementById('deviceCount');
            
            if (Object.keys(devices).length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:40px;color:#dc3545;">No devices found - Check network connection</td></tr>';
                count.textContent = '(0)';
                return;
            }
            
            tbody.innerHTML = Object.values(devices).map(device => `
                <tr class="device-${device.status}">
                    <td><strong>${device.ip}</strong></td>
                    <td>${device.hostname}</td>
                    <td>${device.mac}</td>
                    <td>${device.vendor}</td>
                    <td><span style="color: ${device.status === 'online' ? '#28a745' : '#dc3545'}">
                        ${device.status === 'online' ? '🟢' : '🔴'} ${device.status}
                    </span></td>
                    <td>${new Date(device.first_seen).toLocaleTimeString()}</td>
                </tr>
            `).join('');
            
            count.textContent = `(${Object.keys(devices).length})`;
        }
        
        async function startMonitoring() {
            addLog('🔄 Starting continuous monitoring...');
            updateStatus('Monitoring active');
            
            // Scan every 30 seconds
            setInterval(singleScan, 30000);
            singleScan(); // Initial scan
        }
        
        function stopMonitoring() {
            addLog('⏹️ Monitoring stopped');
            updateStatus('Stopped');
        }
        
        function exportReport() {
            const report = {
                timestamp: new Date().toISOString(),
                network_range: document.getElementById('networkRange').value,
                devices: JSON.parse(document.getElementById('deviceTable').dataset.devices || '{}')
            };
            
            const blob = new Blob([JSON.stringify(report, null, 2)], {type: 'application/json'});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `network_report_${new Date().toISOString().slice(0,19).replace(/:/g, '-')}.json`;
            a.click();
            
            addLog('📁 Report exported');
        }
    </script>
</body>
</html>"""
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html_content.encode())

    def handle_api(self):
        if self.path == '/api/scan' and self.command == 'POST':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            # Update settings
            self.monitor.network_range = data.get('network_range', '192.168.100.0/24')
            self.monitor.admin_email = data.get('admin_email', 'draguluvincent@mail.com')
            self.monitor.email_alerts = data.get('email_alerts', False)
            
            # Perform scan
            old_devices = set(self.monitor.devices.keys())
            current_devices = self.monitor.scan_network()
            new_devices = [self.monitor.devices[ip] for ip in current_devices.keys() if ip not in old_devices]
            
            response = {
                'devices': self.monitor.devices,
                'new_devices': new_devices,
                'status': 'success'
            }
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response, default=str).encode())
        
        elif self.path == '/api/devices':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(self.monitor.devices, default=str).encode())
        
        elif self.path == '/api/status':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(self.monitor.get_status(), default=str).encode())

def create_handler(monitor):
    def handler(*args, **kwargs):
        WebHandler(monitor, *args, **kwargs)
    return handler

def main():
    monitor = NetworkMonitor()
    
    print("🔐 Network Security Monitor - Web Version")
    print("=" * 50)
    print("Starting web server...")
    
    # Try multiple ports if one is blocked
    ports_to_try = [8080, 8000, 8888, 9000, 3000, 5000]
    server = None
    
    for port in ports_to_try:
        try:
            handler = create_handler(monitor)
            server = HTTPServer(('localhost', port), handler)
            print(f"✅ Server started successfully!")
            print(f"🌐 Open your browser and go to: http://localhost:{port}")
            print("📱 Or try: http://127.0.0.1:{port}")
            print("⏹️  Press Ctrl+C to stop")
            print("=" * 50)
            break
        except PermissionError:
            print(f"❌ Port {port} blocked, trying next port...")
        except OSError as e:
            print(f"❌ Port {port} unavailable ({e}), trying next port...")
    
    if server is None:
        print("\n❌ Could not start server on any port!")
        print("\n🔧 Try these solutions:")
        print("1. Run Command Prompt as Administrator")
        print("2. Check Windows Firewall settings")
        print("3. Close other programs using these ports")
        print("4. Use the simple version below instead:")
        print("\n" + "="*50)
        
        # Fallback to command-line version
        print("🔍 Running simple network scan instead...")
        devices = monitor.scan_network()
        
        print(f"\n📊 Found {len(devices)} devices on network {monitor.network_range}:")
        print("-" * 80)
        print(f"{'IP Address':<15} {'Hostname':<20} {'MAC Address':<18} {'Vendor':<15} {'Status'}")
        print("-" * 80)
        
        for ip, device in devices.items():
            print(f"{device['ip']:<15} {device['hostname']:<20} {device['mac']:<18} {device['vendor']:<15} {device['status']}")
        
        if len(devices) == 0:
            print("⚠️  No devices found. Check your network connection.")
            print("💡 Make sure you're connected to your office WiFi")
        
        return
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n⏹️  Shutting down server...")
        server.shutdown()
        print("✅ Server stopped successfully!")

if __name__ == "__main__":
    main()