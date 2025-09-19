from flask import Flask, request, jsonify
from datetime import datetime
import os
import json

# Delta decompression function
def delta_decode(deltas):
    """
    Decode delta-encoded values back to original values.
    This is the inverse of the deltaEncode function used on the device.
    """
    if not deltas:
        return []
    
    # First value is the original value, rest are deltas
    decoded = [deltas[0]]
    
    for i in range(1, len(deltas)):
        # Add the delta to the previous decoded value
        decoded.append(decoded[-1] + deltas[i])
    
    return decoded

def scale_back_float(scaled_int, scale):
    """
    Convert scaled integer back to float value.
    This reverses the scaleFloat function used on the device.
    """
    return scaled_int / (10.0 ** scale)

app = Flask(__name__)

# In-memory database substitute
DATA_STORAGE = []
COMPRESSION_REPORTS = []

@app.route("/")
def index():
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>EcoWatt Cloud - Device Data Monitor</title>
        <style>
            body { 
                font-family: Arial, sans-serif; 
                margin: 20px; 
                background-color: #f5f5f5;
            }
            .header {
                background-color: #2c3e50;
                color: white;
                padding: 20px;
                border-radius: 10px;
                margin-bottom: 20px;
            }
            .status { 
                color: #27ae60; 
                font-weight: bold; 
                font-size: 18px;
            }
            .stats {
                background-color: white;
                padding: 15px;
                border-radius: 8px;
                margin-bottom: 20px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            .table-container {
                background-color: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                margin-bottom: 20px;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 10px;
            }
            th, td {
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }
            th {
                background-color: #3498db;
                color: white;
                font-weight: bold;
            }
            tr:hover {
                background-color: #f5f5f5;
            }
            .field-details {
                font-size: 11px;
                color: #666;
                max-width: 200px;
                word-wrap: break-word;
            }
            .timestamp {
                font-family: monospace;
                font-size: 11px;
            }
            .device-id {
                font-weight: bold;
                color: #e74c3c;
            }
            .no-data {
                text-align: center;
                color: #7f8c8d;
                padding: 40px;
                font-style: italic;
            }
            .refresh-indicator {
                position: fixed;
                top: 10px;
                right: 10px;
                background-color: #27ae60;
                color: white;
                padding: 5px 10px;
                border-radius: 15px;
                font-size: 12px;
                opacity: 0;
                transition: opacity 0.3s;
            }
            .refresh-indicator.show {
                opacity: 1;
            }
            .links {
                background-color: white;
                padding: 15px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            .links a {
                margin: 0 15px 0 0;
                text-decoration: none;
                color: #3498db;
                font-weight: bold;
            }
            .links a:hover {
                text-decoration: underline;
            }
            .field-card {
                border: 1px solid #ddd;
                border-radius: 8px;
                padding: 15px;
                margin: 10px;
                background-color: #f9f9f9;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            .field-card h4 {
                color: #007bff;
                margin: 0 0 10px 0;
                border-bottom: 1px solid #ddd;
                padding-bottom: 5px;
            }
            .field-details div {
                margin: 5px 0;
                font-size: 14px;
            }
            .payload-section {
                background-color: #e8f4f8;
                padding: 10px;
                border-radius: 5px;
                margin-top: 10px;
                border-left: 4px solid #007bff;
            }
            .original-values {
                background-color: #e8f5e8;
                padding: 8px;
                border-radius: 3px;
                margin-top: 5px;
                border-left: 3px solid #28a745;
                font-weight: bold;
            }
            .fields-container {
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔋 EcoWatt Cloud - Device Data Monitor</h1>
            <p class="status">✅ Backend Running</p>
        </div>
        
        <div class="stats">
            <h3>📊 Live Statistics</h3>
            <p><strong>Total Reports Received:</strong> <span id="totalReports">0</span></p>
            <p><strong>Last Update:</strong> <span id="lastUpdate">Never</span></p>
            <p><strong>Auto-refresh:</strong> Every 2 seconds</p>
        </div>
        
        <div class="table-container">
            <h3>📡 Latest Device Compression Reports</h3>
            <div id="tableContent">
                <div class="no-data">
                    Waiting for device data... Send JSON data to <code>POST /upload</code>
                </div>
            </div>
        </div>
        
        <div class="links">
            <h3>🔗 Quick Links</h3>
            <a href="/compression_display">📊 Detailed View</a>
            <a href="/compression_report">📝 Raw JSON API</a>
            <a href="/api/latest_data">🔌 Live Data API</a>
        </div>
        
        <div class="refresh-indicator" id="refreshIndicator">
            🔄 Updating...
        </div>
        
        <script>
            let lastUpdateTime = 0;
            
            function showRefreshIndicator() {
                const indicator = document.getElementById('refreshIndicator');
                indicator.classList.add('show');
                setTimeout(() => {
                    indicator.classList.remove('show');
                }, 1000);
            }
            
            function formatTimestamp(timestamp) {
                return new Date().toLocaleTimeString();
            }
            
                        function createFieldsDisplay(fields) {
                let html = '<div class="fields-container">';
                for (const [fieldName, fieldData] of Object.entries(fields)) {
                    html += `
                        <div class="field-card">
                            <h4>${fieldName}</h4>
                            <div class="field-details">
                                <div><strong>Method:</strong> ${fieldData.method}</div>
                                <div><strong>Param ID:</strong> ${fieldData.param_id}</div>
                                <div><strong>Samples:</strong> ${fieldData.n_samples}</div>
                                <div><strong>Bytes Length:</strong> ${fieldData.bytes_len}</div>
                                <div><strong>CPU Time:</strong> ${fieldData.cpu_time_ms.toFixed(6)} ms</div>
                    `;
                    
                    if (fieldData.payload) {
                        html += `
                                <div class="payload-section">
                                    <div><strong>Compressed Payload:</strong> [${fieldData.payload.join(', ')}]</div>
                        `;
                        
                        if (fieldData.decompressed_payload) {
                            html += `
                                    <div><strong>Decompressed Values:</strong> [${fieldData.decompressed_payload.join(', ')}]</div>
                            `;
                        }
                        
                        if (fieldData.original_values) {
                            html += `
                                    <div class="original-values"><strong>Original Values:</strong> [${fieldData.original_values.map(v => v.toFixed(3)).join(', ')}]</div>
                            `;
                        }
                        
                        html += `</div>`;
                    }
                    
                    html += `
                            </div>
                        </div>
                    `;
                }
                html += '</div>';
                return html;
            }
            
            function updateTable(data) {
                const tableContent = document.getElementById('tableContent');
                const totalReports = document.getElementById('totalReports');
                const lastUpdate = document.getElementById('lastUpdate');
                
                if (data.data && data.data.length > 0) {
                    let tableHTML = `
                        <table>
                            <thead>
                                <tr>
                                    <th>Device ID</th>
                                    <th>Timestamp</th>
                                    <th>Fields Summary</th>
                                    <th>Received At</th>
                                </tr>
                            </thead>
                            <tbody>
                    `;
                    
                    // Show latest reports first
                    data.data.reverse().forEach(report => {
                        const fieldsCount = Object.keys(report.fields || {}).length;
                        tableHTML += `
                            <tr>
                                <td class="device-id">${report.device_id || 'Unknown'}</td>
                                <td class="timestamp">${report.timestamp || 'N/A'}</td>
                                <td>
                                    <strong>${fieldsCount} fields:</strong><br>
                                    ${createFieldsDisplay(report.fields || {})}
                                </td>
                                <td class="timestamp">${formatTimestamp()}</td>
                            </tr>
                        `;
                    });
                    
                    tableHTML += '</tbody></table>';
                    tableContent.innerHTML = tableHTML;
                } else {
                    tableContent.innerHTML = '<div class="no-data">No device data received yet. Waiting for JSON data...</div>';
                }
                
                totalReports.textContent = data.total_reports || 0;
                lastUpdate.textContent = formatTimestamp();
            }
            
            function fetchLatestData() {
                showRefreshIndicator();
                fetch('/api/latest_data')
                    .then(response => response.json())
                    .then(data => {
                        updateTable(data);
                    })
                    .catch(error => {
                        console.error('Error fetching data:', error);
                    });
            }
            
            // Initial load
            fetchLatestData();
            
            // Auto-refresh every 2 seconds
            setInterval(fetchLatestData, 2000);
        </script>
    </body>
    </html>
    """
    return html

# Device uploads compressed data every 15 min
@app.route("/upload", methods=["POST"])
def upload_data():
    try:
        payload = request.json
        if not payload:
            return jsonify({"status": "error", "message": "Invalid JSON"}), 400

        # Process and decompress the payload if it contains fields with payload data
        processed_payload = payload.copy()
        if "fields" in payload:
            for field_name, field_data in payload["fields"].items():
                if "payload" in field_data and field_data["payload"]:
                    # Decompress the delta-encoded payload
                    compressed_payload = field_data["payload"]
                    decompressed_values = delta_decode(compressed_payload)
                    
                    # Assuming scale factor of 3 for voltage/current/frequency measurements
                    # You may need to adjust this based on your device's scale factor
                    scale = 3 if field_name in ["AC_VOLTAGE", "AC_CURRENT", "AC_FREQUENCY"] else 0
                    original_values = [scale_back_float(val, scale) for val in decompressed_values]
                    
                    # Add decompressed data to the field
                    processed_payload["fields"][field_name]["decompressed_payload"] = decompressed_values
                    processed_payload["fields"][field_name]["original_values"] = original_values

        # Store the processed payload with decompressed data
        record = {
            "received_at": datetime.utcnow().isoformat(),
            "device_data": processed_payload
        }
        DATA_STORAGE.append(record)

        # If the payload contains compression report data, store it separately for easy access
        if "fields" in processed_payload:
            # This looks like compression report data
            COMPRESSION_REPORTS.append(processed_payload)

        # Reply with ACK and config stub
        return jsonify({
            "status": "ok",
            "ack_time": record["received_at"],
            "next_config": {
                "upload_interval": 15,  # minutes
                "sampling_rate": 5,     # seconds
            },
            "decompression_status": "success" if "fields" in payload else "no_compression_data"
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# Endpoint for clients to view uploaded inverter data
@app.route("/data", methods=["GET"])
def get_data():
    return jsonify(DATA_STORAGE)

# API endpoint to get latest device data for dynamic table
@app.route("/api/latest_data", methods=["GET"])
def get_latest_data():
    """Returns the latest device compression reports for the dynamic table"""
    if COMPRESSION_REPORTS:
        # Return the last 10 reports for the table
        latest_reports = COMPRESSION_REPORTS[-10:]
        return jsonify({
            "status": "success",
            "data": latest_reports,
            "total_reports": len(COMPRESSION_REPORTS)
        })
    else:
        return jsonify({
            "status": "no_data", 
            "data": [],
            "total_reports": 0
        })

# Endpoint to fetch compression benchmark results
@app.route("/compression_report", methods=["GET"])
def get_compression_reports():
    return jsonify(COMPRESSION_REPORTS)

# Endpoint to display compression reports in browser
@app.route("/compression_display")
def compression_display():
    # Use actual device data if available, otherwise show sample data
    if COMPRESSION_REPORTS:
        # Show the most recent compression report from a device
        display_data = COMPRESSION_REPORTS[-1]
        data_source = "Latest Device Data"
    else:
        # Sample compression report data (fallback when no device data received)
        display_data = {
            "device_id": "002",
            "timestamp": 27379,
            "fields": {
                    "AC_VOLTAGE": {
                        "method": "Delta",
                        "param_id": 0,
                        "n_samples": 1,
                        "bytes_len": 1,
                        "cpu_time_ms": 0.000338,
                        "payload": [230800],
                        "decompressed_payload": [230800],
                        "original_values": [230.8]
                    },
                    "AC_CURRENT": {
                        "method": "Delta",
                        "param_id": 1,
                        "n_samples": 1,
                        "bytes_len": 1,
                        "cpu_time_ms": 0.000160,
                        "payload": [0],
                        "decompressed_payload": [0],
                        "original_values": [0.0]
                    },
                    "AC_FREQUENCY": {
                        "method": "Delta",
                        "param_id": 2,
                        "n_samples": 1,
                        "bytes_len": 1,
                        "cpu_time_ms": 0.000128,
                        "payload": [50070],
                        "decompressed_payload": [50070],
                        "original_values": [50.07]
                    }
            }
        }
        data_source = "Sample Data (No device data received yet)"
    
    # Convert to pretty JSON for display
    json_str = json.dumps(display_data, indent=2)
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>EcoWatt Compression Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            .json-display {{ 
                background-color: #f4f4f4; 
                padding: 20px; 
                border-radius: 5px; 
                white-space: pre-wrap; 
                font-family: monospace;
                border: 1px solid #ddd;
                font-size: 14px;
            }}
            h1 {{ color: #333; }}
            .timestamp {{ color: #666; font-size: 0.9em; }}
            .data-source {{ color: #007bff; font-weight: bold; margin-bottom: 15px; }}
            .refresh-note {{ background-color: #e7f3ff; padding: 10px; border-radius: 5px; margin: 15px 0; }}
        </style>
        <script>
            // Auto-refresh every 5 seconds to show new device data
            setTimeout(function(){{ window.location.reload(); }}, 5000);
        </script>
    </head>
    <body>
        <h1>EcoWatt Cloud - Compression Report Display</h1>
        <p class="timestamp">Page generated at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
        <p class="data-source">📊 {data_source}</p>
        
        <div class="refresh-note">
            📡 This page auto-refreshes every 5 seconds to show new device data. 
            Total reports received: {len(COMPRESSION_REPORTS)}
        </div>
        
        <div class="json-display">{json_str}</div>
        <br>
        <p>
            <a href="/">← Back to Home</a> | 
            <a href="/compression_report">View Raw JSON API</a> |
            <a href="/data">View All Device Data</a>
        </p>
        
        <div style="margin-top: 30px; padding: 15px; background-color: #f8f9fa; border-radius: 5px;">
            <h3>📝 For Device Testing:</h3>
            <p>Send JSON data to: <code>POST /upload</code></p>
            <p>Example using curl:</p>
            <pre style="background-color: #e9ecef; padding: 10px; border-radius: 3px; font-size: 12px;">curl -X POST http://localhost:5000/upload \\
  -H "Content-Type: application/json" \\
  -d '{{"device_id":"002","timestamp":27379,"fields":{{"AC_VOLTAGE":{{"method":"Delta","param_id":0,"n_samples":1,"bytes_len":1,"cpu_time_ms":0.000338,"payload":[230800]}}}}}}'</pre>
        </div>
    </body>
    </html>
    """
    return html

# Endpoint for remote config updates (future milestone)
@app.route("/config", methods=["POST"])
def set_config():
    config = request.json
    # For now just echo back, in Milestone 4 you’d apply validation & persistence
    return jsonify({"status": "config_received", "applied_config": config})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
