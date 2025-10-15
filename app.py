from flask import Flask, request, jsonify
from datetime import datetime, timezone, timedelta
import os
import json
from collections import defaultdict

# Sri Lanka timezone (GMT+5:30)
SRI_LANKA_TZ = timezone(timedelta(hours=5, minutes=30))

# Delta decompression function
def delta_decode(deltas):
    if not deltas:
        return []
    decoded = [deltas[0]]
    for i in range(1, len(deltas)):
        decoded.append(decoded[-1] + deltas[i])
    return decoded

def scale_back_float(scaled_int, scale):
    return scaled_int / (10.0 ** scale)

app = Flask(__name__)

# In-memory database substitute
DATA_STORAGE = []         # Full raw records with device_data
COMPRESSION_REPORTS = []  # Processed payloads (possibly chunked)

# NEW: In-memory stores for Milestone 4 features
# Key: device_id, Value: dict of the config to be sent
PENDING_CONFIGS = defaultdict(dict)
# Key: device_id, Value: dict of the command to be sent
PENDING_COMMANDS = defaultdict(dict)
# Stores acknowledgment logs from devices
CONFIG_LOGS = []
# Stores command result logs from devices
COMMAND_LOGS = []


def _group_uploads_by_session():
    """
    Group possibly chunked uploads by (session_id, window_start_ms, window_end_ms).
    Falls back to unique keys if session metadata is missing.
    Returns a list of combined upload dicts with merged fields.
    """
    groups = {}
    order = []
    for payload in COMPRESSION_REPORTS:
        # Determine grouping key
        sid = payload.get("session_id")
        wstart = payload.get("window_start_ms")
        wend = payload.get("window_end_ms")
        if sid is not None:
            key = (sid, wstart, wend)
        else:
            # Fallback: device_id + timestamp
            key = (payload.get("device_id"), payload.get("timestamp"))

        if key not in groups:
            groups[key] = {
                "device_id": payload.get("device_id"),
                "timestamp": payload.get("timestamp"),
                "received_at": None,
                "session_id": sid,
                "window_start_ms": wstart,
                "window_end_ms": wend,
                "poll_count": payload.get("poll_count"),
                "fields": {},
            }
            order.append(key)

        # Merge fields from chunks
        fields = payload.get("fields", {})
        groups[key]["fields"].update(fields)

    return [groups[k] for k in order]


def _compute_upload_benchmark(upload):
    """
    Compute per-upload benchmark metrics:
      - compression_method (from first field if present)
      - number_of_samples (from poll_count or inferred)
      - original_payload_size_bytes (sum of decompressed ints * 4)
      - compressed_payload_size_bytes (sum of field.bytes_len)
      - compression_ratio (orig / compressed)
      - cpu_time_ms_total (sum)
      - verify_ok (all fields True or decompression present)
    """
    fields = upload.get("fields", {})
    method = None
    # Prefer device-provided totals if available (single-chunk or window totals)
    total_orig = int(upload.get("original_payload_size_bytes_total") or 0)
    total_comp = int(upload.get("compressed_payload_size_bytes_total") or 0)
    total_cpu = float(upload.get("cpu_time_ms_total") or upload.get("cpu_time_ms_total_window") or 0.0)
    all_ok = bool(upload.get("verify_ok_all") or upload.get("verify_ok_all_window") or True)
    inferred_samples = 0

    for name, f in fields.items():
        if method is None:
            method = f.get("method", "Delta")
        n = int(f.get("n_samples", 0))
        if n > inferred_samples:
            inferred_samples = n

        # If device totals are missing, compute per-field and sum
        if total_comp == 0:
            comp = int(f.get("bytes_len", 0))
            if comp <= 0:
                comp = 4 * len(f.get("payload", []))
            total_comp += comp

        if total_orig == 0:
            f_orig = int(f.get("original_bytes") or 0)
            if f_orig == 0:
                decomp = f.get("decompressed_payload")
                if decomp is None:
                    try:
                        decomp = delta_decode(f.get("payload", []))
                    except Exception:
                        decomp = []
                f_orig = 4 * len(decomp)
            total_orig += f_orig

        # CPU time accumulation if total not provided
        if upload.get("cpu_time_ms_total") is None and upload.get("cpu_time_ms_total_window") is None:
            total_cpu += float(f.get("cpu_time_ms", 0.0))

        # verify accumulation if not provided
        if upload.get("verify_ok_all") is None and upload.get("verify_ok_all_window") is None:
            vflag = f.get("verify_ok")
            if vflag is None:
                decomp = f.get("decompressed_payload")
                if decomp is None:
                    try:
                        decomp = delta_decode(f.get("payload", []))
                    except Exception:
                        decomp = []
                vflag = len(decomp) == n if n else len(decomp) > 0
            all_ok = all_ok and bool(vflag)

    poll_count = int(upload.get("poll_count") or inferred_samples)
    ratio = (float(total_orig) / float(total_comp)) if total_comp > 0 else None

    return {
        "received_at": upload.get("received_at"),
        "device_id": upload.get("device_id", "Unknown"),
        "session_id": upload.get("session_id"),
        "window_start_ms": upload.get("window_start_ms"),
        "window_end_ms": upload.get("window_end_ms"),
        "compression_method": method or "Delta",
        "number_of_samples": poll_count,
        "original_payload_size_bytes": total_orig,
        "compressed_payload_size_bytes": total_comp,
        "compression_ratio": ratio,
        "cpu_time_ms_total": total_cpu,
        "verify_ok": all_ok,
    }


@app.route("/")
def index():
    # Format configuration logs
    config_logs_html = ""
    if CONFIG_LOGS:
        config_logs_html = """
        <table>
            <thead>
                <tr>
                    <th>Device ID</th>
                    <th>Acknowledgment Data</th>
                    <th>Received At</th>
                </tr>
            </thead>
            <tbody>
        """
        for log in CONFIG_LOGS[-10:]:  # Show last 10 entries
            config_logs_html += f"""
                <tr>
                    <td class="device-id">{log.get('device_id', 'Unknown')}</td>
                    <td>{json.dumps(log.get('ack_data', {}), indent=2)}</td>
                    <td>{log.get('received_at', 'N/A')}</td>
                </tr>
            """
        config_logs_html += "</tbody></table>"
    else:
        config_logs_html = '<div class="muted">No configuration acknowledgments received yet.</div>'
    
    # Format command logs
    command_logs_html = ""
    if COMMAND_LOGS:
        command_logs_html = """
        <table>
            <thead>
                <tr>
                    <th>Device ID</th>
                    <th>Command Result</th>
                    <th>Received At</th>
                </tr>
            </thead>
            <tbody>
        """
        for log in COMMAND_LOGS[-10:]:  # Show last 10 entries
            command_logs_html += f"""
                <tr>
                    <td class="device-id">{log.get('device_id', 'Unknown')}</td>
                    <td>{json.dumps(log.get('result_data', {}), indent=2)}</td>
                    <td>{log.get('received_at', 'N/A')}</td>
                </tr>
            """
        command_logs_html += "</tbody></table>"
    else:
        command_logs_html = '<div class="muted">No command execution results received yet.</div>'

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>EcoWatt Cloud - Device Data Monitor</title>
        <style>
            :root {{ --brand:#2c3e50; --accent:#3498db; --ok:#27ae60; --panel:#ffffff; --muted:#7f8c8d; }}
            body {{ font-family: Arial, sans-serif; margin: 0; background-color: #f5f7fb; }}
            .header {{ background-color: var(--brand); color: white; padding: 24px; display:flex; align-items:center; justify-content:space-between; }}
            .header h1 {{ margin:0; font-size: 22px; }}
            .btn {{ background: var(--accent); color:#fff; padding:10px 14px; border-radius:8px; text-decoration:none; font-weight:bold; }}
            .container {{ padding: 20px; }}
            .status {{ color: var(--ok); font-weight: bold; font-size: 14px; }}
            .cards {{ display:grid; grid-template-columns: repeat(auto-fit,minmax(240px,1fr)); gap:16px; margin: 20px 0; }}
            .card {{ background:#fff; padding:16px; border-radius:12px; box-shadow:0 6px 16px rgba(0,0,0,0.06); }}
            .table-container {{ background:var(--panel); padding: 16px; border-radius: 12px; box-shadow:0 6px 16px rgba(0,0,0,0.06); }}
            table {{ width:100%; border-collapse: collapse; }}
            th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #eee; }}
            th {{ background-color: #eef6ff; color: #333; }}
            .device-id {{ font-weight: bold; color: #e74c3c; }}
            .fields-container {{ display: flex; flex-wrap: wrap; gap: 10px; }}
            .field-card {{ border: 1px solid #eee; border-radius: 8px; padding: 12px; background-color: #fafafa; }}
            .field-card h4 {{ color: var(--accent); margin: 0 0 6px 0; border-bottom: 1px solid #eee; padding-bottom: 5px; }}
            .field-details div {{ margin: 4px 0; font-size: 13px; color:#444; }}
            .payload-section {{ background-color: #f0f7fb; padding: 8px; border-radius: 5px; margin-top: 8px; border-left: 4px solid var(--accent); font-size:12px; }}
            .original-values {{ background-color: #e8f5e8; padding: 6px; border-radius: 3px; margin-top: 5px; border-left: 3px solid #28a745; font-weight: bold; font-size:12px; }}
            .muted {{ color: var(--muted); font-size:12px; }}
            /* NEW: Form styling */
            form {{ margin: 0; }}
            label {{ font-weight: bold; color: #333; margin-top: 8px; display: inline-block; }}
            input[type="text"], input[type="number"], select {{ width: 100%; padding: 8px; margin: 4px 0 8px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }}
            input[type="submit"] {{ background-color: var(--accent); color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; margin-top: 8px; }}
            input[type="submit"]:hover {{ background-color: #2980b9; }}
            /* NEW: Checkbox group styling */
            .checkbox-group {{ display: flex; flex-wrap: wrap; gap: 16px; margin: 8px 0 12px 0; }}
            .checkbox-item {{ display: flex; align-items: center; padding: 4px 8px; }}
            .checkbox-item input[type="checkbox"] {{ margin-right: 8px; width: auto; }}
            .checkbox-item label {{ margin: 0; font-weight: normal; }}
            /* NEW: Field values styling */
            .field-values {{ font-family: monospace; font-size: 12px; background-color: #f8f9fa; padding: 4px; border-radius: 3px; max-width: 150px; word-wrap: break-word; }}
            /* NEW: Popup notification styles */
            .popup-notification {{
                position: fixed;
                top: 20px;
                right: 20px;
                padding: 16px 20px;
                border-radius: 8px;
                color: white;
                font-weight: bold;
                z-index: 1000;
                max-width: 450px;
                min-width: 300px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                transform: translateX(100%);
                transition: transform 0.3s ease-in-out;
                font-size: 14px;
                line-height: 1.3;
            }}
            .popup-notification.show {{
                transform: translateX(0);
            }}
            .popup-notification.success {{
                background-color: #27ae60;
            }}
            .popup-notification.error {{
                background-color: #e74c3c;
            }}
            .popup-notification .close-btn {{
                float: right;
                margin-left: 10px;
                cursor: pointer;
                font-size: 18px;
                line-height: 1;
                opacity: 0.8;
            }}
            .popup-notification .close-btn:hover {{
                opacity: 1;
            }}
            .popup-notification ul {{
                margin: 4px 0;
                padding-left: 20px;
            }}
            .popup-notification li {{
                margin: 2px 0;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔋 EcoWatt Cloud - Device Data Monitor</h1>
            <div>
                <a class="btn" href="/benchmarks">View Benchmarks</a>
            </div>
        </div>
        <div class="container">
            <div class="cards">
                <div class="card">
                    <h3>Set Device Configuration</h3>
                    <form id="configForm" onsubmit="submitConfigForm(event)">
                        <label for="cfg_device_id">Device ID:</label><br>
                        <input type="text" id="cfg_device_id" name="device_id" value="bitbots-ecoWatt" required><br><br>
                        <label for="sampling_interval">Sampling Interval (ms):</label><br>
                        <input type="number" id="sampling_interval" name="sampling_interval" value="5000" required><br><br>
                        <label>Registers to monitor:</label><br>
                        <div class="checkbox-group">
                            <div class="checkbox-item">
                                <input type="checkbox" id="reg_ac_voltage" name="registers" value="AC_VOLTAGE" checked>
                                <label for="reg_ac_voltage">Voltage</label>
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" id="reg_ac_current" name="registers" value="AC_CURRENT" checked>
                                <label for="reg_ac_current">Current</label>
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" id="reg_ac_frequency" name="registers" value="AC_FREQUENCY" checked>
                                <label for="reg_ac_frequency">Frequency</label>
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" id="reg_pv1_voltage" name="registers" value="PV1_VOLTAGE">
                                <label for="reg_pv1_voltage">PV1 Voltage</label>
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" id="reg_pv2_voltage" name="registers" value="PV2_VOLTAGE">
                                <label for="reg_pv2_voltage">PV2 Voltage</label>
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" id="reg_pv1_current" name="registers" value="PV1_CURRENT">
                                <label for="reg_pv1_current">PV1 Current</label>
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" id="reg_pv2_current" name="registers" value="PV2_CURRENT">
                                <label for="reg_pv2_current">PV2 Current</label>
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" id="reg_temperature" name="registers" value="TEMPERATURE">
                                <label for="reg_temperature">Temperature</label>
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" id="reg_export_power" name="registers" value="EXPORT_POWER_PERCENT">
                                <label for="reg_export_power">Export Power Percent</label>
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" id="reg_output_power" name="registers" value="OUTPUT_POWER">
                                <label for="reg_output_power">Output Power</label>
                            </div>
                        </div><br>
                        <input type="submit" value="Queue Configuration">
                    </form>
                </div>
                <div class="card">
                    <h3>Queue Inverter Command</h3>
                    <form id="commandForm" onsubmit="submitCommandForm(event)">
                        <label for="cmd_device_id">Device ID:</label><br>
                        <input type="text" id="cmd_device_id" name="device_id" value="bitbots-ecoWatt" required><br><br>
                        <label for="target_register">Target Register:</label><br>
                        <select id="target_register" name="target_register">
                            <option value="export_power_percent">output_power_percentage</option>
                        </select><br><br>
                        <label for="value">Value (0-100):</label><br>
                        <input type="number" id="value" name="value" min="0" max="100" required><br><br>
                        <input type="submit" value="Queue Command">
                    </form>
                </div>
            </div>
            <div class="cards">
                <div class="card"><div class="status">Backend Running</div><div class="muted">Auto-refresh every 2s</div></div>
                <div class="card"><div><strong>Total Reports Received</strong></div><div id="totalReports">0</div></div>
                <div class="card"><div><strong>Last Update</strong></div><div id="lastUpdate">Never</div></div>
            </div>
            <div class="table-container">
                <h3>Latest Device Compression Reports</h3>
                <div id="tableContent"><div class="muted">Waiting for device data... Send JSON to POST /upload</div></div>
            </div>
            
            <!-- NEW: Configuration Logs Table -->
            <div class="table-container">
                <h3>Configuration Acknowledgment Logs</h3>
                <div id="configLogsContent">
                    {config_logs_html}
                </div>
            </div>
            
            <!-- NEW: Command Result Logs Table -->
            <div class="table-container">
                <h3>Command Execution Logs</h3>
                <div id="commandLogsContent">
                    {command_logs_html}
                </div>
            </div>
        </div>

        <script>
            function formatTimestamp(isoString) {{ 
                try {{ 
                    if (!isoString) return '—';
                    // Parse the ISO string and format for Sri Lanka timezone
                    const date = new Date(isoString);
                    return date.toLocaleString('en-US', {{
                        timeZone: 'Asia/Colombo',
                        year: 'numeric',
                        month: '2-digit',
                        day: '2-digit',
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit',
                        hour12: false
                    }});
                }} catch(e) {{ 
                    return '—'; 
                }} 
            }}
            
            function createFieldsDisplay(fields) {{
                // Create a formatted display of all fields and their values
                let html = '';
                for (const [fieldName, fieldData] of Object.entries(fields || {{}})) {{
                    if (fieldData && fieldData.original_values) {{
                        const values = fieldData.original_values.map(v => v.toFixed(3)).join(', ');
                        html += `<div class="field-row"><strong>${{fieldName}}:</strong> ${{values}}</div>`;
                    }} else {{
                        html += `<div class="field-row"><strong>${{fieldName}}:</strong> —</div>`;
                    }}
                }}
                return html;
            }}

            function showPopup(message, isSuccess = true, data = null) {{
                // Remove any existing popups
                const existingPopups = document.querySelectorAll('.popup-notification');
                existingPopups.forEach(popup => popup.remove());

                // Create new popup
                const popup = document.createElement('div');
                popup.className = `popup-notification ${{isSuccess ? 'success' : 'error'}}`;
                
                let content = `<span class="close-btn" onclick="this.parentElement.remove()">&times;</span>`;
                
                if (data && data.config) {{
                    // Format configuration data nicely
                    content += `
                        <div style="margin-bottom: 8px;"><strong>✅ Configuration Queued Successfully!</strong></div>
                        <div style="font-size: 13px; line-height: 1.4;">
                            <div><strong>Device:</strong> ${{data.config.device_id}}</div>
                            <div><strong>Sampling Interval:</strong> ${{data.config.sampling_interval}}ms</div>
                            <div><strong>Registers:</strong></div>
                            <ul style="margin: 4px 0; padding-left: 20px; font-size: 12px;">
                                ${{data.config.registers.map(reg => `<li>${{reg}}</li>`).join('')}}
                            </ul>
                        </div>
                    `;
                }} else if (data && data.command) {{
                    // Format command data nicely
                    content += `
                        <div style="margin-bottom: 8px;"><strong>✅ Command Queued Successfully!</strong></div>
                        <div style="font-size: 13px; line-height: 1.4;">
                            <div><strong>Device:</strong> ${{data.command.device_id}}</div>
                            <div><strong>Action:</strong> ${{data.command.action}}</div>
                            <div><strong>Target Register:</strong> ${{data.command.target_register}}</div>
                            <div><strong>Value:</strong> ${{data.command.value}}</div>
                        </div>
                    `;
                }} else {{
                    // Fallback to simple message
                    content += message;
                }}
                
                popup.innerHTML = content;
                
                document.body.appendChild(popup);
                
                // Show popup with animation
                setTimeout(() => popup.classList.add('show'), 100);
                
                // Auto-remove after 7 seconds (longer for detailed content)
                setTimeout(() => {{
                    if (popup.parentElement) {{
                        popup.classList.remove('show');
                        setTimeout(() => popup.remove(), 300);
                    }}
                }}, 7000);
            }}

            function submitConfigForm(event) {{
                event.preventDefault();
                
                const form = document.getElementById('configForm');
                const formData = new FormData(form);
                
                // Convert FormData to JSON
                const data = {{}};
                data.device_id = formData.get('device_id');
                data.sampling_interval = parseInt(formData.get('sampling_interval'));
                data.registers = formData.getAll('registers');
                
                fetch('/set-config', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify(data)
                }})
                .then(response => response.json())
                .then(result => {{
                    if (result.success) {{
                        // Create structured data for popup
                        const popupData = {{
                            config: {{
                                device_id: data.device_id,
                                sampling_interval: data.sampling_interval,
                                registers: data.registers.map(reg => {{
                                    // Map display names for better readability
                                    const displayMap = {{
                                        'AC_VOLTAGE': 'Voltage',
                                        'AC_CURRENT': 'Current',
                                        'AC_FREQUENCY': 'Frequency',
                                        'PV1_VOLTAGE': 'PV1 Voltage',
                                        'PV2_VOLTAGE': 'PV2 Voltage',
                                        'PV1_CURRENT': 'PV1 Current',
                                        'PV2_CURRENT': 'PV2 Current',
                                        'TEMPERATURE': 'Temperature',
                                        'EXPORT_POWER_PERCENT': 'Output Power Percentage',
                                        'OUTPUT_POWER': 'Power'
                                    }};
                                    return displayMap[reg] || reg;
                                }})
                            }}
                        }};
                        showPopup('', true, popupData);
                    }} else {{
                        showPopup(result.message, false);
                    }}
                }})
                .catch(error => {{
                    showPopup('Error submitting configuration: ' + error.message, false);
                }});
            }}

            function submitCommandForm(event) {{
                event.preventDefault();
                
                const form = document.getElementById('commandForm');
                const formData = new FormData(form);
                
                // Convert FormData to JSON
                const data = {{}};
                data.device_id = formData.get('device_id');
                data.target_register = formData.get('target_register');
                data.value = parseInt(formData.get('value'));
                
                fetch('/queue-command', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify(data)
                }})
                .then(response => response.json())
                .then(result => {{
                    if (result.success) {{
                        // Create structured data for popup
                        const popupData = {{
                            command: {{
                                device_id: data.device_id,
                                action: 'Write Register',
                                target_register: 'Output Power Percentage',
                                value: data.value + '%'
                            }}
                        }};
                        showPopup('', true, popupData);
                    }} else {{
                        showPopup(result.message, false);
                    }}
                }})
                .catch(error => {{
                    showPopup('Error submitting command: ' + error.message, false);
                }});
            }}

            function updateTable(data) {{
                const tableContent = document.getElementById('tableContent');
                const totalReports = document.getElementById('totalReports');
                const lastUpdate = document.getElementById('lastUpdate');
                if (data.data && data.data.length > 0) {{
                    let tableHTML = `
                        <table>
                            <thead>
                                <tr>
                                    <th>Device ID</th>
                                    <th>Timestamp</th>
                                    <th>Number of Fields</th>
                                    <th>Number of Samples</th>
                                    <th>Field Values</th>
                                    <th>Server Received At</th>
                                </tr>
                            </thead>
                            <tbody>
                    `;
                    
                    data.data.slice().reverse().forEach(report => {{
                        const fieldsCount = Object.keys(report.fields || {{}}).length;
                        // Calculate total number of samples (use the max from all fields)
                        let totalSamples = 0;
                        if (report.fields) {{
                            Object.values(report.fields).forEach(fieldData => {{
                                const samples = fieldData.n_samples || 0;
                                if (samples > totalSamples) totalSamples = samples;
                            }});
                        }}
                        
                        tableHTML += `
                            <tr>
                                <td class="device-id">${{report.device_id || 'Unknown'}}</td>
                                <td class="timestamp">${{report.timestamp || 'N/A'}}</td>
                                <td>${{fieldsCount}}</td>
                                <td>${{totalSamples}}</td>
                                <td class="field-values-column">${{createFieldsDisplay(report.fields || {{}})}}</td>
                                <td class="timestamp">${{formatTimestamp(report.received_at)}}</td>
                            </tr>
                        `;
                    }});
                    tableHTML += '</tbody></table>';
                    tableContent.innerHTML = tableHTML;
                }} else {{
                    tableContent.innerHTML = '<div class="muted">No device data received yet. Waiting for JSON data...</div>';
                }}
                totalReports.textContent = data.total_reports || 0;
                const latestTime = data.data && data.data.length > 0 ? data.data[data.data.length - 1].received_at : null;
                lastUpdate.textContent = formatTimestamp(latestTime);
            }}

            function fetchLatestData() {{
                fetch('/api/latest_data')
                    .then(r => r.json()).then(updateTable).catch(console.error);
            }}
            fetchLatestData();
            setInterval(fetchLatestData, 2000);
        </script>
    </body>
    </html>
    """
    return html


@app.route("/set-config", methods=["POST"])
def set_config_from_form():
    try:
        # Handle both form data and JSON data
        if request.content_type == 'application/json':
            data = request.json
            device_id = data.get("device_id")
            sampling_interval = data.get("sampling_interval")
            selected_registers = data.get("registers", [])
        else:
            form_data = request.form
            device_id = form_data.get("device_id")
            sampling_interval = form_data.get("sampling_interval", type=int)
            selected_registers = form_data.getlist("registers")
        
        # Get selected registers from checkboxes and map to spec format
        register_mapping = {
            "AC_VOLTAGE": "voltage",
            "AC_CURRENT": "current", 
            "AC_FREQUENCY": "frequency",
            "PV1_VOLTAGE": "pv1_voltage",
            "PV2_VOLTAGE": "pv2_voltage",
            "PV1_CURRENT": "pv1_current",
            "PV2_CURRENT": "pv2_current",
            "TEMPERATURE": "temperature",
            "EXPORT_POWER_PERCENT": "output_power_percentage",
            "OUTPUT_POWER": "power"
        }
        
        # Map to specification format
        spec_registers = [register_mapping.get(reg, reg.lower()) for reg in selected_registers]

        if not device_id or not sampling_interval:
            if request.content_type == 'application/json':
                return jsonify({"success": False, "message": "Missing device_id or sampling_interval"}), 400
            return "Error: Missing device_id or sampling_interval", 400
        
        if not spec_registers:
            if request.content_type == 'application/json':
                return jsonify({"success": False, "message": "At least one register must be selected"}), 400
            return "Error: At least one register must be selected", 400

        # Store configuration in exact specification format
        config = {
            "sampling_interval": sampling_interval,
            "registers": spec_registers
        }
        PENDING_CONFIGS[device_id] = config

        message = f"Configuration for {device_id} has been queued. Registers: {', '.join(spec_registers)}. It will be sent on the device's next check-in."
        
        if request.content_type == 'application/json':
            return jsonify({"success": True, "message": message})
        return message
        
    except Exception as e:
        if request.content_type == 'application/json':
            return jsonify({"success": False, "message": str(e)}), 500
        return f"Error: {str(e)}", 500


@app.route("/queue-command", methods=["POST"])
def queue_command_from_form():
    try:
        # Handle both form data and JSON data
        if request.content_type == 'application/json':
            data = request.json
            device_id = data.get("device_id")
            target_register = data.get("target_register")
            value = data.get("value")
        else:
            form_data = request.form
            device_id = form_data.get("device_id")
            target_register = form_data.get("target_register")
            value = form_data.get("value", type=int)

        if not device_id or not target_register or value is None:
            if request.content_type == 'application/json':
                return jsonify({"success": False, "message": "Missing device_id, target_register, or value"}), 400
            return "Error: Missing device_id, target_register, or value", 400

        # Map form values to specification format
        register_mapping = {
            "export_power_percent": "output_power_percentage"
        }
        spec_target_register = register_mapping.get(target_register, target_register)

        # Store command in exact specification format
        command = {
            "action": "write_register",
            "target_register": spec_target_register,
            "value": value
        }
        PENDING_COMMANDS[device_id] = command

        message = f"Command for {device_id} has been queued (target: {spec_target_register}, value: {value}). It will be sent on the device's next check-in."
        
        if request.content_type == 'application/json':
            return jsonify({"success": True, "message": message})
        return message
        
    except Exception as e:
        if request.content_type == 'application/json':
            return jsonify({"success": False, "message": str(e)}), 500
        return f"Error: {str(e)}", 500


@app.route("/upload", methods=["POST"])
def upload_data():
    try:
        payload = request.json
        if not payload:
            return jsonify({"status": "error", "message": "Invalid JSON"}), 400

        processed_payload = dict(payload)
        
        # NEW: Check for and log command execution results
        if "command_result" in payload:
            command_log_entry = {
                "device_id": payload.get("device_id"),
                "result_data": payload["command_result"],
                "received_at": datetime.now(SRI_LANKA_TZ).isoformat()
            }
            COMMAND_LOGS.append(command_log_entry)
        
        # Decompress each field into decompressed_payload and original_values
        if "fields" in payload:
            for field_name, field_data in payload["fields"].items():
                if "payload" in field_data and field_data["payload"]:
                    compressed_payload = field_data["payload"]
                    decompressed_values = delta_decode(compressed_payload)
                    scale = 3 if field_name in ["AC_VOLTAGE", "AC_CURRENT", "AC_FREQUENCY"] else 0
                    original_values = [scale_back_float(val, scale) for val in decompressed_values]
                    processed_payload.setdefault("fields", {}).setdefault(field_name, {})
                    processed_payload["fields"][field_name]["decompressed_payload"] = decompressed_values
                    processed_payload["fields"][field_name]["original_values"] = original_values

        # Get current time in Sri Lanka timezone
        sri_lanka_time = datetime.now(SRI_LANKA_TZ)
        record = {
            "received_at": sri_lanka_time.isoformat(),
            "device_data": processed_payload
        }
        DATA_STORAGE.append(record)

        if "fields" in processed_payload:
            # Save a flattened copy (without wrapping) for easy grouping
            flat = dict(processed_payload)
            # keep received time for grouping output if desired
            flat["received_at"] = record["received_at"]
            COMPRESSION_REPORTS.append(flat)

        return jsonify({
            "status": "ok",
            "ack_time": record["received_at"],
            "server_time_zone": "Asia/Colombo (GMT+5:30)",
            "next_config": {
                "upload_interval": 15,  # minutes (advisory for demo)
                "sampling_rate": 5,     # seconds
            },
            "decompression_status": "success" if "fields" in payload else "no_compression_data"
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/data", methods=["GET"])
def get_data():
    return jsonify(DATA_STORAGE)


@app.route("/api/latest_data", methods=["GET"])
def get_latest_data():
    if COMPRESSION_REPORTS:
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


@app.route("/compression_report", methods=["GET"])
def get_compression_reports():
    return jsonify(COMPRESSION_REPORTS)


@app.route("/compression_display")
def compression_display():
    # Fallback to sample if no data
    if COMPRESSION_REPORTS:
        display_data = COMPRESSION_REPORTS[-1]
        data_source = "Latest Device Data"
    else:
        display_data = {
            "device_id": "002",
            "timestamp": 27379,
            "fields": {
                "AC_VOLTAGE": {"method": "Delta", "param_id": 0, "n_samples": 1, "bytes_len": 1, "cpu_time_ms": 0.000338, "payload": [230800], "decompressed_payload": [230800], "original_values": [230.8]},
                "AC_CURRENT": {"method": "Delta", "param_id": 1, "n_samples": 1, "bytes_len": 1, "cpu_time_ms": 0.000160, "payload": [0], "decompressed_payload": [0], "original_values": [0.0]},
                "AC_FREQUENCY": {"method": "Delta", "param_id": 2, "n_samples": 1, "bytes_len": 1, "cpu_time_ms": 0.000128, "payload": [50070], "decompressed_payload": [50070], "original_values": [50.07]}
            }
        }
        data_source = "Sample Data (No device data received yet)"
    json_str = json.dumps(display_data, indent=2)
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>EcoWatt Compression Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            .json-display {{ background-color: #f4f4f4; padding: 20px; border-radius: 5px; white-space: pre-wrap; font-family: monospace; border: 1px solid #ddd; font-size: 14px; }}
            h1 {{ color: #333; }} .timestamp {{ color: #666; font-size: 0.9em; }} .data-source {{ color: #007bff; font-weight: bold; margin-bottom: 15px; }}
            .refresh-note {{ background-color: #e7f3ff; padding: 10px; border-radius: 5px; margin: 15px 0; }}
        </style>
        <script> setTimeout(function(){{ window.location.reload(); }}, 5000); </script>
    </head>
    <body>
        <h1>EcoWatt Cloud - Compression Report Display</h1>
        <p class="timestamp">Page generated at: {datetime.now(SRI_LANKA_TZ).strftime('%Y-%m-%d %H:%M:%S')} (Sri Lanka Time, GMT+5:30)</p>
        <p class="data-source">{data_source}</p>
        <div class="refresh-note">This page auto-refreshes every 5 seconds to show new device data. Total reports received: {len(COMPRESSION_REPORTS)}</div>
        <div class="json-display">{json_str}</div>
        <br>
        <p><a href="/">← Back to Home</a></p>
    </body>
    </html>
    """
    return html


@app.route("/benchmarks")
def benchmarks_page():
    # Build combined uploads and compute metrics
    combined = _group_uploads_by_session()
    # inject received_at by matching in DATA_STORAGE (best-effort)
    ra_by_signature = {}
    for rec in DATA_STORAGE:
        dd = rec.get("device_data", {})
        key = (dd.get("session_id"), dd.get("window_start_ms"), dd.get("window_end_ms"))
        ra_by_signature[key] = rec.get("received_at")
    rows = []
    for u in combined:
        sig = (u.get("session_id"), u.get("window_start_ms"), u.get("window_end_ms"))
        u["received_at"] = ra_by_signature.get(sig)
        rows.append(_compute_upload_benchmark(u))

    # Compute overall stats
    total_uploads = len(rows)
    avg_ratio = (sum([r["compression_ratio"] for r in rows if r["compression_ratio"]]) / max(1, len([r for r in rows if r["compression_ratio"]]))) if rows else 0
    avg_orig = (sum([r["original_payload_size_bytes"] for r in rows]) / total_uploads) if total_uploads else 0
    avg_comp = (sum([r["compressed_payload_size_bytes"] for r in rows]) / total_uploads) if total_uploads else 0
    avg_cpu = (sum([r["cpu_time_ms_total"] for r in rows]) / total_uploads) if total_uploads else 0

    # Helper function for formatting timestamps in benchmarks
    def formatTimestamp(iso_string):
        if not iso_string:
            return '—'
        try:
            # Parse the ISO string and convert to Sri Lanka time if needed
            dt = datetime.fromisoformat(iso_string.replace('Z', '+00:00'))
            # If it's already in Sri Lanka timezone, use as is, otherwise convert
            if dt.tzinfo is None:
                # Assume it's already Sri Lanka time if no timezone info
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            elif dt.tzinfo.utcoffset(dt) == timedelta(hours=5, minutes=30):
                # Already in Sri Lanka time
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            else:
                # Convert to Sri Lanka time
                sri_lanka_time = dt.astimezone(SRI_LANKA_TZ)
                return sri_lanka_time.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return iso_string

    # Build HTML
    html_rows = "".join([
        f"""
        <tr>
            <td>{formatTimestamp(r.get('received_at'))}</td>
            <td>{r['device_id']}</td>
            <td>{r.get('session_id') or '—'}</td>
            <td>{r['number_of_samples']}</td>
            <td>{r['original_payload_size_bytes']}</td>
            <td>{r['compressed_payload_size_bytes']}</td>
            <td>{f"{r['compression_ratio']:.2f}" if r['compression_ratio'] else '—'}</td>
            <td>{f"{r['cpu_time_ms_total']:.3f}"}</td>
            <td>{'✅' if r['verify_ok'] else '❌'}</td>
            <td>{r['compression_method']}</td>
        </tr>
        """ for r in rows
    ])

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>EcoWatt Benchmarks</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; background-color: #f5f7fb; }}
            .header {{ background:#2c3e50; color:#fff; padding:20px; display:flex; justify-content:space-between; align-items:center; }}
            .btn {{ background:#3498db; color:#fff; padding:10px 14px; border-radius:8px; text-decoration:none; font-weight:bold; }}
            .container {{ padding:20px; }}
            .cards {{ display:grid; grid-template-columns: repeat(auto-fit,minmax(220px,1fr)); gap:16px; margin-bottom:20px; }}
            .card {{ background:#fff; padding:16px; border-radius:12px; box-shadow:0 6px 16px rgba(0,0,0,0.06); }}
            table {{ width:100%; border-collapse: collapse; background:#fff; box-shadow:0 6px 16px rgba(0,0,0,0.06); border-radius:12px; overflow:hidden; }}
            th, td {{ padding: 10px 12px; border-bottom: 1px solid #eee; text-align:left; }}
            th {{ background:#eef6ff; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h2>EcoWatt Compression Benchmarks</h2>
            <a class="btn" href="/">← Back to Home</a>
        </div>
        <div class="container">
            <div class="cards">
                <div class="card"><div><strong>Total Uploads</strong></div><div>{total_uploads}</div></div>
                <div class="card"><div><strong>Avg Compression Ratio</strong></div><div>{(f"{avg_ratio:.2f}" if avg_ratio else '—')}</div></div>
                <div class="card"><div><strong>Avg Original Size (B)</strong></div><div>{int(avg_orig)}</div></div>
                <div class="card"><div><strong>Avg Compressed Size (B)</strong></div><div>{int(avg_comp)}</div></div>
                <div class="card"><div><strong>Avg CPU Time (ms)</strong></div><div>{avg_cpu:.3f}</div></div>
            </div>

            <table>
                <thead>
                    <tr>
                        <th>Server Received At</th>
                        <th>Device</th>
                        <th>Session</th>
                        <th>Samples</th>
                        <th>Original Bytes</th>
                        <th>Compressed Bytes</th>
                        <th>Ratio</th>
                        <th>CPU ms (Total)</th>
                        <th>Lossless</th>
                        <th>Method</th>
                    </tr>
                </thead>
                <tbody>
                    {html_rows if html_rows else '<tr><td colspan="10">No uploads yet</td></tr>'}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """
    return html


@app.route("/config", methods=["POST"])
def handle_config():
    """
    Configuration endpoint for device configuration updates and command delivery.
    
    Device sends status updates and receives configuration updates or commands in response.
    Device can also send acknowledgments and command results.
    """
    try:
        data = request.json
        if not data:
            return jsonify({"status": "error", "message": "Invalid JSON"}), 400
        
        device_id = data.get("device_id")
        if not device_id:
            return jsonify({"status": "error", "message": "device_id is required"}), 400

        # Handle configuration acknowledgment from device
        if "config_ack" in data:
            ack_log_entry = {
                "device_id": device_id,
                "ack_data": data["config_ack"],
                "received_at": datetime.now(SRI_LANKA_TZ).isoformat()
            }
            CONFIG_LOGS.append(ack_log_entry)
            print(f"[CONFIG ACK] Device {device_id}: {data['config_ack']}")

        # Handle command execution result from device
        if "command_result" in data:
            result_log_entry = {
                "device_id": device_id,
                "result_data": data["command_result"],
                "received_at": datetime.now(SRI_LANKA_TZ).isoformat()
            }
            COMMAND_LOGS.append(result_log_entry)
            print(f"[COMMAND RESULT] Device {device_id}: {data['command_result']}")

        # Prepare response with any pending configuration or commands
        response = {}
        
        # Check for pending configuration update
        if device_id in PENDING_CONFIGS:
            config = PENDING_CONFIGS.pop(device_id)  # Send only once
            response["config_update"] = config
            print(f"[CONFIG SENT] To device {device_id}: {config}")

        # Check for pending command
        if device_id in PENDING_COMMANDS:
            command = PENDING_COMMANDS.pop(device_id)  # Send only once
            response["command"] = command
            print(f"[COMMAND SENT] To device {device_id}: {command}")

        return jsonify(response)

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port, debug=True)
