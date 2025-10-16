from flask import Flask, request, jsonify
from datetime import datetime, timezone, timedelta
import os
import json
from collections import defaultdict
import hmac
import hashlib
import base64
import json
from werkzeug.utils import secure_filename

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

def load_existing_firmware():
    """Load existing firmware files from firmware_files directory on startup"""
    global UPLOADED_FIRMWARE
    firmware_dir = os.path.join(os.getcwd(), 'firmware_files')
    
    if not os.path.exists(firmware_dir):
        return
    
    try:
        for filename in os.listdir(firmware_dir):
            if filename.endswith('.bin'):
                filepath = os.path.join(firmware_dir, filename)
                # Extract version from filename format: version_originalname.bin
                if '_' in filename:
                    version = filename.split('_', 1)[0]
                    original_filename = filename.split('_', 1)[1]
                else:
                    # Fallback for files without version prefix
                    version = "unknown"
                    original_filename = filename
                
                # Get file modification time as upload time
                file_stat = os.stat(filepath)
                uploaded_at = datetime.fromtimestamp(file_stat.st_mtime, SRI_LANKA_TZ).isoformat()
                
                firmware_info = {
                    "version": version,
                    "filename": filename,
                    "original_filename": original_filename,
                    "filepath": filepath,
                    "uploaded_at": uploaded_at
                }
                
                # Check if this firmware is already in the list (avoid duplicates)
                if not any(fw['filepath'] == filepath for fw in UPLOADED_FIRMWARE):
                    UPLOADED_FIRMWARE.append(firmware_info)
                    
        print(f"[FIRMWARE] Loaded {len(UPLOADED_FIRMWARE)} existing firmware files from {firmware_dir}")
        
    except Exception as e:
        print(f"[FIRMWARE] Error loading existing firmware files: {str(e)}")

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

# NEW: Store uploaded firmware information
UPLOADED_FIRMWARE = []  # List of {version, filename, filepath, uploaded_at}

# NEW: Store firmware update logs from devices
FIRMWARE_DOWNLOAD_LOGS = []  # Device download verification logs
FIRMWARE_BOOT_LOGS = []      # Device boot confirmation logs

# Stores the PSK for each known device.
DEVICE_PSKS = {
    "bitbots-ecoWatt": "E5A3C8B2F0D9E8A1C5B3A2D8F0E9C4B2A1D8E5C3B0A9F8E2D1C0B7A6F5E4D3C2"
}

# Stores the last successfully validated nonce for each device to prevent replay attacks.
DEVICE_NONCES = defaultdict(int) # Defaults new devices to a nonce of 0

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

def validate_secure_payload(data):
    """
    Validates an incoming secure payload. Checks the nonce and HMAC signature.
    Returns the decoded JSON payload on success, or None on failure.
    NEW FORMAT: device_id is now inside the encrypted payload, not outside.
    """
    try:
        # Extract required fields from the new secure format
        nonce = int(data['nonce'])
        encoded_payload = data['payload']
        received_mac_hex = data['mac']

        # First, decode the Base64 payload to get the original JSON and extract device_id
        decoded_payload_bytes = base64.b64decode(encoded_payload)
        decoded_payload = json.loads(decoded_payload_bytes.decode('utf-8'))
        
        # Extract device_id from the decoded payload
        device_id = decoded_payload.get('device_id')
        if not device_id:
            print(f"[SECURITY] REJECT: No device_id found in decoded payload")
            return None

        # Check if the device and its key are known
        if device_id not in DEVICE_PSKS:
            print(f"[SECURITY] REJECT: Unknown device_id '{device_id}'")
            return None
        
        psk = DEVICE_PSKS[device_id]
        last_nonce = DEVICE_NONCES[device_id]

        # Check the Nonce to prevent replay attacks
        if nonce <= last_nonce:
            print(f"[SECURITY] REJECT: Replay attack detected for {device_id}. Received nonce: {nonce}, last valid nonce: {last_nonce}")
            return None

        # Verify the HMAC signature to ensure authenticity and integrity
        # Reconstruct the exact "canonical message" that was signed on the ESP8266.
        message_to_sign = f"{nonce}.{encoded_payload}".encode('utf-8')
        
        print(f"[DEBUG] Message to sign length: {len(message_to_sign)} bytes")
        print(f"[DEBUG] PSK for device: {psk[:16]}...{psk[-16:]}")

        # Calculate our own version of the HMAC signature
        key_bytes = psk.encode('utf-8')
        h = hmac.new(key_bytes, message_to_sign, hashlib.sha256)
        calculated_mac_hex = h.hexdigest()
        
        print(f"[DEBUG] Calculated MAC: {calculated_mac_hex[:16]}...{calculated_mac_hex[-16:]}")
        print(f"[DEBUG] Received   MAC: {received_mac_hex[:16]}...{received_mac_hex[-16:]}")

        # Compare the received MAC with our calculated one. Use hmac.compare_digest for security.
        if not hmac.compare_digest(calculated_mac_hex, received_mac_hex):
            print(f"[SECURITY] REJECT: Invalid HMAC signature for {device_id}.")
            return None

        # Success! Update the nonce for this device to prevent reuse of the current one.
        DEVICE_NONCES[device_id] = nonce
        
        print(f"[SECURITY] ACCEPT: Successfully validated payload from {device_id} with nonce {nonce}.")
        
        # Return the trusted, decoded data
        return decoded_payload

    except (KeyError, ValueError, Exception) as e:
        print(f"[SECURITY] REJECT: Error during validation: {str(e)}")
        return None

@app.route("/")
def index():
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
            /* Tab Navigation Styles */
            .tab-navigation {{
                background-color: #f8f9fa;
                border-bottom: 2px solid #e9ecef;
                padding: 0;
                margin: 0;
                display: flex;
            }}
            .tab-button {{
                background-color: transparent;
                border: none;
                padding: 16px 24px;
                cursor: pointer;
                font-size: 16px;
                font-weight: 500;
                color: #495057;
                border-bottom: 3px solid transparent;
                transition: all 0.3s ease;
            }}
            .tab-button:hover {{
                background-color: #e9ecef;
                color: var(--accent);
            }}
            .tab-button.active {{
                color: var(--accent);
                border-bottom-color: var(--accent);
                background-color: #ffffff;
            }}
            /* Tab Content Styles */
            .tab-content {{
                display: none;
            }}
            .tab-content.active {{
                display: block;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔋 EcoWatt Cloud - Device Data Monitor</h1>
        </div>
        
        <!-- Tab Navigation -->
        <div class="tab-navigation">
            <button class="tab-button active" onclick="openTab(event, 'device-config-tab')">Device Configurations</button>
            <button class="tab-button" onclick="openTab(event, 'firmware-update-tab')">Firmware Update</button>
        </div>
        
        <div class="container">
            <!-- Device Configurations Tab Content -->
            <div id="device-config-tab" class="tab-content active">
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
                                <input type="checkbox" id="reg_temperature" name="registers" value="TEMPERATURE" checked>
                                <label for="reg_temperature">Temperature</label>
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" id="reg_output_power" name="registers" value="OUTPUT_POWER" checked>
                                <label for="reg_output_power">Power</label>
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
                                <input type="checkbox" id="reg_export_power" name="registers" value="EXPORT_POWER_PERCENT">
                                <label for="reg_export_power">Export Power Percent</label>
                            </div>
                        </div><br>
                        <input type="submit" value="Queue Configuration">
                    </form>
                </div>
                <div class="card">
                    <h3>Give Inverter Command</h3>
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
                <h3>Inverter Status Reports</h3>
                <div id="tableContent"><div class="muted">Waiting for device data... Send JSON to POST /upload</div></div>
            </div>
            
            <!-- NEW: Configuration Logs Table -->
            <div class="table-container">
                <h3>Configuration Acknowledgment Logs</h3>
                <div id="configLogsContent">
                    <div class="muted">No configuration acknowledgments received yet.</div>
                </div>
            </div>
            
            <!-- NEW: Command Result Logs Table -->
            <div class="table-container">
                <h3>Command Execution Logs</h3>
                <div id="commandLogsContent">
                    <div class="muted">No command execution results received yet.</div>
                </div>
            </div>
            </div>
            
            <!-- Firmware Update Tab Content -->
            <div id="firmware-update-tab" class="tab-content">
                <div class="cards">
                    <div class="card">
                        <h3>Upload Firmware</h3>
                        <form id="firmwareUploadForm" onsubmit="submitFirmwareForm(event)" enctype="multipart/form-data">
                            <label for="firmware_version">Firmware Version:</label><br>
                            <input type="text" id="firmware_version" name="firmware_version" placeholder="e.g., 1.2.3" required><br><br>
                            
                            <label for="firmware_file">Select .bin File:</label><br>
                            <input type="file" id="firmware_file" name="firmware_file" accept=".bin" required><br><br>
                            
                            <input type="submit" value="Upload Firmware">
                        </form>
                    </div>
                    <div class="card">
                        <h3>Deploy Firmware Update</h3>
                        <form id="firmwareDeployForm" onsubmit="submitFirmwareDeployForm(event)">
                            <label for="deploy_device_id">Device Name:</label><br>
                            <input type="text" id="deploy_device_id" name="device_id" value="bitbots-ecoWatt" required><br><br>
                            
                            <label for="firmware_version_select">Select Update Version:</label><br>
                            <select id="firmware_version_select" name="firmware_version" required>
                                <option value="">-- Select Version --</option>
                                <!-- Options will be populated dynamically -->
                            </select><br><br>
                            
                            <input type="submit" value="Queue Firmware Update">
                        </form>
                        
                        <div id="firmwareProgress" style="margin-top: 20px;">
                            <h4>Firmware Download Progress</h4>
                            <div id="progressContainer" style="background-color: #f0f0f0; border-radius: 8px; padding: 16px; margin: 8px 0;">
                                <div id="progressStatus" style="color: #7f8c8d; font-style: italic;">No firmware download in progress</div>
                                <div id="progressBar" style="width: 100%; background-color: #e0e0e0; border-radius: 4px; margin: 8px 0; display: none;">
                                    <div id="progressBarFill" style="width: 0%; height: 20px; background-color: var(--accent); border-radius: 4px; transition: width 0.3s ease;"></div>
                                </div>
                                <div id="progressText" style="font-size: 12px; color: #666; display: none;">0% (0 / 0 bytes)</div>
                            </div>
                        </div>
                        
                        <div id="rebootSection" style="margin-top: 16px;">
                            <button id="rebootDeviceBtn" onclick="rebootDevice()" style="background-color: #e74c3c; color: white; padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; font-weight: bold; opacity: 0.5;" disabled>
                                Reboot Device
                            </button>
                            <div style="font-size: 12px; color: #7f8c8d; margin-top: 4px;">Apply firmware update after download completion</div>
                        </div>
                        
                        <div id="rebootProgress" style="margin-top: 20px;">
                            <h4>Reboot Progress</h4>
                            <div id="rebootProgressContainer" style="background-color: #f0f0f0; border-radius: 8px; padding: 16px; margin: 8px 0;">
                                <div id="rebootProgressStatus" style="color: #7f8c8d; font-style: italic;">No reboot in progress</div>
                                <div id="rebootProgressBar" style="width: 100%; background-color: #e0e0e0; border-radius: 4px; margin: 8px 0; display: none;">
                                    <div id="rebootProgressBarFill" style="width: 0%; height: 20px; background-color: #e74c3c; border-radius: 4px; transition: width 0.3s ease;"></div>
                                </div>
                                <div id="rebootProgressText" style="font-size: 12px; color: #666; display: none;">Rebooting device...</div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Firmware Download Verification Logs -->
                <div class="table-container">
                    <h3>Firmware Download Verification Logs</h3>
                    <div id="firmwareDownloadLogsContent">
                        <div class="muted">No firmware download verifications received yet.</div>
                    </div>
                </div>
                
                <!-- Firmware Boot Confirmation Logs -->
                <div class="table-container">
                    <h3>Firmware Boot Confirmation Logs</h3>
                    <div id="firmwareBootLogsContent">
                        <div class="muted">No firmware boot confirmations received yet.</div>
                    </div>
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
                }} else if (data && data.firmware) {{
                    // Format firmware upload data nicely
                    content += `
                        <div style="margin-bottom: 8px;"><strong>✅ Firmware Uploaded Successfully!</strong></div>
                        <div style="font-size: 13px; line-height: 1.4;">
                            <div><strong>Version:</strong> ${{data.firmware.version}}</div>
                            <div><strong>Filename:</strong> ${{data.firmware.filename}}</div>
                            <div><strong>Location:</strong> firmware_files/ folder</div>
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

            function submitFirmwareForm(event) {{
                event.preventDefault();
                
                const form = document.getElementById('firmwareUploadForm');
                const formData = new FormData(form);
                
                // Show loading message
                showPopup('Uploading firmware...', true);
                
                fetch('/upload-firmware', {{
                    method: 'POST',
                    body: formData
                }})
                .then(response => response.json())
                .then(result => {{
                    if (result.success) {{
                        // Create structured data for popup
                        const popupData = {{
                            firmware: {{
                                version: result.version,
                                filename: result.filename,
                                message: result.message
                            }}
                        }};
                        showPopup('', true, popupData);
                        // Reset the form
                        form.reset();
                        // Refresh the firmware versions dropdown
                        loadAvailableFirmwareVersions();
                    }} else {{
                        showPopup(result.message, false);
                    }}
                }})
                .catch(error => {{
                    showPopup('Error uploading firmware: ' + error.message, false);
                }});
            }}

            function submitFirmwareDeployForm(event) {{
                event.preventDefault();
                
                const form = document.getElementById('firmwareDeployForm');
                const formData = new FormData(form);
                
                const deviceId = formData.get('device_id');
                const firmwareVersion = formData.get('firmware_version');
                
                // Show placeholder message for now
                showPopup(`Firmware update queued for device "${{deviceId}}" with version "${{firmwareVersion}}". Implementation coming soon.`, true);
                
                // TODO: Implement actual firmware deployment queueing
                // fetch('/queue-firmware-update', {{
                //     method: 'POST',
                //     headers: {{
                //         'Content-Type': 'application/json',
                //     }},
                //     body: JSON.stringify({{
                //         device_id: deviceId,
                //         firmware_version: firmwareVersion
                //     }})
                // }})
                // .then(response => response.json())
                // .then(result => {{
                //     if (result.success) {{
                //         showPopup('Firmware update queued successfully!', true);
                //         // Start monitoring progress
                //         startProgressMonitoring(deviceId);
                //     }} else {{
                //         showPopup(result.message, false);
                //     }}
                // }})
                // .catch(error => {{
                //     showPopup('Error queueing firmware update: ' + error.message, false);
                // }});
            }}

            function updateProgressDisplay(progress) {{
                const progressStatus = document.getElementById('progressStatus');
                const progressBar = document.getElementById('progressBar');
                const progressBarFill = document.getElementById('progressBarFill');
                const progressText = document.getElementById('progressText');
                const rebootBtn = document.getElementById('rebootDeviceBtn');

                if (progress && progress.status) {{
                    progressStatus.textContent = progress.status;
                    progressStatus.style.color = '#2c3e50';
                    progressStatus.style.fontStyle = 'normal';

                    if (progress.percentage !== undefined) {{
                        progressBar.style.display = 'block';
                        progressText.style.display = 'block';
                        progressBarFill.style.width = progress.percentage + '%';
                        progressText.textContent = `${{progress.percentage}}% (${{progress.downloaded || 0}} / ${{progress.total || 0}} bytes)`;
                    }}

                    if (progress.completed) {{
                        progressStatus.textContent = '✅ Download completed successfully';
                        progressStatus.style.color = '#27ae60';
                        rebootBtn.style.opacity = '1';
                        rebootBtn.disabled = false;
                        rebootBtn.style.backgroundColor = '#e74c3c';
                    }}
                }} else {{
                    progressStatus.textContent = 'No firmware download in progress';
                    progressStatus.style.color = '#7f8c8d';
                    progressStatus.style.fontStyle = 'italic';
                    progressBar.style.display = 'none';
                    progressText.style.display = 'none';
                    rebootBtn.style.opacity = '0.5';
                    rebootBtn.disabled = true;
                }}
            }}

            function updateRebootProgressDisplay(progress) {{
                const rebootProgressStatus = document.getElementById('rebootProgressStatus');
                const rebootProgressBar = document.getElementById('rebootProgressBar');
                const rebootProgressBarFill = document.getElementById('rebootProgressBarFill');
                const rebootProgressText = document.getElementById('rebootProgressText');

                if (progress && progress.status) {{
                    rebootProgressStatus.textContent = progress.status;
                    rebootProgressStatus.style.color = '#2c3e50';
                    rebootProgressStatus.style.fontStyle = 'normal';

                    if (progress.percentage !== undefined) {{
                        rebootProgressBar.style.display = 'block';
                        rebootProgressText.style.display = 'block';
                        rebootProgressBarFill.style.width = progress.percentage + '%';
                        rebootProgressText.textContent = progress.message || 'Rebooting device...';
                    }}

                    if (progress.completed) {{
                        rebootProgressStatus.textContent = '✅ Device rebooted successfully';
                        rebootProgressStatus.style.color = '#27ae60';
                        // Reset after successful reboot
                        setTimeout(() => {{
                            updateRebootProgressDisplay(null);
                        }}, 3000);
                    }} else if (progress.failed) {{
                        rebootProgressStatus.textContent = '❌ Reboot failed';
                        rebootProgressStatus.style.color = '#e74c3c';
                    }}
                }} else {{
                    rebootProgressStatus.textContent = 'No reboot in progress';
                    rebootProgressStatus.style.color = '#7f8c8d';
                    rebootProgressStatus.style.fontStyle = 'italic';
                    rebootProgressBar.style.display = 'none';
                    rebootProgressText.style.display = 'none';
                }}
            }}

            function rebootDevice() {{
                const deviceId = document.getElementById('deploy_device_id').value;
                
                if (confirm(`Are you sure you want to reboot device "${{deviceId}}" to apply the firmware update?`)) {{
                    showPopup(`Reboot command sent to device "${{deviceId}}". Implementation coming soon.`, true);
                    
                    // Show reboot progress
                    updateRebootProgressDisplay({{
                        status: 'Sending reboot command to device...',
                        percentage: 20,
                        message: 'Initiating device reboot'
                    }});
                    
                    // Simulate reboot progress (replace with actual implementation)
                    setTimeout(() => {{
                        updateRebootProgressDisplay({{
                            status: 'Device is rebooting...',
                            percentage: 60,
                            message: 'Applying firmware update'
                        }});
                    }}, 2000);
                    
                    setTimeout(() => {{
                        updateRebootProgressDisplay({{
                            status: 'Waiting for device to come back online...',
                            percentage: 90,
                            message: 'Finalizing boot process'
                        }});
                    }}, 5000);
                    
                    setTimeout(() => {{
                        updateRebootProgressDisplay({{
                            status: 'Device rebooted successfully',
                            percentage: 100,
                            completed: true,
                            message: 'Firmware update applied successfully'
                        }});
                        // Reset firmware download progress after successful reboot
                        updateProgressDisplay(null);
                    }}, 8000);
                    
                    // TODO: Implement actual device reboot
                    // fetch('/reboot-device', {{
                    //     method: 'POST',
                    //     headers: {{
                    //         'Content-Type': 'application/json',
                    //     }},
                    //     body: JSON.stringify({{
                    //         device_id: deviceId
                    //     }})
                    // }})
                    // .then(response => response.json())
                    // .then(result => {{
                    //     if (result.success) {{
                    //         showPopup('Device reboot command sent successfully!', true);
                    //         updateProgressDisplay(null);
                    //         // Start monitoring reboot progress
                    //         startRebootProgressMonitoring(deviceId);
                    //     }} else {{
                    //         showPopup(result.message, false);
                    //         updateRebootProgressDisplay({{
                    //             status: 'Reboot failed',
                    //             failed: true
                    //         }});
                    //     }}
                    // }})
                    // .catch(error => {{
                    //     showPopup('Error sending reboot command: ' + error.message, false);
                    //     updateRebootProgressDisplay({{
                    //         status: 'Reboot failed',
                    //         failed: true
                    //     }});
                    // }});
                }}
            }}

            function loadAvailableFirmwareVersions() {{
                const versionSelect = document.getElementById('firmware_version_select');
                
                // Clear existing options except the first one
                while (versionSelect.children.length > 1) {{
                    versionSelect.removeChild(versionSelect.lastChild);
                }}
                
                // Fetch available firmware versions from backend
                fetch('/api/firmware-versions')
                    .then(response => response.json())
                    .then(data => {{
                        if (data.success && data.versions) {{
                            if (data.versions.length === 0) {{
                                // No firmware uploaded yet
                                const option = document.createElement('option');
                                option.value = '';
                                option.textContent = 'No firmware versions available';
                                option.disabled = true;
                                versionSelect.appendChild(option);
                            }} else {{
                                // Add each uploaded firmware version
                                data.versions.forEach(firmware => {{
                                    const option = document.createElement('option');
                                    option.value = firmware.version;
                                    option.textContent = `Version ${{firmware.version}} (${{firmware.original_filename}})`;
                                    versionSelect.appendChild(option);
                                }});
                            }}
                        }} else {{
                            console.error('Failed to load firmware versions:', data.message);
                            const option = document.createElement('option');
                            option.value = '';
                            option.textContent = 'Error loading versions';
                            option.disabled = true;
                            versionSelect.appendChild(option);
                        }}
                    }})
                    .catch(error => {{
                        console.error('Error loading firmware versions:', error);
                        const option = document.createElement('option');
                        option.value = '';
                        option.textContent = 'Error loading versions';
                        option.disabled = true;
                        versionSelect.appendChild(option);
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

            function updateLogs(logsData) {{
                const configLogsContent = document.getElementById('configLogsContent');
                const commandLogsContent = document.getElementById('commandLogsContent');
                const firmwareDownloadLogsContent = document.getElementById('firmwareDownloadLogsContent');
                const firmwareBootLogsContent = document.getElementById('firmwareBootLogsContent');
                
                // Update config logs
                if (logsData.config_logs && logsData.config_logs.length > 0) {{
                    let configHTML = `
                        <table>
                            <thead>
                                <tr>
                                    <th>Device ID</th>
                                    <th>Accepted</th>
                                    <th>Rejected</th>
                                    <th>Unchanged</th>
                                    <th>Received At</th>
                                </tr>
                            </thead>
                            <tbody>
                    `;
                    logsData.config_logs.forEach(log => {{
                        const ackData = log.ack_data || {{}};
                        const accepted = (ackData.accepted || []).join(', ') || 'None';
                        const rejected = (ackData.rejected || []).join(', ') || 'None';
                        const unchanged = (ackData.unchanged || []).join(', ') || 'None';
                        
                        configHTML += `
                            <tr>
                                <td class="device-id">${{log.device_id || 'Unknown'}}</td>
                                <td style="color: #27ae60; font-weight: bold;">${{accepted}}</td>
                                <td style="color: #e74c3c; font-weight: bold;">${{rejected}}</td>
                                <td style="color: #f39c12; font-weight: bold;">${{unchanged}}</td>
                                <td>${{formatTimestamp(log.received_at)}}</td>
                            </tr>
                        `;
                    }});
                    configHTML += '</tbody></table>';
                    configLogsContent.innerHTML = configHTML;
                }} else {{
                    configLogsContent.innerHTML = '<div class="muted">No configuration acknowledgments received yet.</div>';
                }}
                
                // Update command logs
                if (logsData.command_logs && logsData.command_logs.length > 0) {{
                    let commandHTML = `
                        <table>
                            <thead>
                                <tr>
                                    <th>Device ID</th>
                                    <th>Status</th>
                                    <th>Executed At</th>
                                    <th>Error Message</th>
                                    <th>Received At</th>
                                </tr>
                            </thead>
                            <tbody>
                    `;
                    logsData.command_logs.forEach(log => {{
                        const resultData = log.result_data || {{}};
                        const status = resultData.status || 'unknown';
                        const executedAt = resultData.executed_at || 'N/A';
                        const errorMessage = resultData.error_message || 'None';
                        
                        // Color code the status
                        let statusColor = '#7f8c8d'; // Default gray
                        let statusText = status;
                        if (status === 'success') {{
                            statusColor = '#27ae60'; // Green
                            statusText = '✅ Success';
                        }} else if (status === 'failure') {{
                            statusColor = '#e74c3c'; // Red
                            statusText = '❌ Failure';
                        }}
                        
                        commandHTML += `
                            <tr>
                                <td class="device-id">${{log.device_id || 'Unknown'}}</td>
                                <td style="color: ${{statusColor}}; font-weight: bold;">${{statusText}}</td>
                                <td>${{formatTimestamp(executedAt)}}</td>
                                <td style="color: ${{errorMessage === 'None' ? '#7f8c8d' : '#e74c3c'}}; font-style: ${{errorMessage === 'None' ? 'italic' : 'normal'}};">${{errorMessage}}</td>
                                <td>${{formatTimestamp(log.received_at)}}</td>
                            </tr>
                        `;
                    }});
                    commandHTML += '</tbody></table>';
                    commandLogsContent.innerHTML = commandHTML;
                }} else {{
                    commandLogsContent.innerHTML = '<div class="muted">No command execution results received yet.</div>';
                }}
                
                // Update firmware download logs
                if (logsData.firmware_download_logs && logsData.firmware_download_logs.length > 0) {{
                    let downloadHTML = `
                        <table>
                            <thead>
                                <tr>
                                    <th>Device ID</th>
                                    <th>Firmware Version</th>
                                    <th>Download Status</th>
                                    <th>File Size</th>
                                    <th>Checksum Verified</th>
                                    <th>Received At</th>
                                </tr>
                            </thead>
                            <tbody>
                    `;
                    logsData.firmware_download_logs.forEach(log => {{
                        const downloadData = log.download_data || {{}};
                        const status = downloadData.status || 'unknown';
                        const version = downloadData.firmware_version || 'N/A';
                        const fileSize = downloadData.file_size || 'N/A';
                        const checksumVerified = downloadData.checksum_verified || false;
                        
                        // Color code the status
                        let statusColor = '#7f8c8d'; // Default gray
                        let statusText = status;
                        if (status === 'success') {{
                            statusColor = '#27ae60'; // Green
                            statusText = '✅ Download Complete';
                        }} else if (status === 'failure') {{
                            statusColor = '#e74c3c'; // Red
                            statusText = '❌ Download Failed';
                        }} else if (status === 'in_progress') {{
                            statusColor = '#3498db'; // Blue
                            statusText = '⬇️ Downloading';
                        }}
                        
                        downloadHTML += `
                            <tr>
                                <td class="device-id">${{log.device_id || 'Unknown'}}</td>
                                <td>${{version}}</td>
                                <td style="color: ${{statusColor}}; font-weight: bold;">${{statusText}}</td>
                                <td>${{fileSize}} bytes</td>
                                <td style="color: ${{checksumVerified ? '#27ae60' : '#e74c3c'}}; font-weight: bold;">${{checksumVerified ? '✅ Verified' : '❌ Failed'}}</td>
                                <td>${{formatTimestamp(log.received_at)}}</td>
                            </tr>
                        `;
                    }});
                    downloadHTML += '</tbody></table>';
                    firmwareDownloadLogsContent.innerHTML = downloadHTML;
                }} else {{
                    firmwareDownloadLogsContent.innerHTML = '<div class="muted">No firmware download verifications received yet.</div>';
                }}
                
                // Update firmware boot logs
                if (logsData.firmware_boot_logs && logsData.firmware_boot_logs.length > 0) {{
                    let bootHTML = `
                        <table>
                            <thead>
                                <tr>
                                    <th>Device ID</th>
                                    <th>Firmware Version</th>
                                    <th>Boot Status</th>
                                    <th>Boot Time</th>
                                    <th>Error Message</th>
                                    <th>Received At</th>
                                </tr>
                            </thead>
                            <tbody>
                    `;
                    logsData.firmware_boot_logs.forEach(log => {{
                        const bootData = log.boot_data || {{}};
                        const status = bootData.status || 'unknown';
                        const version = bootData.firmware_version || 'N/A';
                        const bootTime = bootData.boot_time || 'N/A';
                        const errorMessage = bootData.error_message || 'None';
                        
                        // Color code the status
                        let statusColor = '#7f8c8d'; // Default gray
                        let statusText = status;
                        if (status === 'success') {{
                            statusColor = '#27ae60'; // Green
                            statusText = '✅ Boot Successful';
                        }} else if (status === 'failure') {{
                            statusColor = '#e74c3c'; // Red
                            statusText = '❌ Boot Failed';
                        }} else if (status === 'rebooting') {{
                            statusColor = '#f39c12'; // Orange
                            statusText = '🔄 Rebooting';
                        }}
                        
                        bootHTML += `
                            <tr>
                                <td class="device-id">${{log.device_id || 'Unknown'}}</td>
                                <td>${{version}}</td>
                                <td style="color: ${{statusColor}}; font-weight: bold;">${{statusText}}</td>
                                <td>${{bootTime}}ms</td>
                                <td style="color: ${{errorMessage === 'None' ? '#7f8c8d' : '#e74c3c'}}; font-style: ${{errorMessage === 'None' ? 'italic' : 'normal'}};">${{errorMessage}}</td>
                                <td>${{formatTimestamp(log.received_at)}}</td>
                            </tr>
                        `;
                    }});
                    bootHTML += '</tbody></table>';
                    firmwareBootLogsContent.innerHTML = bootHTML;
                }} else {{
                    firmwareBootLogsContent.innerHTML = '<div class="muted">No firmware boot confirmations received yet.</div>';
                }}
            }}

            function openTab(evt, tabName) {{
                // Hide all tab contents
                var tabContents = document.getElementsByClassName("tab-content");
                for (var i = 0; i < tabContents.length; i++) {{
                    tabContents[i].classList.remove("active");
                }}

                // Remove active class from all tab buttons
                var tabButtons = document.getElementsByClassName("tab-button");
                for (var i = 0; i < tabButtons.length; i++) {{
                    tabButtons[i].classList.remove("active");
                }}

                // Show the selected tab content and mark button as active
                document.getElementById(tabName).classList.add("active");
                evt.currentTarget.classList.add("active");
            }}

            function fetchLatestData() {{
                fetch('/api/latest_data')
                    .then(r => r.json()).then(updateTable).catch(console.error);
                    
                fetch('/api/logs')
                    .then(r => r.json()).then(updateLogs).catch(console.error);
            }}
            fetchLatestData();
            setInterval(fetchLatestData, 2000);
            
            // Load available firmware versions on page load
            loadAvailableFirmwareVersions();
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


@app.route("/upload-firmware", methods=["POST"])
def upload_firmware():
    try:
        # Check if firmware version is provided
        firmware_version = request.form.get('firmware_version')
        if not firmware_version:
            return jsonify({"success": False, "message": "Firmware version is required"}), 400

        # Check if file is provided
        if 'firmware_file' not in request.files:
            return jsonify({"success": False, "message": "No file selected"}), 400
        
        file = request.files['firmware_file']
        if file.filename == '':
            return jsonify({"success": False, "message": "No file selected"}), 400

        # Check if file has .bin extension
        if not file.filename.lower().endswith('.bin'):
            return jsonify({"success": False, "message": "Only .bin files are allowed"}), 400

        # Create firmware_files directory if it doesn't exist
        firmware_dir = os.path.join(os.getcwd(), 'firmware_files')
        os.makedirs(firmware_dir, exist_ok=True)

        # Secure the filename and create a unique name with version
        original_filename = secure_filename(file.filename)
        # Create filename with version: version_originalname.bin
        filename = f"{firmware_version}_{original_filename}"
        filepath = os.path.join(firmware_dir, filename)

        # Save the file
        file.save(filepath)

        # Store firmware information for later retrieval
        firmware_info = {
            "version": firmware_version,
            "filename": filename,
            "original_filename": original_filename,
            "filepath": filepath,
            "uploaded_at": datetime.now(SRI_LANKA_TZ).isoformat()
        }
        UPLOADED_FIRMWARE.append(firmware_info)

        return jsonify({
            "success": True, 
            "message": f"Firmware version {firmware_version} uploaded successfully",
            "filename": filename,
            "version": firmware_version
        })

    except Exception as e:
        return jsonify({"success": False, "message": f"Upload failed: {str(e)}"}), 500


@app.route("/api/firmware-versions", methods=["GET"])
def get_firmware_versions():
    """Return list of available firmware versions"""
    try:
        # Return the stored firmware information
        return jsonify({
            "success": True,
            "versions": UPLOADED_FIRMWARE
        })
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to retrieve versions: {str(e)}"}), 500


@app.route("/upload", methods=["POST"])
def upload_data():
    try:
        # The new secure format contains only nonce, payload, and mac
        secure_data = request.json
                
        if not secure_data:
            return jsonify({"status": "error", "message": "Invalid JSON"}), 400
        
        # Validate the secure payload - device_id is now inside the encrypted data
        payload = validate_secure_payload(secure_data)

        if payload is None:
            # If validation fails, reject the request.
            return jsonify({"status": "error", "message": "Security validation failed"}), 403 # 403 Forbidden

        processed_payload = dict(payload)
        device_id = payload.get("device_id", "Unknown")
        
        # Process configuration acknowledgment if present
        if "config_ack" in payload:
            ack_log_entry = {
                "device_id": device_id,
                "ack_data": payload["config_ack"],
                "received_at": datetime.now(SRI_LANKA_TZ).isoformat()
            }
            CONFIG_LOGS.append(ack_log_entry)
        
        # Process command execution result if present
        if "command_result" in payload:
            command_log_entry = {
                "device_id": device_id,
                "result_data": payload["command_result"],
                "received_at": datetime.now(SRI_LANKA_TZ).isoformat()
            }
            COMMAND_LOGS.append(command_log_entry)
        
        # Process sensor data if present
        sensor_data_processed = False
        if "fields" in payload:
            sensor_data_processed = True
            for field_name, field_data in payload["fields"].items():
                if "payload" in field_data and field_data["payload"]:
                    compressed_payload = field_data["payload"]
                    decompressed_values = delta_decode(compressed_payload)
                    scale = 3 if field_name in ["AC_VOLTAGE", "AC_CURRENT", "AC_FREQUENCY"] else 0
                    original_values = [scale_back_float(val, scale) for val in decompressed_values]
                    processed_payload.setdefault("fields", {}).setdefault(field_name, {})
                    processed_payload["fields"][field_name]["decompressed_payload"] = decompressed_values
                    processed_payload["fields"][field_name]["original_values"] = original_values

        # Store the complete record
        sri_lanka_time = datetime.now(SRI_LANKA_TZ)
        record = {
            "received_at": sri_lanka_time.isoformat(),
            "device_data": processed_payload
        }
        DATA_STORAGE.append(record)

        # Store flattened copy for compression reports if sensor data was included
        if sensor_data_processed:
            flat = dict(processed_payload)
            flat["received_at"] = record["received_at"]
            COMPRESSION_REPORTS.append(flat)

        # Build response with acknowledgment status
        response = {
            "status": "ok",
            "ack_time": record["received_at"],
            "server_time_zone": "Asia/Colombo (GMT+5:30)",
            "processed": {
                "sensor_data": sensor_data_processed,
                "config_ack": "config_ack" in payload,
                "command_result": "command_result" in payload
            }
        }
        
        # Add decompression status if sensor data was present
        if sensor_data_processed:
            response["decompression_status"] = "success"

        return jsonify(response)

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


@app.route("/api/logs", methods=["GET"])
def get_logs():
    """API endpoint to get the latest config, command, and firmware logs"""
    return jsonify({
        "config_logs": CONFIG_LOGS[-10:],  # Last 10 config acknowledgments
        "command_logs": COMMAND_LOGS[-10:],  # Last 10 command results
        "firmware_download_logs": FIRMWARE_DOWNLOAD_LOGS[-10:],  # Last 10 firmware download verifications
        "firmware_boot_logs": FIRMWARE_BOOT_LOGS[-10:]  # Last 10 firmware boot confirmations
    })


@app.route("/test-ack", methods=["POST"])
def test_acknowledgment():
    """Test endpoint to simulate a device acknowledgment"""
    test_ack = {
        "device_id": "test-device",
        "config_ack": {
            "accepted": ["sampling_interval", "registers"],
            "rejected": ["invalid_param"],
            "unchanged": ["device_id"]
        }
    }
    
    # Process the test acknowledgment
    ack_log_entry = {
        "device_id": test_ack["device_id"],
        "ack_data": test_ack["config_ack"],
        "received_at": datetime.now(SRI_LANKA_TZ).isoformat()
    }
    CONFIG_LOGS.append(ack_log_entry)
    print(f"[TEST CONFIG ACK] Added test acknowledgment: {test_ack['config_ack']}")
    
    return jsonify({"status": "Test acknowledgment added", "data": test_ack})


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


@app.route("/config", methods=["POST"])
def handle_config():
    """
    Configuration endpoint for device configuration updates and command delivery.
    
    Device sends status updates and receives configuration updates or commands in response.
    Device can also send acknowledgments and command results.
    """
    try:
        print(f"\n[CONFIG DEBUG] ===== NEW CONFIG REQUEST =====")
        # The new secure format contains only nonce, payload, and mac
        secure_data = request.json
        
        print(f"[CONFIG DEBUG] Request content type: {request.content_type}")
        print(f"[CONFIG DEBUG] Request data size: {len(str(secure_data)) if secure_data else 0} chars")
                
        if not secure_data:
            return jsonify({"status": "error", "message": "Invalid JSON"}), 400
        
        # Validate the secure payload - device_id is now inside the encrypted data
        data = validate_secure_payload(secure_data)

        if data is None:
            # If validation fails, reject the request.
            print(f"[CONFIG DEBUG] Validation failed, rejecting request")
            return jsonify({"status": "error", "message": "Security validation failed"}), 403 # 403 Forbidden

        print(f"[CONFIG DEBUG] Validation successful, processing payload...")
        device_id = data.get("device_id")
        
        print(f"[CONFIG DEBUG] Processing config request from device: {device_id}")
        print(f"[CONFIG DEBUG] Payload contains: {list(data.keys())}")

        # Handle configuration acknowledgment from device
        if "config_ack" in data:
            print(f"[CONFIG DEBUG] Processing config acknowledgment: {data['config_ack']}")
            ack_log_entry = {
                "device_id": device_id,
                "ack_data": data["config_ack"],
                "received_at": datetime.now(SRI_LANKA_TZ).isoformat()
            }
            CONFIG_LOGS.append(ack_log_entry)

        # Handle command execution result from device
        if "command_result" in data:
            print(f"[CONFIG DEBUG] Processing command result: {data['command_result']}")
            result_log_entry = {
                "device_id": device_id,
                "result_data": data["command_result"],
                "received_at": datetime.now(SRI_LANKA_TZ).isoformat()
            }
            COMMAND_LOGS.append(result_log_entry)

        # Prepare response with any pending configuration or commands
        response = {}
        
        # Check for pending configuration update
        if device_id in PENDING_CONFIGS:
            config = PENDING_CONFIGS.pop(device_id)  # Send only once
            response["config_update"] = config
            print(f"[CONFIG DEBUG] Sending pending config to device {device_id}: {config}")

        # Check for pending command
        if device_id in PENDING_COMMANDS:
            command = PENDING_COMMANDS.pop(device_id)  # Send only once
            response["command"] = command
            print(f"[CONFIG DEBUG] Sending pending command to device {device_id}: {command}")

        print(f"[CONFIG DEBUG] Sending response: {response}")
        print(f"[CONFIG DEBUG] ===== CONFIG REQUEST COMPLETE =====\n")
        return jsonify(response)

    except Exception as e:
        print(f"[CONFIG DEBUG] ERROR: Exception occurred: {str(e)}")
        print(f"[CONFIG DEBUG] Exception type: {type(e).__name__}")
        import traceback
        print(f"[CONFIG DEBUG] Traceback: {traceback.format_exc()}")
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    # Load existing firmware files on startup
    load_existing_firmware()
    
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port, debug=True)
