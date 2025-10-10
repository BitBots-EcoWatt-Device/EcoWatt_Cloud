from flask import Flask, request, jsonify
from datetime import datetime, timezone, timedelta
import os

app = Flask(__name__)

# Timezone
SRI_LANKA_TZ = timezone(timedelta(hours=5, minutes=30))

# In-memory storage
DATA_STORAGE = []
COMPRESSION_REPORTS = []
ACCUMULATED_SERIES = {}  # { field_name: {labels: [...], values: [...]} }


# ---------- Utility Functions ----------

def delta_decode(deltas):
    if not deltas:
        return []
    decoded = [deltas[0]]
    for i in range(1, len(deltas)):
        decoded.append(decoded[-1] + deltas[i])
    return decoded


def scale_back_float(scaled_int, scale):
    return scaled_int / (10.0 ** scale)


def extract_device_data(payload):
    if not payload:
        return None
    if "device_data" in payload and isinstance(payload["device_data"], dict):
        return payload["device_data"]
    return payload


# ---------- Routes ----------

@app.route("/")
def index():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>EcoWatt Dashboard</title>
        <meta charset="utf-8">
        <style>
            body {font-family: 'Segoe UI', Arial; margin:0; background:#f6f8fa;}
            .header {background:#1f2937; color:white; padding:16px 24px; display:flex; justify-content:space-between; align-items:center;}
            .header h1 {margin:0; font-size:20px;}
            .btn {background:#2563eb; color:#fff; padding:8px 14px; border-radius:8px; text-decoration:none; font-weight:600;}
            .container {padding:20px; max-width:1200px; margin:auto;}
            .card {background:white; border-radius:10px; box-shadow:0 4px 8px rgba(0,0,0,0.05); padding:16px; margin-bottom:16px;}
            table {width:100%; border-collapse:collapse; margin-top:10px;}
            th, td {padding:10px; border-bottom:1px solid #eee; text-align:left; vertical-align:top;}
            th {background:#f0f6ff;}
            .field-summary {font-family: monospace; font-size:13px; line-height:1.4; color:#111;}
            .muted {color:#888;}
            .device-id {font-weight:bold; color:#e11d48;}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔋 EcoWatt Device Dashboard</h1>
            <div>
                <a class="btn" href="/display">Display</a>
                <a class="btn" href="/config">Configure</a>
            </div>
        </div>

        <div class="container">
            <div class="card">
                <h2 style="margin-top:0;">Device Reports</h2>
                <p class="muted">Auto-refreshes every 2 seconds</p>
                <div id="tableContent" class="muted">Waiting for data...</div>
            </div>
        </div>

        <script>
            function formatValues(arr){
                return arr.map(v => Number(v).toFixed(3)).join(', ');
            }

            function renderTable(data){
                if(!data.data || data.data.length===0){
                    document.getElementById('tableContent').innerHTML = '<div class="muted">No data yet</div>';
                    return;
                }
                let html = '<table><thead><tr><th>Device ID</th><th>Device Timestamp</th><th>#Fields</th><th>Samples/Field</th><th>Field Summary</th><th>Received At</th></tr></thead><tbody>';
                data.data.slice().reverse().forEach(row=>{
                    const flds = row.fields || {};
                    const names = Object.keys(flds);
                    let summary='';
                    names.forEach(fn=>{
                        const orig = flds[fn]?.original_values || [];
                        summary += `<div><b>${fn}</b>: ${formatValues(orig)}</div>`;
                    });
                    html += `<tr>
                        <td class="device-id">${row.device_id||'-'}</td>
                        <td>${row.timestamp||'-'}</td>
                        <td>${names.length}</td>
                        <td>${flds[names[0]]?.n_samples||'-'}</td>
                        <td class="field-summary">${summary}</td>
                        <td>${row.received_at||'-'}</td>
                    </tr>`;
                });
                html += '</tbody></table>';
                document.getElementById('tableContent').innerHTML = html;
            }

            async function load(){
                try{
                    const res = await fetch('/api/latest_data');
                    const data = await res.json();
                    renderTable(data);
                }catch(e){console.error(e);}
            }
            load();
            setInterval(load,2000);
        </script>
    </body>
    </html>
    """


@app.route("/display")
def display():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>EcoWatt Live Display</title>
        <meta charset="utf-8">
        <style>
            body {font-family:'Segoe UI', Arial; background:#f9fafb; margin:0;}
            .header {background:#1f2937; color:white; padding:12px 20px; display:flex; justify-content:space-between; align-items:center;}
            .btn {background:#2563eb; color:white; padding:6px 10px; border-radius:6px; text-decoration:none;}
            .container {padding:20px; max-width:1200px; margin:auto;}
            .chart-card {background:white; border-radius:10px; box-shadow:0 4px 8px rgba(0,0,0,0.05); padding:16px; margin-bottom:16px;}
            canvas {width:100%!important; height:300px!important;}
        </style>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    </head>
    <body>
        <div class="header">
            <h2>📊 EcoWatt Live Charts</h2>
            <div>
                <a class="btn" href="/">Dashboard</a>
                <a class="btn" href="/config">Configure</a>
            </div>
        </div>

        <div class="container" id="charts"></div>

        <script>
            const charts = {};

            function createChart(name){
                const div = document.createElement('div');
                div.className = 'chart-card';
                div.innerHTML = `<h3>${name}</h3><canvas id="chart_${name}"></canvas>`;
                document.getElementById('charts').appendChild(div);

                const ctx = div.querySelector('canvas').getContext('2d');
                const chart = new Chart(ctx,{
                    type:'line',
                    data:{labels:[], datasets:[{label:name,data:[],borderColor:'#2563eb',tension:0.3,fill:false,pointRadius:0}]},
                    options:{responsive:true,maintainAspectRatio:false,scales:{x:{display:false}}}
                });
                charts[name]=chart;
            }

            async function updateCharts(){
                try{
                    const r = await fetch('/api/fields_series');
                    const j = await r.json();
                    const series = j.fields_series||{};
                    for(const [fname,vals] of Object.entries(series)){
                        if(!charts[fname]) createChart(fname);
                        const chart = charts[fname];
                        chart.data.labels = vals.labels;
                        chart.data.datasets[0].data = vals.values;
                        chart.update();
                    }
                }catch(e){console.error(e);}
            }
            updateCharts();
            setInterval(updateCharts,2000);
        </script>
    </body>
    </html>
    """


@app.route("/upload", methods=["POST"])
def upload():
    try:
        payload = request.json
        device_data = extract_device_data(payload)
        if not device_data:
            return jsonify({"error": "No device_data found"}), 400

        sri_time = datetime.now(SRI_LANKA_TZ).isoformat()

        # Parse fields
        fields = device_data.get("fields", {})
        for name, fdata in fields.items():
            if not isinstance(fdata, dict):
                continue

            # Delta decode + scale
            payload_vals = fdata.get("payload", [])
            dec = delta_decode(payload_vals) if payload_vals else []
            scale = 3 if name in ["AC_VOLTAGE", "AC_CURRENT", "AC_FREQUENCY"] else 0
            orig_vals = [scale_back_float(v, scale) for v in dec] if dec else fdata.get("original_values", [])

            fdata["original_values"] = orig_vals
            fdata["n_samples"] = fdata.get("n_samples", len(orig_vals))

            # accumulate for display
            if name not in ACCUMULATED_SERIES:
                ACCUMULATED_SERIES[name] = {"labels": [], "values": []}
            for v in orig_vals:
                ACCUMULATED_SERIES[name]["labels"].append(sri_time)
                ACCUMULATED_SERIES[name]["values"].append(v)

        # Save data
        flat = dict(device_data)
        flat["received_at"] = sri_time
        COMPRESSION_REPORTS.append(flat)
        DATA_STORAGE.append({"device_data": device_data, "received_at": sri_time})

        return jsonify({"status": "ok", "received_at": sri_time})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/latest_data")
def api_latest_data():
    n = 20
    return jsonify({"data": COMPRESSION_REPORTS[-n:], "total_reports": len(COMPRESSION_REPORTS)})


@app.route("/api/fields_series")
def api_fields_series():
    return jsonify({"fields_series": ACCUMULATED_SERIES})


@app.route("/config")
def config_page():
    return """
    <html><body style='font-family:Arial;padding:40px;'>
    <h2>Configuration</h2>
    <p>POST to <code>/config</code> to update device settings.</p>
    <a href="/">← Back</a>
    </body></html>
    """


@app.route("/config", methods=["POST"])
def config_set():
    return jsonify({"status": "received", "config": request.json})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
