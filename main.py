import os
import time
import json
import threading
import subprocess
from datetime import datetime
import requests
from flask import Flask, request, render_template_string, redirect, url_for, Response

# ───────────────── CONFIG ─────────────────
ZT_TOKEN = os.getenv("ZT_TOKEN")
ZT_NETWORK = os.getenv("ZT_NETWORK")
TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT = os.getenv("TELEGRAM_CHAT_ID")

JUMP_HOST_IP = os.getenv("JUMP_HOST_IP")
JUMP_HOST_USER = os.getenv("JUMP_HOST_USER")

WEB_USER = os.getenv("WEB_USER", "admin")
WEB_PASS = os.getenv("WEB_PASSWORD", "")

NOTIFY_OFFLINE = os.getenv("NOTIFY_OFFLINE", "true").lower() == "true"
NOTIFY_ONLINE = os.getenv("NOTIFY_ONLINE", "true").lower() == "true"
NOTIFY_OFF_SCHEDULE = os.getenv("NOTIFY_OFF_SCHEDULE", "true").lower() == "true"
NOTIFY_STARTUP = os.getenv("NOTIFY_STARTUP", "true").lower() == "true"
NOTIFY_API_ERROR = os.getenv("NOTIFY_API_ERROR", "true").lower() == "true"

CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL_SECONDS", "300"))

SSH_CONFIG_FILE = os.environ.get("SSH_CONFIG_FILE", "/app/data/config")
STATE_FILE = "/app/data/last_state.json"

ZT_API_URL = f"https://api.zerotier.com/api/v1/network/{ZT_NETWORK}/member"

app = Flask(__name__)

@app.before_request
def require_login():
    if not WEB_PASS:
        return
    auth = request.authorization
    if not auth or not (auth.username == WEB_USER and auth.password == WEB_PASS):
        return Response(
            'Acceso denegado. Credenciales incorrectas.', 401,
            {'WWW-Authenticate': 'Basic realm="ZeroTier Monitor Login"'}
        )

# Global state for dashboard
global_hosts_state = []
global_last_update = "Nunca"
monitor_event = threading.Event()

auto_zt_enabled = True

# ───────────────── UTILS ─────────────────

def send_telegram(msg: str):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT:
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        requests.post(url, data={"chat_id": TELEGRAM_CHAT, "text": msg}, timeout=5)
    except Exception as e:
        print(f"[ZT-MONITOR] Error enviando Telegram: {e}", flush=True)

ON_DEMAND_VALUES = ["none", "-", "libre", "opcional", "ondemand"]

def is_within_schedule(horario_str, current_hour):
    if not horario_str:
        return True
    if horario_str.strip().lower() in ON_DEMAND_VALUES:
        return False
    try:
        start, end = map(int, horario_str.split("-"))
        if start < end:
            return start <= current_hour < end
        else:
            return current_hour >= start or current_hour < end
    except:
        return True

def get_network(name, ip):
    if name.endswith("z") or (ip and ip.startswith("192.168.191.")):
        return "ZeroTier"
    if ip and ip.startswith("192.168.10."):
        return "Local"
    if ip and ip.startswith("192.168.1."):
        return "Remota"
    return "Desconocida"

# ───────────────── PARSER ─────────────────

def parse_ssh_config(filepath):
    if not os.path.exists(filepath):
        return []
    
    hosts = []
    current_host = None
    
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith("Host "):
                parts = [p.strip() for p in line.split("#")]
                if len(parts) >= 2:
                    name = parts[0].replace("Host ", "").strip()
                    desc = parts[1]
                    mac = parts[2] if len(parts) > 3 else None
                    horario = parts[-1] if len(parts) > 2 else "0-24"
                    current_host = {
                        "name": name,
                        "description": desc,
                        "mac": mac,
                        "horario": horario,
                        "ip": None,
                        "network": "Desconocida"
                    }
                    hosts.append(current_host)
            elif line.lower().startswith("hostname") and current_host is not None:
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[1].strip()
                    current_host["ip"] = ip
                    current_host["network"] = get_network(current_host["name"], ip)
                
    return hosts

# ───────────────── NETWORK CHECKS ─────────────────

def fetch_zt_members():
    if not ZT_TOKEN or not ZT_NETWORK:
        return {}
    try:
        headers = {"Authorization": f"token {ZT_TOKEN}"}
        r = requests.get(ZT_API_URL, headers=headers, timeout=10)
        r.raise_for_status()
        raw = r.json()
        now_ms = time.time() * 1000
        zt_nodes = {}
        
        for m in raw:
            last_ts = m.get("lastOnline") or m.get("lastSeen") or 0
            cfg = m.get("config", {}) or {}
            ip_assignments = cfg.get("ipAssignments") or []
            
            is_online = last_ts and (now_ms - last_ts) < 300000
            name = m.get("name") or m.get("nodeId", "Desconocido")
            ip = ip_assignments[0] if ip_assignments else None
            
            node_info = {
                "name": name,
                "ip": ip,
                "is_online": is_online,
                "description": f"ZT Node ({m.get('nodeId')})",
                "horario": "none"
            }
            zt_nodes[name] = node_info
            if ip:
                zt_nodes[ip] = node_info
        return zt_nodes
    except Exception as e:
        print(f"[ZT-MONITOR] Error API ZT: {e}")
        return {"API_ERROR": str(e)}

def check_local(ip):
    try:
        res = subprocess.run(["fping", "-c", "1", "-t", "500", ip], capture_output=True)
        return res.returncode == 0
    except:
        return False

def check_remote(ip):
    if not JUMP_HOST_IP or not JUMP_HOST_USER:
        print(f"[ZT-MONITOR] Remote check skipped for {ip}: Missing JUMP_HOST_IP or JUMP_HOST_USER.", flush=True)
        return False
    try:
        cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", f"{JUMP_HOST_USER}@{JUMP_HOST_IP}", f"ping -c 1 -W 1 {ip}"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            print(f"[ZT-MONITOR] check_remote failed for {ip}. RC: {res.returncode}, STDERR: {res.stderr.strip()}", flush=True)
        return res.returncode == 0
    except Exception as e:
        print(f"[ZT-MONITOR] Exception in check_remote for {ip}: {e}", flush=True)
        return False

# ───────────────── NETWORK SCANNER ─────────────────

def scan_networks():
    scanned_ips = set()
    results = []

    # 1. ZeroTier
    zt_nodes = fetch_zt_members()
    for node_info in zt_nodes.values():
        if node_info["ip"] and node_info["ip"] not in scanned_ips:
            scanned_ips.add(node_info["ip"])
            results.append({
                "ip": node_info["ip"],
                "name": node_info["name"].replace(" ", "_"),
                "network": "ZeroTier",
                "description": node_info["description"]
            })

    def parse_nmap_or_fping(stdout, network_name, prefix):
        current_ip = None
        current_name = None
        vendor = ""

        def commit_host():
            nonlocal current_ip, current_name, vendor
            if current_ip and current_ip not in scanned_ips:
                scanned_ips.add(current_ip)
                desc = current_name
                if vendor:
                    desc += f" - {vendor}"
                results.append({
                    "ip": current_ip,
                    "name": current_name.replace(" ", "_"),
                    "network": network_name,
                    "description": desc
                })

        for line in stdout.splitlines():
            line = line.strip()
            if not line: continue
            
            if line.startswith("Nmap scan report for"):
                if current_ip: commit_host()
                current_ip = None
                current_name = None
                vendor = ""
                
                parts = line.replace("Nmap scan report for", "").strip()
                if "(" in parts and parts.endswith(")"):
                    current_name = parts.split("(")[0].strip()
                    current_ip = parts.split("(")[1].replace(")", "").strip()
                else:
                    current_ip = parts
                    current_name = f"{prefix}_{current_ip.split('.')[-1]}"
                    
            elif line.startswith("MAC Address:"):
                mac_info = line.replace("MAC Address:", "").strip()
                if "(" in mac_info and mac_info.endswith(")"):
                    vendor = mac_info.split("(")[1].replace(")", "").strip()
                    
            elif line.count('.') == 3 and not line.startswith("Host:") and not line.startswith("Starting") and not line.startswith("Nmap"):
                # Handle fping simple output
                if current_ip: commit_host()
                current_ip = line
                current_name = f"{prefix}_{current_ip.split('.')[-1]}"
                vendor = ""
                
        if current_ip:
            commit_host()

    # 2. Local (192.168.10.0/24)
    try:
        res = subprocess.run(["nmap", "-sn", "192.168.10.0/24"], capture_output=True, text=True, timeout=30)
        parse_nmap_or_fping(res.stdout, "Local", "Local")
    except Exception as e:
        print(f"[ZT-MONITOR] Error escaneando red Local con nmap: {e}")

    # 3. Remota (192.168.1.0/24)
    if JUMP_HOST_IP and JUMP_HOST_USER:
        try:
            cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", 
                   f"{JUMP_HOST_USER}@{JUMP_HOST_IP}", "nmap -sn 192.168.1.0/24 2>/dev/null || fping -a -g 192.168.1.0/24 2>/dev/null"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
            parse_nmap_or_fping(res.stdout, "Remota", "Remoto")
        except Exception as e:
            print(f"[ZT-MONITOR] Error escaneando red Remota: {e}")

    return results

# ───────────────── MONITOR LOOP ─────────────────

def load_last_state():
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

def monitor_thread():
    global global_hosts_state, global_last_update, auto_zt_enabled
    
    if NOTIFY_STARTUP:
        send_telegram("🤖 Monitor ZeroTier iniciado.")
        
    api_error_sent = False
    
    while True:
        try:
            hosts = parse_ssh_config(SSH_CONFIG_FILE)
            zt_nodes = fetch_zt_members()
            
            alerts = []
            
            if "API_ERROR" in zt_nodes:
                if NOTIFY_API_ERROR and not api_error_sent:
                    alerts.append(f"❌ ERROR: La API de ZeroTier no responde. {zt_nodes['API_ERROR']}")
                    api_error_sent = True
                zt_nodes = {}
            else:
                if api_error_sent and NOTIFY_API_ERROR:
                    alerts.append("✅ INFO: La API de ZeroTier vuelve a estar operativa.")
                api_error_sent = False
                
            current_hour = datetime.now().hour
            
            config_names = {h["name"] for h in hosts}
            config_ips = {h["ip"] for h in hosts if h.get("ip")}
            
            if auto_zt_enabled:
                for k, zt_info in zt_nodes.items():
                    if zt_info["name"] not in config_names and (not zt_info["ip"] or zt_info["ip"] not in config_ips):
                        hosts.append({
                            "name": zt_info["name"],
                            "description": zt_info["description"],
                            "mac": None,
                            "horario": zt_info["horario"],
                            "ip": zt_info["ip"],
                            "network": "ZeroTier (Auto)"
                        })
                        config_names.add(zt_info["name"])
                        if zt_info["ip"]:
                            config_ips.add(zt_info["ip"])
            
            last_state = load_last_state()
            new_state = {}
            
            for h in hosts:
                ip = h.get("ip")
                net = h.get("network")
                name = h.get("name")
                
                is_online = False
                
                if net == "Local" and ip:
                    is_online = check_local(ip)
                elif "ZeroTier" in net:
                    zt_node = zt_nodes.get(ip) or zt_nodes.get(name)
                    if zt_node:
                        is_online = zt_node["is_online"]
                elif net == "Remota" and ip:
                    is_online = check_remote(ip)
                else:
                    if ip:
                        is_online = check_local(ip)
                        
                scheduled_online = is_within_schedule(h["horario"], current_hour)
                
                if is_online:
                    status = "ONLINE"
                else:
                    status = "OFFLINE" if scheduled_online else "OFFLINE (Scheduled)"
                    
                h["status"] = status
                new_state[name] = status
                
                old_status = last_state.get(name, status)
                
                if status != old_status:
                    if status == "OFFLINE" and NOTIFY_OFFLINE:
                        alerts.append(f"🔴 ALERTA: {name} ({ip or ''}) ha pasado a OFFLINE pero debería estar encendido ({h['horario']}).")
                    elif status == "ONLINE":
                        if scheduled_online and NOTIFY_ONLINE:
                            alerts.append(f"🟢 INFO: {name} ({ip or ''}) vuelve a estar ONLINE.")
                        elif not scheduled_online and NOTIFY_OFF_SCHEDULE:
                            if h["horario"].strip().lower() in ON_DEMAND_VALUES:
                                alerts.append(f"ℹ️ INFO: {name} ({ip or ''}) se ha conectado.")
                            else:
                                alerts.append(f"⚠️ ATENCIÓN: {name} ({ip or ''}) se ha conectado FUERA DE HORARIO ({h['horario']}).")
            
            global_hosts_state = hosts
            global_last_update = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            try:
                save_state(new_state)
            except Exception as e:
                print(f"[ZT-MONITOR] Warning: No se pudo guardar el estado: {e}", flush=True)
            
            for a in alerts:
                send_telegram(a)
                print(a, flush=True)
                
        except Exception as e:
            print(f"[ZT-MONITOR] Error en bucle: {e}", flush=True)
            
        monitor_event.wait(CHECK_INTERVAL)
        monitor_event.clear()

# ───────────────── FLASK APP ─────────────────

DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Monitor</title>
    <style>
        body { font-family: Arial, sans-serif; background: #111; color: #eee; padding: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 10px; border-bottom: 1px solid #333; text-align: left; }
        th { background: #222; cursor: pointer; user-select: none; }
        th:hover { background: #333; }
        tr.ONLINE td { background-color: #122818; color: #4CAF50; font-weight: bold; }
        tr.OFFLINE td { background-color: #331111; color: #F44336; font-weight: bold; }
        tr.OFFLINE_SCHEDULED td { background-color: #1a1a1a; color: #777; font-weight: bold; }
        .footer { margin-top: 15px; font-size: 0.9em; color: #aaa; }
        .btn { padding: 10px 15px; background: #4CAF50; color: white; text-decoration: none; border-radius: 5px; }
        .btn:hover { background: #45a049; }
        .header-bar { display: flex; justify-content: space-between; align-items: center; }
        .toggle-box { background: #222; padding: 10px; border-radius: 5px; display: inline-flex; align-items: center; gap: 10px; border: 1px solid #444; }
        .sort-icon { color: #888; font-size: 12px; margin-left: 5px; }
        @media (max-width: 600px) {
            body { padding: 8px; }
            th, td { padding: 6px 4px; font-size: 13px; }
            h1 { font-size: 22px; margin-top: 5px; }
            .hide-mobile { display: none; }
            .header-bar > div { display: none; }
            .sort-icon { margin-left: 2px; }
        }
    </style>
</head>
<body>
    <div class="header-bar">
        <h1>Estado de Nodos</h1>
        <div>
            <form action="/toggle_zt" method="POST" class="toggle-box" style="margin-right: 15px;">
                <label style="cursor: pointer; display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" onchange="this.form.submit()" {% if auto_zt %}checked{% endif %}>
                    Auto-detección ZeroTier
                </label>
            </form>
            <a href="/scan" class="btn" id="btnScan" onclick="showScanLoader(this)" style="margin-right: 10px; background-color: #2196F3;">
            <span id="scanText">Escanear Redes</span>
            <span id="scanLoader" style="display:none; font-size: 12px; margin-left: 5px;">⏳</span>
        </a>
        <a href="/config" class="btn">Editar Configuración</a>
        </div>
    </div>
    <table id="dashTable">
        <thead>
            <tr>
                <th onclick="sortDash(0, false)">Nombre <span class="sort-icon">↕</span></th>
                <th onclick="sortDash(1, false)" class="hide-mobile">Descripción <span class="sort-icon">↕</span></th>
                <th onclick="sortDash(2, true)">IP <span class="sort-icon">↕</span></th>
                <th onclick="sortDash(3, false)" class="hide-mobile">Red <span class="sort-icon">↕</span></th>
                <th onclick="sortDash(4, false)" class="hide-mobile">Horario <span class="sort-icon">↕</span></th>
                <th onclick="sortDash(5, false)">Estado <span class="sort-icon">↕</span></th>
            </tr>
        </thead>
        <tbody>
            {% for h in hosts %}
            <tr class="{{ h.status.replace(' (Scheduled)', '_SCHEDULED') }}">
                <td>{{ h.name }}</td>
                <td class="hide-mobile">{{ h.description }}</td>
                <td>{{ h.ip or '-' }}</td>
                <td class="hide-mobile">{{ h.network }}</td>
                <td class="hide-mobile">{{ h.horario }}</td>
                <td>{{ h.status }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    <p class="footer">Última actualización: {{ timestamp }}</p>

    <script>
    function showScanLoader(btn) {
        document.getElementById('scanText').innerText = "Escaneando... ";
        document.getElementById('scanLoader').style.display = "inline";
        btn.style.opacity = "0.7";
        btn.style.pointerEvents = "none";
    }

    let currentSortCol = -1;
        let currentSortAsc = true;

        function ip2num(ip) {
            if(!ip || ip === '-') return 0;
            let parts = ip.split('.');
            if(parts.length !== 4) return 0;
            return parts.reduce((acc, octet) => (acc * 256) + parseInt(octet, 10), 0);
        }

        function sortDash(colIndex, isIp) {
            const table = document.getElementById("dashTable");
            const tbody = table.tBodies[0];
            const rows = Array.from(tbody.querySelectorAll("tr"));
            
            if (currentSortCol === colIndex) {
                currentSortAsc = !currentSortAsc;
            } else {
                currentSortCol = colIndex;
                currentSortAsc = true;
            }
            
            rows.sort((a, b) => {
                let valA = a.cells[colIndex].innerText.trim();
                let valB = b.cells[colIndex].innerText.trim();
                
                if (isIp) {
                    valA = ip2num(valA);
                    valB = ip2num(valB);
                } else {
                    valA = valA.toLowerCase();
                    valB = valB.toLowerCase();
                }
                
                if (valA < valB) return currentSortAsc ? -1 : 1;
                if (valA > valB) return currentSortAsc ? 1 : -1;
                return 0;
            });
            
            rows.forEach(row => tbody.appendChild(row));
            
            // Update icons
            const headers = table.querySelectorAll("thead th");
            headers.forEach((th, idx) => {
                const span = th.querySelector("span");
                if (span) {
                    if (idx === colIndex) {
                        span.innerHTML = currentSortAsc ? "▲" : "▼";
                        span.style.color = "#4CAF50";
                    } else {
                        span.innerHTML = "↕";
                        span.style.color = "#888";
                    }
                }
            });
        }
    </script>
</body>
</html>
"""

CONFIG_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Editar SSH Config</title>
    <style>
        body { font-family: Arial, sans-serif; background: #111; color: #eee; padding: 20px; }
        .btn { padding: 10px 15px; background: #4CAF50; color: white; border: none; cursor: pointer; border-radius: 5px; font-size: 14px; margin-top: 10px; }
        .btn:hover { background: #45a049; }
        .btn-danger { background: #F44336; }
        .btn-danger:hover { background: #d32f2f; }
        .btn-secondary { background: #555; text-decoration: none; display: inline-block; }
        .btn-secondary:hover { background: #444; }
        .msg { padding: 10px; background: #2e7d32; margin-bottom: 15px; border-radius: 5px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; background: #222; }
        th, td { padding: 10px; border-bottom: 1px solid #333; text-align: left; font-size: 14px; }
        th { background: #1a1a1a; cursor: pointer; user-select: none; }
        th:hover { background: #2a2a2a; }
        input[type="text"] { width: 100%; padding: 6px; box-sizing: border-box; background: #333; color: white; border: 1px solid #555; border-radius: 3px; font-family: monospace;}
        .help-text { font-size: 11px; color: #aaa; display: block; margin-top: 4px; font-weight: normal; }
        .sort-icon { color: #888; margin-left: 5px; font-size: 12px; }
    </style>
</head>
<body>
    <h1>Editor Visual de Nodos</h1>
    <p>Ruta actual: <code>{{ config_path }}</code></p>
    
    {% if msg %}
    <div class="msg">{{ msg }}</div>
    {% endif %}
    
    <div style="margin-bottom: 10px; overflow: hidden;">
        <button type="button" class="btn" onclick="addHost()">+ Añadir Nuevo Host</button>
        <a href="/" class="btn btn-secondary" style="float: right;">Volver al Dashboard</a>
    </div>

    <form method="POST" id="configForm" onsubmit="prepareSubmit()">
        <textarea name="config_content" id="raw_config" style="display:none;"></textarea>
        
        <div style="overflow-x: auto;">
        <table id="hostsTable">
            <thead>
                <tr>
                    <th onclick="sortHosts('name')">Nombre (Host) <span id="sort_name" class="sort-icon">↕</span><br><span class="help-text">Sin espacios. Ej: MiServer</span></th>
                    <th onclick="sortHosts('ip')">IP (HostName) <span id="sort_ip" class="sort-icon">↕</span><br><span class="help-text">Ej: 192.168.1.100</span></th>
                    <th onclick="sortHosts('description')">Descripción <span id="sort_description" class="sort-icon">↕</span><br><span class="help-text">Nombre legible</span></th>
                    <th onclick="sortHosts('mac')">MAC <span id="sort_mac" class="sort-icon">↕</span><br><span class="help-text">Opcional. Dejar en blanco si no hay.</span></th>
                    <th onclick="sortHosts('horario')">Horario <span id="sort_horario" class="sort-icon">↕</span><br><span class="help-text">Ej: 8-18, 'libre' o 'none'</span></th>
                    <th>Acciones</th>
                </tr>
            </thead>
            <tbody>
                <!-- JS populates this -->
            </tbody>
        </table>
        </div>
        
        <br>
        <button type="submit" class="btn" style="font-size: 16px; padding: 12px 20px;">Guardar Cambios y Recargar</button>
    </form>

    <script>
        let hostsData = {{ parsed_hosts | tojson | safe }};
        const tbody = document.querySelector('#hostsTable tbody');
        
        let currentSortCol = '';
        let currentSortAsc = true;

        function ip2num(ip) {
            if(!ip) return 0;
            let parts = ip.split('.');
            if(parts.length !== 4) return 0;
            return parts.reduce((acc, octet) => (acc * 256) + parseInt(octet, 10), 0);
        }

        function sortHosts(col) {
            if (currentSortCol === col) {
                currentSortAsc = !currentSortAsc;
            } else {
                currentSortCol = col;
                currentSortAsc = true;
            }
            
            hostsData.sort((a, b) => {
                let valA = a[col] || '';
                let valB = b[col] || '';
                
                if (col === 'ip') {
                    valA = ip2num(valA);
                    valB = ip2num(valB);
                } else {
                    valA = valA.toString().toLowerCase();
                    valB = valB.toString().toLowerCase();
                }
                
                if (valA < valB) return currentSortAsc ? -1 : 1;
                if (valA > valB) return currentSortAsc ? 1 : -1;
                return 0;
            });
            
            updateHeaders();
            renderHosts();
        }

        function updateHeaders() {
            ['name', 'ip', 'description', 'mac', 'horario'].forEach(col => {
                const span = document.getElementById('sort_' + col);
                if (span) {
                    if (currentSortCol === col) {
                        span.innerHTML = currentSortAsc ? '▲' : '▼';
                        span.style.color = '#4CAF50';
                    } else {
                        span.innerHTML = '↕';
                        span.style.color = '#888';
                    }
                }
            });
        }

        function renderHosts() {
            tbody.innerHTML = '';
            if (hostsData.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding: 20px;">No hay nodos configurados. Añade uno nuevo.</td></tr>';
                return;
            }
            hostsData.forEach((host, index) => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><input type="text" value="${host.name || ''}" oninput="updateHost(${index}, 'name', this.value)" required placeholder="NombreHost"></td>
                    <td><input type="text" value="${host.ip || ''}" oninput="updateHost(${index}, 'ip', this.value)" required placeholder="192.168.x.x"></td>
                    <td><input type="text" value="${host.description || ''}" oninput="updateHost(${index}, 'description', this.value)" placeholder="Mi Ordenador"></td>
                    <td><input type="text" value="${(host.mac && host.mac.trim() !== '-' && host.mac.trim() !== 'None') ? host.mac : ''}" oninput="updateHost(${index}, 'mac', this.value)" placeholder=""></td>
                    <td><input type="text" value="${host.horario || 'libre'}" oninput="updateHost(${index}, 'horario', this.value)" placeholder="8-18 o libre"></td>
                    <td><button type="button" class="btn btn-danger" style="margin-top:0;" onclick="removeHost(${index})">Eliminar</button></td>
                `;
                tbody.appendChild(tr);
            });
        }

        function updateHost(index, field, value) {
            hostsData[index][field] = value;
        }

        function addHost() {
            hostsData.push({
                name: 'NuevoHost',
                ip: '',
                description: 'Descripción',
                mac: '',
                horario: 'libre',
                network: ''
            });
            renderHosts();
        }

        function removeHost(index) {
            if(confirm("¿Seguro que deseas eliminar este host?")) {
                hostsData.splice(index, 1);
                renderHosts();
            }
        }

        function prepareSubmit() {
            // Ordenar por IP antes de guardar para que el archivo físico quede ordenado
            hostsData.sort((a, b) => ip2num(a.ip) - ip2num(b.ip));
            
            let configText = "";
            hostsData.forEach(h => {
                if(!h.name || !h.ip) return; // Skip invalid
                let name = h.name.trim().replace(/\\s+/g, "_"); // Remove spaces
                let desc = h.description ? h.description.trim() : name;
                let mac = h.mac ? h.mac.trim() : "";
                let hor = h.horario ? h.horario.trim() : "libre";
                
                configText += `Host ${name} # ${desc} # ${mac} # ${hor}\n`;
                configText += `HostName ${h.ip}\n\n`;
            });
            document.getElementById('raw_config').value = configText;
        }

        // Init por IP inicialmente si se desea
        sortHosts('ip');
    </script>
</body>
</html>
"""

SCAN_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Escanear Dispositivos</title>
    <style>
        body { font-family: Arial, sans-serif; background: #111; color: #eee; padding: 20px; }
        .btn { padding: 10px 15px; background: #4CAF50; color: white; border: none; cursor: pointer; border-radius: 5px; font-size: 14px; margin-top: 10px; text-decoration: none; display: inline-block; }
        .btn:hover { background: #45a049; }
        .btn-secondary { background: #555; }
        .btn-secondary:hover { background: #444; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; background: #222; }
        th, td { padding: 10px; border-bottom: 1px solid #333; text-align: left; font-size: 14px; }
        th { background: #1a1a1a; }
        input[type="text"] { width: 100%; padding: 6px; box-sizing: border-box; background: #333; color: white; border: 1px solid #555; border-radius: 3px; font-family: monospace;}
        .help-text { font-size: 11px; color: #aaa; display: block; margin-top: 4px; font-weight: normal; }
        .loader { border: 4px solid #333; border-top: 4px solid #2196F3; border-radius: 50%; width: 30px; height: 30px; animation: spin 1s linear infinite; margin: 20px auto; display: none; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <h1>Dispositivos No Configurados</h1>
    <p>Se han escaneado las redes (Local, Remota, ZeroTier). Los siguientes dispositivos <strong>no están</strong> en tu configuración SSH:</p>
    
    <div style="margin-bottom: 10px; overflow: hidden;">
        <a href="/" class="btn btn-secondary" style="float: right;">Volver al Dashboard</a>
    </div>

    <form method="POST" action="/scan_add">
        <div style="overflow-x: auto;">
        <table id="scanTable">
            <thead>
                <tr>
                    <th>Añadir</th>
                    <th>IP (HostName)</th>
                    <th>Red Detectada</th>
                    <th>Nombre (Host)<br><span class="help-text">Puedes editarlo</span></th>
                    <th>Descripción<br><span class="help-text">Puedes editarla</span></th>
                    <th>Horario<br><span class="help-text">Por defecto 'libre'</span></th>
                </tr>
            </thead>
            <tbody>
                {% if devices|length == 0 %}
                <tr><td colspan="6" style="text-align:center; padding: 20px;">No se encontraron dispositivos nuevos.</td></tr>
                {% endif %}
                {% for d in devices %}
                <tr>
                    <td style="text-align: center;">
                        <input type="checkbox" name="add_ip_{{ d.ip }}" value="1" style="transform: scale(1.5);">
                        <input type="hidden" name="ip_{{ d.ip }}" value="{{ d.ip }}">
                    </td>
                    <td><strong>{{ d.ip }}</strong></td>
                    <td>{{ d.network }}</td>
                    <td><input type="text" name="name_{{ d.ip }}" value="{{ d.name }}" required></td>
                    <td><input type="text" name="desc_{{ d.ip }}" value="{{ d.description }}"></td>
                    <td><input type="text" name="horario_{{ d.ip }}" value="libre"></td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        </div>
        
        {% if devices|length > 0 %}
        <br>
        <button type="submit" class="btn" style="font-size: 16px; padding: 12px 20px; background-color: #2196F3;" onclick="this.innerHTML='Guardando...'">Añadir Seleccionados al Config</button>
        {% endif %}
    </form>
</body>
</html>
"""

@app.route("/")
def index():
    def sort_key(h):
        status = h.get("status", "")
        if status == "OFFLINE":
            prio = 1
        elif status == "ONLINE":
            prio = 2
        else:
            prio = 3
            
        ip = h.get("ip") or ""
        try:
            ip_parts = tuple(int(x) for x in ip.split(".")) if ip.count(".") == 3 else (0,0,0,0)
        except ValueError:
            ip_parts = (0,0,0,0)
            
        return (prio, ip_parts)
        
    sorted_hosts = sorted(global_hosts_state, key=sort_key)
    return render_template_string(DASHBOARD_TEMPLATE, hosts=sorted_hosts, timestamp=global_last_update, auto_zt=auto_zt_enabled)

@app.route("/toggle_zt", methods=["POST"])
def toggle_zt():
    global auto_zt_enabled
    auto_zt_enabled = not auto_zt_enabled
    return redirect("/")

@app.route("/api/status")
def api_status():
    return json.dumps(global_hosts_state)

@app.route("/config", methods=["GET", "POST"])
def edit_config():
    msg = None
    if request.method == "POST":
        new_content = request.form.get("config_content", "")
        # Normalize line endings
        new_content = new_content.replace("\r\n", "\n")
        try:
            with open(SSH_CONFIG_FILE, "w") as f:
                f.write(new_content)
            msg = "Configuración guardada exitosamente."
            monitor_event.set()
        except Exception as e:
            msg = f"Error al guardar: {e}"
            
    content = ""
    parsed_hosts = []
    if os.path.exists(SSH_CONFIG_FILE):
        with open(SSH_CONFIG_FILE, "r") as f:
            content = f.read()
        parsed_hosts = parse_ssh_config(SSH_CONFIG_FILE)
            
    return render_template_string(CONFIG_TEMPLATE, content=content, config_path=SSH_CONFIG_FILE, msg=msg, parsed_hosts=parsed_hosts)

@app.route("/scan")
def scan_view():
    # 1. Leer config actual para saber cuáles excluir
    hosts = parse_ssh_config(SSH_CONFIG_FILE)
    config_ips = {h["ip"] for h in hosts if h.get("ip")}
    
    # 2. Escanear
    scanned_devices = scan_networks()
    
    # 3. Filtrar
    new_devices = [d for d in scanned_devices if d["ip"] not in config_ips]
    
    return render_template_string(SCAN_TEMPLATE, devices=new_devices)

@app.route("/scan_add", methods=["POST"])
def scan_add():
    hosts = parse_ssh_config(SSH_CONFIG_FILE)
    
    # Identificar cuáles han sido marcados para añadir
    for key in request.form:
        if key.startswith("add_ip_"):
            ip_id = key.replace("add_ip_", "")
            
            ip = request.form.get(f"ip_{ip_id}")
            name = request.form.get(f"name_{ip_id}")
            desc = request.form.get(f"desc_{ip_id}")
            horario = request.form.get(f"horario_{ip_id}")
            
            if ip and name:
                hosts.append({
                    "name": name.strip().replace(" ", "_"),
                    "ip": ip.strip(),
                    "description": desc.strip() if desc else name,
                    "mac": "",
                    "horario": horario.strip() if horario else "libre",
                    "network": "Nueva"
                })
    
    # Función de utilidad compartida
    def ip2num(ip_str):
        if not ip_str: return 0
        parts = ip_str.split('.')
        if len(parts) != 4: return 0
        return sum(int(octet) * (256 ** (3 - i)) for i, octet in enumerate(parts) if octet.isdigit())
        
    hosts.sort(key=lambda h: ip2num(h.get("ip", "")))
    
    # Generar texto y guardar
    config_text = ""
    for h in hosts:
        if not h.get("name") or not h.get("ip"): continue
        mac_str = h.get("mac") or ""
        config_text += f"Host {h['name']} # {h['description']} # {mac_str} # {h.get('horario', 'libre')}\n"
        config_text += f"HostName {h['ip']}\n\n"
        
    with open(SSH_CONFIG_FILE, "w") as f:
        f.write(config_text)
        
    monitor_event.set()
        
    return redirect("/config")

if __name__ == "__main__":
    print("[ZT-MONITOR] Iniciando monitor...", flush=True)
    os.makedirs("/app/data", exist_ok=True)
    
    # Iniciar hilo de monitorización
    t = threading.Thread(target=monitor_thread, daemon=True)
    t.start()
    
    # Iniciar Flask
    app.run(host="0.0.0.0", port=8080)
