import re

lines = [
    "Host picostation # Antena casa Jorge # 00:15:6D:4A:3A:DF # 0-24",
    "HostName 192.168.10.150",
    "Host camara # Camara patio # 8-20",
    "HostName 192.168.10.151"
]

hosts = []
current_host = None

for line in lines:
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
                "ip": None
            }
            hosts.append(current_host)
    elif line.startswith("HostName ") and current_host is not None:
        ip = line.split(" ")[1].strip()
        current_host["ip"] = ip

print(hosts)
