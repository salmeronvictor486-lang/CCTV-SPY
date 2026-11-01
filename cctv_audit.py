#!/usr/bin/env python3
"""
CCTV-SPY — Auditor de red y cámaras CCTV
=========================================

Herramienta DEFENSIVA de auditoría. Escanea SOLO los objetivos que tú indicas
(tu red, tus cámaras, o un alcance que tengas autorizado por escrito), detecta
dispositivos de videovigilancia, identifica marca/servicios y, opcionalmente,
comprueba si siguen con credenciales de fábrica para que puedas corregirlo.

Uso legítimo: inventario y bastionado de sistemas propios o auditorías con
permiso. No está pensada para escanear sistemas de terceros sin autorización;
hacerlo es ilegal (en España, arts. 197 bis y 264 del Código Penal).

Solo biblioteca estándar de Python 3.8+. Sin dependencias externas.
"""

import argparse
import base64
import concurrent.futures
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
from datetime import datetime
from http.client import HTTPConnection, HTTPSConnection

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------

# Puertos típicos de cámaras IP / NVR / DVR y su significado.
CAMERA_PORTS = {
    80: "HTTP (panel web)",
    81: "HTTP alternativo",
    443: "HTTPS (panel web)",
    554: "RTSP (streaming)",
    8000: "Hikvision SDK / HTTP",
    8080: "HTTP alternativo",
    8554: "RTSP alternativo",
    8899: "ONVIF / HTTP",
    9000: "HTTP alternativo",
    34567: "Dahua/XMeye (media)",
    37777: "Dahua (SDK/DVR)",
    2020: "ONVIF",
}

# Firmas para adivinar la marca a partir de cabeceras/HTML.
VENDOR_SIGNATURES = [
    ("Hikvision", re.compile(r"hikvision|webs|dvrdvs|/doc/page/login", re.I)),
    ("Dahua", re.compile(r"dahua|dh_web|webplugin|/RPC2", re.I)),
    ("Axis", re.compile(r"axis|vapix", re.I)),
    ("Foscam", re.compile(r"foscam", re.I)),
    ("Reolink", re.compile(r"reolink", re.I)),
    ("Vivotek", re.compile(r"vivotek", re.I)),
    ("TP-Link/Tapo", re.compile(r"tp-?link|tapo", re.I)),
    ("Ubiquiti", re.compile(r"ubnt|unifi|ubiquiti", re.I)),
    ("Amcrest", re.compile(r"amcrest", re.I)),
    ("Mobotix", re.compile(r"mobotix", re.I)),
    ("Sony", re.compile(r"sony network camera", re.I)),
    ("Panasonic", re.compile(r"panasonic|i-pro", re.I)),
]

# Credenciales de fábrica más habituales por fabricante.
# Solo se prueban con --check-default-creds y sobre objetivos autorizados.
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "password"),
    ("admin", ""),
    ("admin", "admin12345"),
    ("root", "root"),
    ("root", "12345"),
    ("root", "pass"),
    ("user", "user"),
    ("guest", "guest"),
    ("admin", "9999"),
    ("admin", "4321"),
    ("supervisor", "supervisor"),
]

SOCKET_TIMEOUT = 2.0
HTTP_TIMEOUT = 4.0
USER_AGENT = "CCTV-SPY/1.0 (auditoria-autorizada)"


# ---------------------------------------------------------------------------
# Utilidades de objetivos
# ---------------------------------------------------------------------------

def parse_targets(specs):
    """Convierte una lista de especificaciones en IPs concretas.

    Admite: 192.168.1.10, 192.168.1.0/24, 192.168.1.10-192.168.1.40
    """
    hosts = []
    for spec in specs:
        spec = spec.strip()
        if not spec or spec.startswith("#"):
            continue
        try:
            if "/" in spec:  # CIDR
                net = ipaddress.ip_network(spec, strict=False)
                hosts.extend(str(ip) for ip in net.hosts())
            elif "-" in spec:  # rango inicio-fin
                start_s, end_s = spec.split("-", 1)
                start = ipaddress.ip_address(start_s.strip())
                end = ipaddress.ip_address(end_s.strip())
                cur = int(start)
                while cur <= int(end):
                    hosts.append(str(ipaddress.ip_address(cur)))
                    cur += 1
            else:  # IP suelta
                hosts.append(str(ipaddress.ip_address(spec)))
        except ValueError as exc:
            print(f"[!] Objetivo no válido '{spec}': {exc}", file=sys.stderr)
    # Deduplicar conservando orden
    seen = set()
    result = []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            result.append(h)
    return result


def load_targets_file(path):
    with open(path, "r", encoding="utf-8") as fh:
        return [line for line in fh.read().splitlines()]


# ---------------------------------------------------------------------------
# Sondas de red
# ---------------------------------------------------------------------------

def scan_port(ip, port):
    """Devuelve True si el puerto TCP está abierto."""
    try:
        with socket.create_connection((ip, port), timeout=SOCKET_TIMEOUT):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def probe_rtsp(ip, port):
    """Envía OPTIONS RTSP y devuelve la cabecera Server si responde."""
    try:
        with socket.create_connection((ip, port), timeout=SOCKET_TIMEOUT) as sock:
            req = (
                f"OPTIONS rtsp://{ip}:{port} RTSP/1.0\r\n"
                "CSeq: 1\r\n"
                f"User-Agent: {USER_AGENT}\r\n\r\n"
            )
            sock.sendall(req.encode())
            data = sock.recv(1024).decode("latin-1", "replace")
            if "RTSP/1.0" in data:
                server = ""
                for line in data.split("\r\n"):
                    if line.lower().startswith("server:"):
                        server = line.split(":", 1)[1].strip()
                return {"ok": True, "server": server, "raw": data.strip()}
    except OSError:
        pass
    return {"ok": False}


def http_get(ip, port, path="/", use_tls=False, auth=None):
    """GET HTTP(S) sencillo. Devuelve (status, headers, body) o None."""
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = HTTPSConnection(ip, port, timeout=HTTP_TIMEOUT, context=ctx)
        else:
            conn = HTTPConnection(ip, port, timeout=HTTP_TIMEOUT)
        headers = {"User-Agent": USER_AGENT}
        if auth:
            user, pwd = auth
            token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
            headers["Authorization"] = f"Basic {token}"
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        body = resp.read(4096).decode("latin-1", "replace")
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        status = resp.status
        conn.close()
        return status, hdrs, body
    except (OSError, ssl.SSLError, Exception):
        return None


def fingerprint_http(ip, port, use_tls):
    """Intenta identificar marca y título del panel web."""
    result = http_get(ip, port, "/", use_tls)
    if not result:
        return None
    status, hdrs, body = result
    server = hdrs.get("server", "")
    title = ""
    m = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
    if m:
        title = m.group(1).strip()[:80]
    haystack = f"{server} {title} {body} {hdrs.get('www-authenticate','')}"
    vendor = None
    for name, pattern in VENDOR_SIGNATURES:
        if pattern.search(haystack):
            vendor = name
            break
    return {
        "status": status,
        "server": server,
        "title": title,
        "vendor": vendor,
        "auth_required": status == 401,
        "realm": hdrs.get("www-authenticate", ""),
    }


def probe_onvif(ip, port, use_tls):
    """Comprueba si responde el servicio ONVIF (GetDeviceInformation)."""
    soap = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
        '<s:Body><GetDeviceInformation '
        'xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>'
    )
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = HTTPSConnection(ip, port, timeout=HTTP_TIMEOUT, context=ctx)
        else:
            conn = HTTPConnection(ip, port, timeout=HTTP_TIMEOUT)
        headers = {
            "Content-Type": "application/soap+xml; charset=utf-8",
            "User-Agent": USER_AGENT,
        }
        conn.request("POST", "/onvif/device_service", body=soap, headers=headers)
        resp = conn.getresponse()
        body = resp.read(2048).decode("latin-1", "replace")
        conn.close()
        if "onvif" in body.lower() or "GetDeviceInformationResponse" in body:
            return True
        if resp.status in (400, 401, 500) and "soap" in body.lower():
            return True  # Responde SOAP: hay ONVIF aunque pida auth
    except OSError:
        pass
    return False


def check_default_creds(ip, port, use_tls):
    """Prueba credenciales de fábrica contra el panel web (solo si se pide).

    Devuelve la primera combinación que da acceso (status 200 tras 401), o None.
    """
    # Confirmar primero que el recurso pide autenticación.
    base = http_get(ip, port, "/", use_tls)
    if not base:
        return None
    for user, pwd in DEFAULT_CREDENTIALS:
        res = http_get(ip, port, "/", use_tls, auth=(user, pwd))
        if not res:
            continue
        status, _, _ = res
        if status in (200, 301, 302):
            return {"user": user, "password": pwd if pwd else "(vacía)"}
        time.sleep(0.05)  # no martillear el dispositivo
    return None


# ---------------------------------------------------------------------------
# Orquestación por host
# ---------------------------------------------------------------------------

def audit_host(ip, ports, do_creds):
    """Audita un host: puertos, fingerprint y (opcional) credenciales."""
    open_ports = {}
    for port in ports:
        if scan_port(ip, port):
            open_ports[port] = {"service": CAMERA_PORTS.get(port, "desconocido")}

    if not open_ports:
        return None

    host_info = {
        "ip": ip,
        "ports": open_ports,
        "vendor": None,
        "is_camera": False,
        "rtsp": None,
        "onvif": False,
        "web": None,
        "default_creds": None,
        "findings": [],
    }

    # RTSP
    for p in (554, 8554):
        if p in open_ports:
            rtsp = probe_rtsp(ip, p)
            if rtsp.get("ok"):
                host_info["rtsp"] = {"port": p, "server": rtsp.get("server", "")}
                host_info["is_camera"] = True

    # HTTP/HTTPS fingerprint
    for p in (80, 81, 8080, 8000, 8899, 9000):
        if p in open_ports:
            fp = fingerprint_http(ip, p, use_tls=False)
            if fp:
                host_info["web"] = {"port": p, "tls": False, **fp}
                if fp.get("vendor"):
                    host_info["vendor"] = fp["vendor"]
                    host_info["is_camera"] = True
                break
    if host_info["web"] is None and 443 in open_ports:
        fp = fingerprint_http(ip, 443, use_tls=True)
        if fp:
            host_info["web"] = {"port": 443, "tls": True, **fp}
            if fp.get("vendor"):
                host_info["vendor"] = fp["vendor"]
                host_info["is_camera"] = True

    # ONVIF
    for p in (2020, 8899, 80, 8000):
        if p in open_ports:
            if probe_onvif(ip, p, use_tls=False):
                host_info["onvif"] = True
                host_info["is_camera"] = True
                break

    # Marcar como cámara también por puertos propietarios
    if any(p in open_ports for p in (37777, 34567, 8000)):
        host_info["is_camera"] = True

    # Hallazgos / recomendaciones
    if host_info["web"] and host_info["web"].get("auth_required") is False \
            and host_info["web"].get("status") == 200:
        host_info["findings"].append(
            "El panel web responde 200 sin pedir autenticación: revisa el acceso."
        )
    if host_info["rtsp"]:
        host_info["findings"].append(
            "RTSP accesible: restríngelo por firewall/VPN si da a Internet."
        )

    # Credenciales por defecto (opcional)
    if do_creds and host_info["web"]:
        w = host_info["web"]
        creds = check_default_creds(ip, w["port"], w["tls"])
        if creds:
            host_info["default_creds"] = creds
            host_info["findings"].append(
                f"CRÍTICO: credenciales de fábrica activas "
                f"({creds['user']} / {creds['password']}). Cámbialas ya."
            )

    return host_info


# ---------------------------------------------------------------------------
# Salida
# ---------------------------------------------------------------------------

def print_console_report(results, elapsed):
    print()
    print("=" * 64)
    print("  RESULTADOS DE LA AUDITORÍA CCTV-SPY")
    print("=" * 64)
    cams = [r for r in results if r and r["is_camera"]]
    others = [r for r in results if r and not r["is_camera"]]

    if not results:
        print("  No se ha encontrado ningún host con puertos abiertos.")
    for r in cams:
        print(f"\n  [CÁMARA] {r['ip']}")
        print(f"    Marca:   {r['vendor'] or 'desconocida'}")
        print(f"    Puertos: {', '.join(str(p) for p in r['ports'])}")
        if r["web"]:
            w = r["web"]
            print(f"    Web:     :{w['port']} | {w.get('title') or w.get('server') or ''}")
        if r["rtsp"]:
            print(f"    RTSP:    :{r['rtsp']['port']} | {r['rtsp']['server']}")
        if r["onvif"]:
            print("    ONVIF:   sí")
        if r["default_creds"]:
            c = r["default_creds"]
            print(f"    \033[91m[!] CREDENCIALES DE FÁBRICA: {c['user']} / {c['password']}\033[0m")
        for f in r["findings"]:
            print(f"    -> {f}")

    if others:
        print(f"\n  Otros hosts con puertos abiertos (no parecen cámaras): "
              f"{', '.join(r['ip'] for r in others)}")

    print("\n" + "-" * 64)
    print(f"  Cámaras detectadas: {len(cams)} | "
          f"Hosts con puertos abiertos: {len([r for r in results if r])} | "
          f"Tiempo: {elapsed:.1f}s")
    print("=" * 64 + "\n")


def write_html_report(results, path, scan_meta):
    cams = [r for r in results if r and r["is_camera"]]
    rows = []
    for r in cams:
        creds = r["default_creds"]
        cred_html = (
            f"<span class='bad'>{creds['user']} / {creds['password']}</span>"
            if creds else "<span class='ok'>no detectadas</span>"
        )
        findings = "".join(f"<li>{f}</li>" for f in r["findings"]) or "<li>Sin hallazgos.</li>"
        web = r["web"]
        web_txt = f":{web['port']} {web.get('title') or web.get('server') or ''}" if web else "—"
        rows.append(f"""
        <tr>
          <td class="ip">{r['ip']}</td>
          <td>{r['vendor'] or '—'}</td>
          <td>{', '.join(str(p) for p in r['ports'])}</td>
          <td>{web_txt}</td>
          <td>{'sí' if r['rtsp'] else '—'}</td>
          <td>{'sí' if r['onvif'] else '—'}</td>
          <td>{cred_html}</td>
          <td><ul>{findings}</ul></td>
        </tr>""")

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe CCTV-SPY</title>
<style>
  :root {{ --bg:#0d1117; --card:#161b22; --line:#30363d; --txt:#e6edf3;
          --mut:#8b949e; --ok:#3fb950; --bad:#f85149; --acc:#58a6ff; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;
         background:var(--bg); color:var(--txt); padding:24px; }}
  .wrap {{ max-width:1100px; margin:0 auto; }}
  h1 {{ font-size:1.5rem; margin:0 0 4px; }}
  .sub {{ color:var(--mut); margin:0 0 24px; font-size:.9rem; }}
  .stats {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:24px; }}
  .stat {{ background:var(--card); border:1px solid var(--line);
          border-radius:10px; padding:14px 18px; flex:1; min-width:130px; }}
  .stat b {{ display:block; font-size:1.8rem; color:var(--acc); }}
  .stat span {{ color:var(--mut); font-size:.8rem; }}
  table {{ width:100%; border-collapse:collapse; background:var(--card);
          border:1px solid var(--line); border-radius:10px; overflow:hidden; }}
  th,td {{ padding:10px 12px; text-align:left; border-bottom:1px solid var(--line);
          vertical-align:top; font-size:.88rem; }}
  th {{ background:#1c2128; color:var(--mut); text-transform:uppercase;
       font-size:.72rem; letter-spacing:.04em; }}
  tr:last-child td {{ border-bottom:none; }}
  .ip {{ font-family:ui-monospace,monospace; color:var(--acc); }}
  .bad {{ color:var(--bad); font-weight:600; }}
  .ok {{ color:var(--ok); }}
  ul {{ margin:0; padding-left:16px; }}
  footer {{ color:var(--mut); font-size:.78rem; margin-top:24px;
           border-top:1px solid var(--line); padding-top:12px; }}
  @media(max-width:700px){{ th:nth-child(4),td:nth-child(4){{display:none;}} }}
</style>
</head>
<body><div class="wrap">
  <h1>Informe de auditoría CCTV-SPY</h1>
  <p class="sub">Objetivos: {scan_meta['targets']} · {scan_meta['date']}</p>
  <div class="stats">
    <div class="stat"><b>{len(cams)}</b><span>Cámaras detectadas</span></div>
    <div class="stat"><b>{scan_meta['hosts_up']}</b><span>Hosts con puertos abiertos</span></div>
    <div class="stat"><b>{scan_meta['default_creds']}</b><span>Con credenciales de fábrica</span></div>
    <div class="stat"><b>{scan_meta['elapsed']:.0f}s</b><span>Duración</span></div>
  </div>
  <table>
    <thead><tr>
      <th>IP</th><th>Marca</th><th>Puertos</th><th>Web</th>
      <th>RTSP</th><th>ONVIF</th><th>Cred. fábrica</th><th>Hallazgos</th>
    </tr></thead>
    <tbody>{''.join(rows) or '<tr><td colspan=8>Ninguna cámara detectada.</td></tr>'}</tbody>
  </table>
  <footer>
    Generado por CCTV-SPY. Herramienta de auditoría defensiva para uso sobre
    sistemas propios o con autorización por escrito. El uso contra sistemas
    de terceros sin permiso es ilegal.
  </footer>
</div></body></html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

BANNER = r"""
  ____ ____ _______     __     ____  ______   __
 / ___/ ___|_   _\ \   / /    / ___||  _ \ \ / /
| |  | |     | |  \ \ / /_____\___ \| |_) \ V /
| |__| |___  | |   \ V /_____|___) |  __/ | |
 \____\____| |_|    \_/      |____/|_|    |_|
        Auditor de red y cámaras CCTV · uso autorizado
"""


def confirm_authorization(assume_yes):
    print(BANNER)
    print("Esta herramienta solo debe usarse sobre redes/dispositivos propios")
    print("o con autorización POR ESCRITO del responsable. El uso no autorizado")
    print("contra sistemas de terceros es ilegal (CP arts. 197 bis y 264).\n")
    if assume_yes:
        print("[i] Autorización confirmada por parámetro (--i-am-authorized).\n")
        return True
    try:
        ans = input("¿Confirmas que estás autorizado a auditar estos objetivos? (si/no): ")
    except EOFError:
        return False
    return ans.strip().lower() in ("si", "sí", "s", "yes", "y")


def main():
    parser = argparse.ArgumentParser(
        description="Auditor defensivo de red y cámaras CCTV (uso autorizado).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Ejemplos:
  %(prog)s -t 192.168.1.0/24
  %(prog)s -t 192.168.1.10 192.168.1.20-192.168.1.40 --check-default-creds
  %(prog)s --targets-file objetivos.txt -o informe.html
""",
    )
    parser.add_argument("-t", "--targets", nargs="+", default=[],
                        help="IPs, rangos (a-b) o CIDR a auditar.")
    parser.add_argument("--targets-file",
                        help="Fichero con un objetivo por línea.")
    parser.add_argument("--check-default-creds", action="store_true",
                        help="Prueba credenciales de fábrica (solo en objetivos propios/autorizados).")
    parser.add_argument("--ports", help="Puertos extra separados por coma (ej: 7001,8081).")
    parser.add_argument("-o", "--output", default="informe_cctv.html",
                        help="Ruta del informe HTML (por defecto informe_cctv.html).")
    parser.add_argument("--json", help="Guardar resultados también en JSON.")
    parser.add_argument("--workers", type=int, default=100,
                        help="Hilos concurrentes (por defecto 100).")
    parser.add_argument("--i-am-authorized", action="store_true",
                        help="Confirma sin preguntar que tienes autorización.")
    args = parser.parse_args()

    specs = list(args.targets)
    if args.targets_file:
        specs.extend(load_targets_file(args.targets_file))
    if not specs:
        parser.error("Indica objetivos con -t o --targets-file.")

    if not confirm_authorization(args.i_am_authorized):
        print("\n[x] Sin confirmación de autorización. Abortado.")
        sys.exit(1)

    targets = parse_targets(specs)
    if not targets:
        print("[x] No hay objetivos válidos.")
        sys.exit(1)

    ports = list(CAMERA_PORTS.keys())
    if args.ports:
        for p in args.ports.split(","):
            try:
                ports.append(int(p.strip()))
            except ValueError:
                pass
    ports = sorted(set(ports))

    print(f"[i] Objetivos: {len(targets)} host(s) | Puertos: {len(ports)} | "
          f"Credenciales por defecto: {'SÍ' if args.check_default_creds else 'no'}")
    print("[i] Escaneando...\n")

    start = time.time()
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(audit_host, ip, ports, args.check_default_creds): ip
            for ip in targets
        }
        done = 0
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            print(f"\r  Progreso: {done}/{len(targets)} hosts", end="", flush=True)
            try:
                res = fut.result()
                if res:
                    results.append(res)
            except Exception as exc:
                print(f"\n[!] Error en {futures[fut]}: {exc}", file=sys.stderr)
    print()

    elapsed = time.time() - start
    results.sort(key=lambda r: ipaddress.ip_address(r["ip"]))

    print_console_report(results, elapsed)

    cams = [r for r in results if r["is_camera"]]
    scan_meta = {
        "targets": ", ".join(specs)[:120],
        "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "hosts_up": len(results),
        "default_creds": len([r for r in cams if r["default_creds"]]),
        "elapsed": elapsed,
    }
    write_html_report(results, args.output, scan_meta)
    print(f"[+] Informe HTML: {args.output}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2, ensure_ascii=False)
        print(f"[+] JSON: {args.json}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[x] Interrumpido por el usuario.")
        sys.exit(130)
