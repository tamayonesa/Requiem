#!/usr/bin/env python3
# REQUIEM - herramienta interactiva de reconocimiento web y generación de informes.

import argparse
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from html import escape

# Colores ANSI
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"

CABECERAS_SEGURIDAD = {
    "Strict-Transport-Security": ("Fuerza el uso de HTTPS en navegadores compatibles.", "Reduce ataques de downgrade y sslstrip."),
    "Content-Security-Policy": ("Restringe los orígenes de scripts, estilos y otros recursos.", "Ayuda a mitigar XSS e inyección de contenido."),
    "X-Frame-Options": ("Controla la carga de la página dentro de iframes.", "Ayuda a prevenir clickjacking."),
    "X-Content-Type-Options": ("Evita que el navegador adivine el tipo MIME.", "Reduce ataques de MIME sniffing."),
    "Referrer-Policy": ("Controla la información enviada en la cabecera Referer.", "Reduce filtraciones de URL."),
    "Permissions-Policy": ("Restringe ciertas API del navegador.", "Reduce la exposición de funcionalidades."),
    "Cross-Origin-Opener-Policy": ("Aísla contextos de navegación entre orígenes.", "Reduce algunas fugas entre ventanas."),
    "Cross-Origin-Resource-Policy": ("Controla quién puede cargar los recursos.", "Limita usos no deseados entre orígenes."),
}
CABECERAS_FUGA = ["Server", "X-Powered-By", "X-AspNet-Version", "Via"]
PUERTOS_COMUNES = [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]

def banner():
    print(CYAN + BOLD + r"""
 ██▀███  ▓█████   █████   █    ██  ██▓▓█████  ███▄ ▄███▓
▓██ ▒ ██▒▓█   ▀ ▒██▓  ██▒ ██  ▓██▒▓██▒▓█   ▀ ▓██▒▀█▀ ██▒
▓██ ░▄█ ▒▒███   ▒██▒  ██░▓██  ▒██░▒██▒▒███   ▓██    ▓██░
▒██▀▀█▄  ▒▓█  ▄ ░██  █▀ ░▓▓█  ░██░░██░▒▓█  ▄ ▒██    ▒██ 
░██▓ ▒██▒░▒████▒░▒███▒█▄ ▒▒█████▓ ░██░░▒████▒▒██▒   ░██▒
░ ▒▓ ░▒▓░░░ ▒░ ░░░ ▒▒░ ▒ ░▒▓▒ ▒ ▒ ░▓  ░░ ▒░ ░░ ▒░   ░  ░
  ░▒ ░ ▒░ ░ ░  ░ ░ ▒░  ░ ░░▒░ ░ ░  ▒ ░ ░ ░  ░░  ░      ░
  ░░   ░    ░      ░   ░  ░░░ ░ ░  ▒ ░   ░   ░      ░   
   ░        ░  ░    ░       ░      ░     ░  ░       ░   
                                                        
""" + RESET + MAGENTA + "        RECON • WEB AUDIT • INTELLIGENCE • REPORTS" + RESET)
    print(DIM + "        Solo para sistemas propios o con autorización." + RESET)

def normalizar_dominio(valor):
    valor = valor.strip()
    if "://" in valor:
        valor = urllib.parse.urlparse(valor).hostname or valor
    valor = valor.split("/")[0].split(":")[0].strip().lower()
    if not valor or not re.fullmatch(r"[a-z0-9.-]+", valor):
        raise ValueError("Introduce un dominio válido, por ejemplo ejemplo.com")
    return valor

def http_get(url, timeout=8, headers=None):
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "REQUIEM/1.0 (authorized security assessment)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {"status": resp.status, "body": resp.read(), "headers": dict(resp.getheaders()), "url": resp.geturl(), "error": None}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": e.read(), "headers": dict(e.headers), "url": url, "error": None}
    except Exception as e:
        return {"status": None, "body": b"", "headers": {}, "url": url, "error": str(e)}

def modulo_dns(dominio):
    datos = {"ips": [], "alias": []}
    try:
        info = socket.getaddrinfo(dominio, None)
        datos["ips"] = sorted(set(item[4][0] for item in info))
    except socket.gaierror as e:
        datos["error"] = str(e)
    try:
        datos["alias"] = socket.gethostbyname_ex(dominio)[1]
    except Exception:
        pass
    return datos

def modulo_tls(dominio):
    datos = {}
    try:
        contexto = ssl.create_default_context()
        with socket.create_connection((dominio, 443), timeout=6) as sock:
            with contexto.wrap_socket(sock, server_hostname=dominio) as ssock:
                cert = ssock.getpeercert()
                datos["emisor"] = dict(x[0] for x in cert.get("issuer", []))
                datos["valido_hasta"] = cert.get("notAfter")
                datos["san"] = [v for k, v in cert.get("subjectAltName", [])]
    except Exception as e:
        datos["error"] = str(e)
    return datos

def modulo_http(dominio):
    url = "https://" + dominio
    r = http_get(url)
    if r["status"] is None:
        r = http_get("http://" + dominio)
    headers = {k.lower(): v for k, v in r["headers"].items()}
    seguridad = {}
    for nombre in CABECERAS_SEGURIDAD:
        seguridad[nombre] = headers.get(nombre.lower())
    fugas = {nombre: headers[nombre.lower()] for nombre in CABECERAS_FUGA if nombre.lower() in headers}
    return {"url": r["url"], "status": r["status"], "error": r["error"], "seguridad": seguridad, "fugas": fugas, "headers": r["headers"]}

def modulo_whois(dominio):
    tld = dominio.rsplit(".", 1)[-1]
    resultado = {"servidor": None, "salida": "", "error": None}
    try:
        with socket.create_connection(("whois.iana.org", 43), timeout=5) as s:
            s.sendall((tld + "\r\n").encode())
            respuesta = b""
            while True:
                bloque = s.recv(4096)
                if not bloque:
                    break
                respuesta += bloque
        for linea in respuesta.decode(errors="ignore").splitlines():
            if linea.lower().startswith("whois:"):
                resultado["servidor"] = linea.split(":", 1)[1].strip()
                break
        if not resultado["servidor"]:
            resultado["error"] = "No se encontró servidor WHOIS para el TLD."
            return resultado
        with socket.create_connection((resultado["servidor"], 43), timeout=6) as s:
            s.sendall((dominio + "\r\n").encode())
            partes = []
            while True:
                try:
                    bloque = s.recv(4096)
                except socket.timeout:
                    break
                if not bloque:
                    break
                partes.append(bloque)
        resultado["salida"] = b"".join(partes).decode(errors="ignore")
    except Exception as e:
        resultado["error"] = str(e)
    return resultado

def modulo_crtsh(dominio):
    url = "https://crt.sh/?" + urllib.parse.urlencode({"q": "%." + dominio, "output": "json"})
    r = http_get(url, timeout=15)
    if r["status"] != 200:
        return {"subdominios": [], "error": r["error"] or "crt.sh no devolvió HTTP 200"}
    try:
        registros = json.loads(r["body"].decode(errors="ignore"))
        nombres = set()
        for registro in registros:
            for nombre in registro.get("name_value", "").splitlines():
                nombre = nombre.strip().lower().lstrip("*.")
                if nombre == dominio or nombre.endswith("." + dominio):
                    nombres.add(nombre)
        return {"subdominios": sorted(nombres), "error": None}
    except Exception as e:
        return {"subdominios": [], "error": str(e)}

def modulo_wayback(dominio):
    url = "https://archive.org/wayback/available?" + urllib.parse.urlencode({"url": dominio})
    r = http_get(url, timeout=10)
    try:
        info = json.loads(r["body"].decode(errors="ignore"))
        snap = info.get("archived_snapshots", {}).get("closest")
        return snap or {}
    except Exception:
        return {}

def modulo_robots(dominio):
    resultados = {}
    for ruta in ["/robots.txt", "/sitemap.xml"]:
        r = http_get("https://" + dominio + ruta, timeout=6)
        if r["status"] is None:
            r = http_get("http://" + dominio + ruta, timeout=6)
        resultados[ruta] = {"status": r["status"], "bytes": len(r["body"]), "error": r["error"]}
    return resultados

def modulo_puertos(dominio, puertos):
    resultados = []
    try:
        ip = socket.gethostbyname(dominio)
    except socket.gaierror as e:
        return {"ip": None, "abiertos": [], "error": str(e)}
    for puerto in puertos:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.7)
        try:
            if sock.connect_ex((ip, puerto)) == 0:
                resultados.append(puerto)
        except OSError:
            pass
        finally:
            sock.close()
    return {"ip": ip, "abiertos": resultados, "error": None}

def modulo_subdominios(dominio, palabras):
    encontrados = []
    for palabra in palabras:
        nombre = palabra.strip() + "." + dominio
        try:
            ips = sorted(set(item[4][0] for item in socket.getaddrinfo(nombre, None)))
            encontrados.append({"dominio": nombre, "ips": ips})
        except socket.gaierror:
            pass
    return encontrados

def modulo_analisis_objetivo(dominio, opciones, puertos, palabras):
    informe = {
        "herramienta": "REQUIEM",
        "objetivo": dominio,
        "inicio_utc": datetime.now(timezone.utc).isoformat(),
        "alcance_declarado": opciones["alcance"],
        "modulos": {},
        "notas": [
            "Los resultados son observaciones técnicas, no una certificación de seguridad.",
            "La ausencia de una cabecera no demuestra por sí sola una vulnerabilidad explotable.",
            "El escaneo TCP genera tráfico directo y puede aparecer en registros."
        ]
    }
    modulos = informe["modulos"]
    if opciones["whois"]:
        modulos["whois"] = modulo_whois(dominio)
    if opciones["crtsh"]:
        modulos["certificados_ct"] = modulo_crtsh(dominio)
    if opciones["wayback"]:
        modulos["wayback"] = modulo_wayback(dominio)
    if opciones["robots"]:
        modulos["robots_sitemap"] = modulo_robots(dominio)
    if opciones["dns"]:
        modulos["dns"] = modulo_dns(dominio)
    if opciones["puertos"]:
        modulos["puertos_tcp"] = modulo_puertos(dominio, puertos)
    if opciones["tls"]:
        modulos["tls"] = modulo_tls(dominio)
    if opciones["headers"]:
        modulos["http_headers"] = modulo_http(dominio)
    if opciones["subdominios"]:
        modulos["subdominios_activos"] = modulo_subdominios(dominio, palabras)
    informe["fin_utc"] = datetime.now(timezone.utc).isoformat()
    return informe

def clasificacion(informe):
    modulos = informe["modulos"]
    hallazgos = []
    h = modulos.get("http_headers")
    if h:
        ausentes = [k for k, v in h["seguridad"].items() if not v]
        if ausentes:
            hallazgos.append(("MEDIA", "Cabeceras HTTP de seguridad ausentes", "No se observaron: " + ", ".join(ausentes)))
        if h["fugas"]:
            hallazgos.append(("BAJA", "Cabeceras que revelan información tecnológica", ", ".join(k + "=" + str(v) for k, v in h["fugas"].items())))
    p = modulos.get("puertos_tcp")
    if p and p.get("abiertos"):
        hallazgos.append(("INFO", "Puertos TCP accesibles", "Puertos observados abiertos: " + ", ".join(str(x) for x in p["abiertos"])))
    t = modulos.get("tls")
    if t and t.get("error"):
        hallazgos.append(("INFO", "No se pudo inspeccionar TLS", t["error"]))
    return hallazgos

def html_informe(informe):
    hallazgos = clasificacion(informe)
    def esc(x):
        return escape(str(x))
    filas = ""
    for nivel, titulo, detalle in hallazgos:
        color = {"MEDIA": "#f0a23b", "BAJA": "#56b6c2", "INFO": "#8290a8"}.get(nivel, "#8290a8")
        filas += f"<tr><td><span class='badge' style='border-color:{color};color:{color}'>{esc(nivel)}</span></td><td>{esc(titulo)}</td><td>{esc(detalle)}</td></tr>"
    if not filas:
        filas = "<tr><td colspan='3'>No se generaron hallazgos automáticos. Revisa los módulos y sus limitaciones.</td></tr>"
    datos = json.dumps(informe, ensure_ascii=False, indent=2)
    datos = esc(datos)
    return """<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>REQUIEM | Informe</title><style>
:root{--bg:#080b12;--panel:#111827;--line:#263248;--text:#e5edf7;--muted:#95a5bc;--cyan:#5ee7df;--pink:#e879f9}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at top,#172033 0,#080b12 60%);color:var(--text);font:15px/1.6 system-ui,Segoe UI,sans-serif}
header{padding:36px 6vw 28px;border-bottom:1px solid var(--line)}.logo{font-size:clamp(32px,6vw,58px);letter-spacing:.14em;font-weight:900;color:var(--cyan)}.sub{color:var(--pink);letter-spacing:.2em;font-size:12px}
main{max-width:1100px;margin:28px auto;padding:0 20px}.panel{background:#101724d9;border:1px solid var(--line);border-radius:14px;padding:22px;margin-bottom:18px;box-shadow:0 12px 35px #0003}
h2{margin-top:0;color:var(--cyan)}.meta{color:var(--muted);overflow-wrap:anywhere}.badge{border:1px solid;padding:3px 9px;border-radius:20px;font-size:12px;font-weight:700}
table{border-collapse:collapse;width:100%;overflow-wrap:anywhere}th,td{text-align:left;padding:12px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted)}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#080d16;border:1px solid var(--line);padding:16px;border-radius:8px;max-height:650px;overflow:auto}footer{color:var(--muted);text-align:center;padding:28px}
</style></head><body><header><div class="logo">REQUIEM</div><div class="sub">RECON • WEB AUDIT • INTELLIGENCE</div><p>Informe técnico de reconocimiento</p></header><main>
<div class="panel"><h2>Resumen del análisis</h2><div class="meta">Objetivo: """ + esc(informe["objetivo"]) + """<br>Alcance declarado: """ + esc(informe["alcance_declarado"]) + """<br>Inicio UTC: """ + esc(informe["inicio_utc"]) + """<br>Fin UTC: """ + esc(informe["fin_utc"]) + """</div></div>
<div class="panel"><h2>Hallazgos automáticos</h2><table><thead><tr><th>Nivel</th><th>Hallazgo</th><th>Detalle</th></tr></thead><tbody>""" + filas + """</tbody></table><p class="meta">La prioridad es orientativa y requiere validación manual.</p></div>
<div class="panel"><h2>Resultados completos</h2><pre>""" + datos + """</pre></div>
<div class="panel"><h2>Limitaciones y uso responsable</h2><ul>""" + "".join("<li>" + esc(n) + "</li>" for n in informe["notas"]) + """<li>Usa REQUIEM únicamente contra activos propios o con autorización explícita.</li></ul></div>
</main><footer>REQUIEM · Informe generado localmente</footer></body></html>"""

def guardar_informe(informe, carpeta):
    os.makedirs(carpeta, exist_ok=True)
    marca = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = re.sub(r"[^a-zA-Z0-9.-]", "_", informe["objetivo"])
    ruta_json = os.path.join(carpeta, "REQUIEM_" + base + "_" + marca + ".json")
    ruta_html = os.path.join(carpeta, "REQUIEM_" + base + "_" + marca + ".html")
    with open(ruta_json, "w", encoding="utf-8") as f:
        json.dump(informe, f, ensure_ascii=False, indent=2)
    with open(ruta_html, "w", encoding="utf-8") as f:
        f.write(html_informe(informe))
    return ruta_html, ruta_json

def menu():
    banner()
    print("\n" + BOLD + " [1] Análisis completo" + RESET)
    print(" [2] Reconocimiento pasivo")
    print(" [3] Auditoría web (HTTP/TLS/cabeceras)")
    print(" [4] Reconocimiento activo (DNS/puertos/subdominios)")
    print(" [5] Capturador User-Agent (servidor local)")
    print(" [0] Salir")
    return input("\nREQUIEM > ").strip()

def ejecutar_servidor_ua(host="127.0.0.1", puerto=8000):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    capturas = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            captura = {"timestamp": datetime.now().isoformat(timespec="seconds"), "ip_origen": self.client_address[0],
                       "metodo": "GET", "ruta": self.path, "user_agent": self.headers.get("User-Agent", "(sin User-Agent)")}
            capturas.append(captura)
            print(CYAN + "[" + captura["timestamp"] + "] " + captura["ip_origen"] + " " + self.path + RESET)
            print("    User-Agent: " + captura["user_agent"])
            cuerpo = (json.dumps(capturas, ensure_ascii=False, indent=2) if self.path == "/capturas" else
                      "<!doctype html><meta charset='utf-8'><title>REQUIEM UA</title><body style='background:#080b12;color:#5ee7df;font:16px monospace;padding:30px'><h1>REQUIEM // UA SENSOR</h1><p>Petición registrada.</p><p>IP: " + escape(captura["ip_origen"]) + "</p><p>User-Agent: " + escape(captura["user_agent"]) + "</p><a style='color:#e879f9' href='/capturas'>Ver capturas JSON</a></body>").encode("utf-8")
            if isinstance(cuerpo, str):
                cuerpo = cuerpo.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8" if self.path == "/capturas" else "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(cuerpo)))
            self.end_headers()
            self.wfile.write(cuerpo)
        def log_message(self, fmt, *args):
            pass
    print("\nSensor User-Agent en http://" + host + ":" + str(puerto) + " (Ctrl+C para detener)")
    print("Prueba: curl -A 'REQUIEM-test/1.0' http://" + host + ":" + str(puerto) + "/")
    try:
        ThreadingHTTPServer((host, puerto), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\nSensor detenido.")

def main():
    parser = argparse.ArgumentParser(description="REQUIEM - reconocimiento autorizado e informes.")
    parser.add_argument("--target", help="Dominio objetivo")
    parser.add_argument("--mode", choices=["full", "passive", "web", "active"], default="full")
    parser.add_argument("--ports", help="Puertos TCP separados por comas")
    parser.add_argument("--wordlist", help="Fichero con prefijos de subdominio, uno por línea")
    parser.add_argument("--reports", default="reports", help="Carpeta de informes (por defecto: reports)")
    args = parser.parse_args()
    if args.target:
        ejecutar(args.target, args.mode, args.ports, args.wordlist, args.reports)
        return
    while True:
        opcion = menu()
        if opcion == "0":
            print(CYAN + "Hasta luego. Mantén la curiosidad y el permiso." + RESET)
            break
        if opcion == "5":
            ejecutar_servidor_ua()
            continue
        if opcion not in ["1", "2", "3", "4"]:
            print(RED + "Opción no válida." + RESET)
            continue
        objetivo = input("Dominio objetivo (solo activos autorizados): ").strip()
        try:
            dominio = normalizar_dominio(objetivo)
        except ValueError as e:
            print(RED + str(e) + RESET)
            continue
        if input("¿Tienes autorización para analizar este objetivo? [s/N]: ").strip().lower() != "s":
            print(YELLOW + "Análisis cancelado: confirma autorización antes de continuar." + RESET)
            continue
        modo = {"1": "full", "2": "passive", "3": "web", "4": "active"}[opcion]
        puertos = input("Puertos TCP (coma separados; Enter = comunes): ").strip()
        wordlist = input("Fichero de subdominios (Enter = lista integrada): ").strip() or None
        ejecutar(dominio, modo, puertos or None, wordlist, args.reports)

def ejecutar(objetivo, modo, puertos_arg, wordlist_path, carpeta):
    try:
        dominio = normalizar_dominio(objetivo)
    except ValueError as e:
        print(RED + str(e) + RESET)
        return
    alcance = input("Describe el alcance autorizado (ej. dominio corporativo propio / laboratorio): ").strip() or "No especificado"
    puertos = PUERTOS_COMUNES
    if puertos_arg:
        try:
            puertos = sorted(set(int(p.strip()) for p in puertos_arg.split(",") if p.strip()))
            if any(p < 1 or p > 65535 for p in puertos):
                raise ValueError()
        except ValueError:
            print(RED + "Lista de puertos inválida." + RESET)
            return
    palabras = ["www", "mail", "ftp", "vpn", "api", "dev", "test", "staging", "admin", "portal", "blog"]
    if wordlist_path:
        try:
            with open(wordlist_path, encoding="utf-8") as f:
                palabras = [x.strip() for x in f if x.strip()]
        except OSError as e:
            print(RED + "No se pudo leer la wordlist: " + str(e) + RESET)
            return
    opciones = {"alcance": alcance, "whois": modo in ["full", "passive"], "crtsh": modo in ["full", "passive"],
                "wayback": modo in ["full", "passive"], "robots": modo in ["full", "passive", "web"],
                "dns": modo in ["full", "active"], "puertos": modo in ["full", "active"],
                "tls": modo in ["full", "web"], "headers": modo in ["full", "web"],
                "subdominios": modo in ["full", "active"]}
    print(CYAN + "\n[*] REQUIEM iniciado para " + dominio + RESET)
    print(YELLOW + "[!] Los módulos activos generan tráfico directo." + RESET)
    informe = modulo_analisis_objetivo(dominio, opciones, puertos, palabras)
    html_path, json_path = guardar_informe(informe, carpeta)
    print(GREEN + "\n[+] Análisis terminado." + RESET)
    print("Informe HTML: " + os.path.abspath(html_path))
    print("Datos JSON:   " + os.path.abspath(json_path))
    print("\nResumen de módulos:")
    for nombre, resultado in informe["modulos"].items():
        print("  - " + nombre + ": " + ("OK" if resultado else "sin resultados"))
    if clasificacion(informe):
        print("\nHallazgos automáticos:")
        for nivel, titulo, detalle in clasificacion(informe):
            print("  [" + nivel + "] " + titulo + ": " + detalle)
    if input("\n¿Abrir informe HTML ahora? [s/N]: ").strip().lower() == "s":
        import webbrowser
        webbrowser.open("file://" + os.path.abspath(html_path))

if __name__ == "__main__":
    main()
