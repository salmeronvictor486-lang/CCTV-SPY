# CCTV-SPY — Auditor de red y cámaras CCTV

Herramienta **defensiva** de línea de comandos para auditar tu propia red de
videovigilancia. Escanea los objetivos que **tú** indicas, detecta cámaras IP,
NVR y DVR, identifica la marca, comprueba servicios (HTTP, RTSP, ONVIF) y, de
forma opcional, verifica si algún dispositivo sigue con las **credenciales de
fábrica** para que puedas corregirlo. Genera un informe HTML.

> ⚠️ **Uso legal.** Úsala **solo** sobre redes y dispositivos **tuyos** o con
> **autorización por escrito** del responsable. Escanear o intentar acceder a
> sistemas de terceros sin permiso es ilegal. En España puede constituir delito
> (Código Penal, arts. 197 bis —acceso ilícito— y 264 —daños informáticos—).
> El autor y esta herramienta no se responsabilizan de un uso indebido.

---

## ¿Qué hace?

- **Escaneo de puertos** típicos de cámaras/NVR/DVR (80, 443, 554, 8000, 37777…).
- **Fingerprint de marca** (Hikvision, Dahua, Axis, Foscam, Reolink, Vivotek…).
- **Sondas de servicio**: RTSP (OPTIONS), ONVIF (GetDeviceInformation), panel web.
- **Chequeo de credenciales de fábrica** (opcional, `--check-default-creds`).
- **Informe** en consola + HTML (con diseño, apto para móvil) y JSON opcional.
- **Sin dependencias**: solo Python 3.8+ y su biblioteca estándar.

---

## Instalación en Kali Linux (paso a paso)

Recomendado ejecutarla en **Kali Linux**, pero funciona en cualquier Linux con
Python 3.

**1. Abrimos una terminal y comprobamos Python 3** (Kali ya lo trae):

```bash
python3 --version
```

Si no estuviera instalado:

```bash
sudo apt update && sudo apt install -y python3 git
```

**2. Clonamos el repositorio:**

```bash
git clone https://github.com/salmeronvictor486-lang/cctv-spy.git
cd cctv-spy
```

**3. Damos permisos de ejecución al script:**

```bash
chmod +x cctv_audit.py
```

**4. Comprobamos que arranca:**

```bash
python3 cctv_audit.py --help
```

No hace falta `pip install` ni entorno virtual: no usa librerías externas.

---

## Uso

**Auditar toda tu red local (ejemplo, una /24):**

```bash
python3 cctv_audit.py -t 192.168.1.0/24
```

**Auditar IPs y rangos sueltos:**

```bash
python3 cctv_audit.py -t 192.168.1.10 192.168.1.20-192.168.1.40
```

**Desde un fichero de objetivos** (uno por línea; admite `#` para comentarios):

```bash
python3 cctv_audit.py --targets-file objetivos.example.txt -o informe.html
```

**Comprobar credenciales de fábrica** (solo en TUS dispositivos):

```bash
python3 cctv_audit.py -t 192.168.1.0/24 --check-default-creds
```

Al arrancar pedirá que confirmes que estás autorizado. Para automatizarlo (p. ej.
en un cron sobre tu propia red) usa `--i-am-authorized`.

**Guardar también en JSON** (para procesarlo después):

```bash
python3 cctv_audit.py -t 192.168.1.0/24 --json resultados.json
```

### Parámetros

| Parámetro | Descripción |
|---|---|
| `-t, --targets` | IPs, rangos `inicio-fin` o CIDR a auditar. |
| `--targets-file` | Fichero con un objetivo por línea. |
| `--check-default-creds` | Prueba credenciales de fábrica (solo autorizado). |
| `--ports` | Puertos extra, separados por coma (ej. `7001,8081`). |
| `-o, --output` | Ruta del informe HTML (por defecto `informe_cctv.html`). |
| `--json` | Guarda también los resultados en JSON. |
| `--workers` | Hilos concurrentes (por defecto 100). |
| `--i-am-authorized` | Confirma la autorización sin preguntar. |

---

## Ejemplo de salida

```
  [CÁMARA] 192.168.1.64
    Marca:   Hikvision
    Puertos: 80, 554, 8000
    Web:     :80 | Login
    RTSP:    :554 | Hikvision
    ONVIF:   sí
    [!] CREDENCIALES DE FÁBRICA: admin / 12345
    -> CRÍTICO: credenciales de fábrica activas (admin / 12345). Cámbialas ya.
    -> RTSP accesible: restríngelo por firewall/VPN si da a Internet.
```

El informe HTML (`informe_cctv.html`) recoge lo mismo en una tabla con
indicadores y recomendaciones.

---

## Recomendaciones de bastionado (si detectas problemas)

1. **Cambia las credenciales de fábrica** por contraseñas largas y únicas.
2. **No expongas las cámaras a Internet.** Usa VPN para acceso remoto.
3. **Segmenta** la videovigilancia en su propia VLAN, sin salida a Internet.
4. **Actualiza el firmware** del fabricante.
5. **Desactiva servicios** que no uses (UPnP, P2P en la nube, Telnet).

---

## Aviso legal

Software entregado «tal cual», sin garantías. Su finalidad es la auditoría de
seguridad de sistemas propios o autorizados. El usuario es el único responsable
del uso que haga de la herramienta y debe cumplir la legislación aplicable.
