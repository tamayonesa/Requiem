# REQUIEM

Herramienta interactiva en Python para reconocimiento de dominios, revisión de configuración web y generación de informes HTML/JSON.

## Características

- Banner ASCII y colores ANSI.
- Menú interactivo.
- Reconocimiento pasivo: WHOIS, Certificate Transparency (`crt.sh`) y Wayback Machine.
- Reconocimiento activo: DNS, puertos TCP seleccionados y resolución de subdominios comunes.
- Auditoría web: cabeceras HTTP de seguridad, cabeceras que revelan tecnología y datos básicos TLS.
- Comprobación de `robots.txt` y `sitemap.xml`.
- Sensor HTTP para registrar cabeceras `User-Agent`.
- Informes HTML con estilo oscuro/cian/magenta y datos JSON para procesarlos después.
- Sin dependencias de terceros: usa la biblioteca estándar de Python.

## Requisitos

- Python 3.9 o posterior recomendado.
- Conexión a Internet para las consultas externas.
- Solo analizar sistemas propios, laboratorios o activos para los que tengas autorización explícita.

## Ejecutar

```bash
python3 requiem.py
```

Selecciona una opción en el menú, introduce el dominio y confirma que tienes autorización. Los informes se guardan en `reports/`.

## Modo por argumentos

```bash
python3 requiem.py --target ejemplo.com --mode full
python3 requiem.py --target ejemplo.com --mode passive
python3 requiem.py --target ejemplo.com --mode web
python3 requiem.py --target ejemplo.com --mode active --ports 22,80,443,8080
```

Si se indica `--target`, el programa no muestra el menú interactivo y ejecuta el modo indicado. La descripción del alcance se solicita durante la ejecución.

## Módulos

| Módulo | Tipo | Qué hace |
|---|---|---|
| WHOIS | Pasivo/terceros | Busca el servidor WHOIS del TLD y consulta los datos públicos del dominio |
| crt.sh | Pasivo/terceros | Busca nombres observados en certificados públicos |
| Wayback | Pasivo/terceros | Consulta si existe una captura archivada |
| DNS | Activo | Resuelve el dominio |
| Puertos TCP | Activo | Prueba conexiones TCP a una lista limitada de puertos |
| Subdominios | Activo | Prueba prefijos de una wordlist |
| HTTP | Activo | Obtiene estado, cabeceras y posibles cabeceras de seguridad ausentes |
| TLS | Activo | Consulta información básica del certificado presentado |
| User-Agent sensor | Local | Registra IP, ruta y User-Agent de peticiones recibidas |

## Limitaciones

- Los resultados son indicios, no una auditoría exhaustiva ni una certificación.
- Una cabecera ausente no equivale automáticamente a una vulnerabilidad explotable.
- El escaneo TCP es básico y puede no detectar servicios filtrados, UDP o puertos fuera de la lista.
- La enumeración de subdominios depende de la wordlist y de la resolución DNS.
- WHOIS, crt.sh y Wayback pueden no estar disponibles o limitar consultas.
- El sensor User-Agent escucha en `127.0.0.1` por defecto para limitar exposición local. No lo publiques en Internet sin controles adicionales.
