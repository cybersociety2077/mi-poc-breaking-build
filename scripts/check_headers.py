#!/usr/bin/env python3
"""
check_headers.py — Security Headers Scanner
=============================================
Verifica la presencia y correcta configuración de headers de seguridad HTTP.

Uso:
    python check_headers.py --url https://ejemplo.com --output results/headers.json

¿Qué revisa?
    - Headers de seguridad requeridos (HSTS, CSP, X-Frame-Options, etc.)
    - Headers peligrosos que exponen información (Server, X-Powered-By)
    - Configuración correcta de los valores de cada header
"""

import argparse
import json
import sys
from datetime import datetime, timezone

# Intentar importar requests, si no está disponible, dar instrucciones
try:
    import requests
except ImportError:
    print("❌ Módulo 'requests' no encontrado.")
    print("   Instala con: pip install requests")
    sys.exit(1)


# ============================================================
# CONFIGURACIÓN DE REGLAS
# ============================================================
# Estos son los headers que DEBERÍAN estar presentes.
# Cada uno tiene:
#   - severity: qué tan grave es que falte (critical, high, medium, low)
#   - description: para qué sirve
#   - recommended: valor recomendado
# ============================================================

REQUIRED_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "description": "Fuerza el uso de HTTPS. Previene ataques de downgrade a HTTP.",
        "recommended": "max-age=31536000; includeSubDomains",
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "description": "Previene que el navegador interprete archivos con un MIME type diferente.",
        "recommended": "nosniff",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "Previene ataques de clickjacking al no permitir que la página se cargue en un iframe.",
        "recommended": "DENY o SAMEORIGIN",
    },
    "Content-Security-Policy": {
        "severity": "high",
        "description": "Controla qué recursos puede cargar la página. Mitiga XSS e inyecciones.",
        "recommended": "default-src 'self'",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Controla cuánta información del referrer se envía en las peticiones.",
        "recommended": "strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Controla qué APIs del navegador puede usar la página (cámara, micrófono, etc.).",
        "recommended": "geolocation=(), camera=(), microphone=()",
    },
    "X-XSS-Protection": {
        "severity": "low",
        "description": "Activa el filtro XSS del navegador (legacy, pero aún útil).",
        "recommended": "1; mode=block",
    },
}

# Headers que NO deberían estar presentes porque exponen información del servidor.
FORBIDDEN_HEADERS = {
    "Server": {
        "severity": "low",
        "description": "Expone el tipo y versión del servidor web.",
    },
    "X-Powered-By": {
        "severity": "low",
        "description": "Expone la tecnología backend (Express, PHP, ASP.NET, etc.).",
    },
}


def scan_headers(url):
    """
    Hace una petición GET a la URL y analiza los headers de la respuesta.

    Retorna una lista de 'findings' (hallazgos), donde cada finding es:
    {
        "title": "Missing header: X-Frame-Options",
        "severity": "medium",
        "category": "headers",
        "description": "...",
        "status": "open"
    }
    """
    findings = []

    # ── Paso 1: Hacer la petición HTTP ──
    print(f"🔍 Escaneando headers de: {url}")
    try:
        response = requests.get(url, timeout=30, verify=True, allow_redirects=True)
    except requests.exceptions.SSLError:
        # Si falla SSL, intentar sin verificación pero reportar el problema
        print("⚠️  Error de SSL, reintentando sin verificación...")
        response = requests.get(url, timeout=30, verify=False, allow_redirects=True)
        findings.append({
            "title": "SSL Certificate Validation Failed",
            "severity": "high",
            "category": "tls",
            "description": "El certificado SSL no pudo ser validado correctamente.",
            "status": "open",
        })
    except requests.exceptions.RequestException as e:
        print(f"❌ Error conectando a {url}: {e}")
        sys.exit(1)

    # Convertir todos los headers a un dict (case-insensitive por defecto en requests)
    headers = response.headers
    print(f"📡 Status: {response.status_code}")
    print(f"📋 Headers recibidos: {len(headers)}\n")

    # ── Paso 2: Verificar headers requeridos ──
    print("── Headers de seguridad requeridos ──")
    for header_name, rules in REQUIRED_HEADERS.items():
        value = headers.get(header_name)

        if value is None:
            # Header faltante → es un finding
            status_icon = "❌"
            findings.append({
                "title": f"Missing header: {header_name}",
                "severity": rules["severity"],
                "category": "headers",
                "description": rules["description"],
                "detail": f"Recomendado: {rules['recommended']}",
                "status": "open",
            })
        else:
            status_icon = "✅"

        print(f"  {status_icon} {header_name}: {value or 'NO PRESENTE'}")

    # ── Paso 3: Verificar headers prohibidos ──
    print("\n── Headers que exponen información ──")
    for header_name, rules in FORBIDDEN_HEADERS.items():
        value = headers.get(header_name)

        if value is not None:
            # Header presente que no debería estar → es un finding
            status_icon = "⚠️"
            findings.append({
                "title": f"Information disclosure: {header_name}",
                "severity": rules["severity"],
                "category": "headers",
                "description": f"{rules['description']} Valor expuesto: {value}",
                "status": "open",
            })
        else:
            status_icon = "✅"

        print(f"  {status_icon} {header_name}: {value or 'no expuesto (bien)'}")

    return findings, dict(headers)


def build_report(url, findings, raw_headers):
    """
    Construye el JSON final con el formato estándar que espera el security gate.

    Este formato es el "contrato" entre Pipeline A y Pipeline B.
    Todos los scanners (headers, ZAP, testssl) deben generar este mismo formato.
    """
    report = {
        "scanner": "check_headers",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": url,
        "summary": {
            "total": len(findings),
            "critical": len([f for f in findings if f["severity"] == "critical"]),
            "high": len([f for f in findings if f["severity"] == "high"]),
            "medium": len([f for f in findings if f["severity"] == "medium"]),
            "low": len([f for f in findings if f["severity"] == "low"]),
        },
        "findings": findings,
        "raw_headers": raw_headers,
    }
    return report


def main():
    parser = argparse.ArgumentParser(
        description="Escanea headers de seguridad HTTP de una URL."
    )
    parser.add_argument(
        "--url",
        required=True,
        help="URL a escanear (ej: https://ejemplo.com)",
    )
    parser.add_argument(
        "--output",
        default="results/headers.json",
        help="Ruta donde guardar el JSON de resultados (default: results/headers.json)",
    )
    args = parser.parse_args()

    # Ejecutar el scan
    findings, raw_headers = scan_headers(args.url)

    # Construir el reporte
    report = build_report(args.url, findings, raw_headers)

    # Guardar el JSON
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    # Resumen final
    print(f"\n{'='*50}")
    print(f"📊 Resumen del scan de headers")
    print(f"{'='*50}")
    print(f"  URL:      {args.url}")
    print(f"  Total:    {report['summary']['total']} findings")
    print(f"  Critical: {report['summary']['critical']}")
    print(f"  High:     {report['summary']['high']}")
    print(f"  Medium:   {report['summary']['medium']}")
    print(f"  Low:      {report['summary']['low']}")
    print(f"  Output:   {args.output}")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
