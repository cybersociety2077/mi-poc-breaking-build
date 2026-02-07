#!/usr/bin/env python3
"""
normalize_results.py — Unificador de resultados de seguridad
=============================================================
Toma los JSON de los 3 scanners (ZAP, headers, testssl) y los combina
en un único archivo con formato estándar.

Pipeline A ejecuta los scanners → cada uno genera su JSON → este script
los unifica → se commitea el resultado en results/latest.json

Uso:
    python normalize_results.py \
        --app mi-aplicacion \
        --headers results/headers.json \
        --zap results/zap.json \
        --tls results/tls.json \
        --output results/latest.json

Formato de salida (el "contrato" con Pipeline B):
{
    "app": "mi-aplicacion",
    "timestamp": "2026-02-07T10:00:00+00:00",
    "pipeline_id": "12345",
    "summary": { "total": 10, "critical": 1, "high": 3, ... },
    "findings": [ { "title": "...", "severity": "high", ... }, ... ],
    "scans_completed": ["headers", "zap", "tls"]
}
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone


# ============================================================
# MAPEO DE SEVERIDADES
# ============================================================
# Cada herramienta usa nombres diferentes para las severidades.
# Este mapeo las normaliza a: critical, high, medium, low, info
# ============================================================

# ZAP usa niveles numéricos de riesgo (0-3)
ZAP_SEVERITY_MAP = {
    "3": "high",       # ZAP "High" → nuestro "high"
    "2": "medium",     # ZAP "Medium" → nuestro "medium"
    "1": "low",        # ZAP "Low" → nuestro "low"
    "0": "info",       # ZAP "Informational" → nuestro "info"
}

# testssl.sh usa sus propios niveles
TESTSSL_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
    "OK": "info",
    "WARN": "medium",
}


def parse_headers_results(filepath):
    """
    Parsea resultados de check_headers.py

    check_headers.py YA genera el formato estándar, así que solo
    extraemos la lista de findings directamente.
    """
    if not os.path.exists(filepath):
        print(f"  ⚠️  Archivo no encontrado: {filepath} (saltando headers)")
        return []

    with open(filepath) as f:
        data = json.load(f)

    findings = data.get("findings", [])
    print(f"  ✅ Headers: {len(findings)} findings cargados")
    return findings


def parse_zap_results(filepath):
    """
    Parsea resultados de OWASP ZAP (formato JSON).

    ZAP genera un JSON con esta estructura:
    {
        "site": [{
            "alerts": [{
                "name": "Cross-Site Scripting",
                "riskcode": "3",        ← esto mapeamos a severity
                "confidence": "2",
                "riskdesc": "High (Medium)",
                "desc": "...",
                "instances": [{ "uri": "...", "method": "GET" }]
            }]
        }]
    }

    Nosotros lo convertimos a nuestro formato estándar de findings.
    """
    if not os.path.exists(filepath):
        print(f"  ⚠️  Archivo no encontrado: {filepath} (saltando ZAP)")
        return []

    with open(filepath) as f:
        data = json.load(f)

    findings = []

    # ZAP puede tener múltiples "sites" escaneados
    sites = data.get("site", [])
    for site in sites:
        alerts = site.get("alerts", [])
        for alert in alerts:
            # Mapear el riskcode de ZAP a nuestra severidad
            risk_code = str(alert.get("riskcode", "0"))
            severity = ZAP_SEVERITY_MAP.get(risk_code, "info")

            # Obtener las URLs afectadas
            instances = alert.get("instances", [])
            urls = [inst.get("uri", "N/A") for inst in instances[:5]]  # Max 5 URLs

            finding = {
                "title": alert.get("name", "Unknown ZAP Alert"),
                "severity": severity,
                "category": "dast",
                "description": alert.get("desc", "")[:500],  # Truncar descripciones largas
                "detail": f"Confidence: {alert.get('confidence', 'N/A')}. "
                          f"Affected URLs: {', '.join(urls)}",
                "solution": alert.get("solution", "")[:300],
                "status": "open",
            }
            findings.append(finding)

    print(f"  ✅ ZAP: {len(findings)} findings cargados")
    return findings


def parse_testssl_results(filepath):
    """
    Parsea resultados de testssl.sh (formato JSON).

    testssl.sh genera un JSON con esta estructura:
    {
        "scanResult": [{
            "serverDefaults": [...],
            "protocols": [...],
            "vulnerabilities": [{
                "id": "BEAST",
                "severity": "LOW",
                "finding": "TLS1: ...",
            }]
        }]
    }

    También puede generar un formato más plano como lista de findings.
    Manejamos ambos formatos.
    """
    if not os.path.exists(filepath):
        print(f"  ⚠️  Archivo no encontrado: {filepath} (saltando TLS)")
        return []

    with open(filepath) as f:
        data = json.load(f)

    findings = []

    # testssl.sh puede generar diferentes formatos según la versión
    # Formato 1: Con scanResult (versiones más nuevas)
    scan_results = data.get("scanResult", [])
    if scan_results:
        for scan in scan_results:
            # Revisar la sección de vulnerabilidades
            vulns = scan.get("vulnerabilities", [])
            for vuln in vulns:
                raw_severity = vuln.get("severity", "INFO").upper()
                severity = TESTSSL_SEVERITY_MAP.get(raw_severity, "info")

                # Solo incluir findings que NO sean OK/info
                if severity == "info" and raw_severity == "OK":
                    continue

                finding = {
                    "title": f"TLS: {vuln.get('id', 'Unknown')}",
                    "severity": severity,
                    "category": "tls",
                    "description": vuln.get("finding", "No description"),
                    "detail": f"CVE: {vuln.get('cve', 'N/A')}. "
                              f"CWE: {vuln.get('cwe', 'N/A')}",
                    "status": "open",
                }
                findings.append(finding)

            # También revisar protocolos inseguros
            protocols = scan.get("protocols", [])
            for proto in protocols:
                if proto.get("severity", "").upper() in ("HIGH", "CRITICAL", "MEDIUM"):
                    severity = TESTSSL_SEVERITY_MAP.get(
                        proto.get("severity", "INFO").upper(), "info"
                    )
                    finding = {
                        "title": f"TLS Protocol: {proto.get('id', 'Unknown')}",
                        "severity": severity,
                        "category": "tls",
                        "description": proto.get("finding", "Insecure protocol detected"),
                        "status": "open",
                    }
                    findings.append(finding)

    # Formato 2: Lista plana de findings (formato legacy o --jsonfile)
    elif isinstance(data, list):
        for item in data:
            raw_severity = item.get("severity", "INFO").upper()
            severity = TESTSSL_SEVERITY_MAP.get(raw_severity, "info")

            if severity == "info":
                continue

            finding = {
                "title": f"TLS: {item.get('id', 'Unknown')}",
                "severity": severity,
                "category": "tls",
                "description": item.get("finding", "No description"),
                "status": "open",
            }
            findings.append(finding)

    print(f"  ✅ TLS: {len(findings)} findings cargados")
    return findings


def build_unified_report(app_name, all_findings, scans_completed):
    """
    Construye el reporte unificado final.

    Este es EL archivo que Pipeline B lee para decidir si romper el build.
    Contiene:
    - Metadata (app, timestamp, pipeline)
    - Resumen con conteos por severidad
    - Lista completa de findings de todos los scanners
    - Qué scans se completaron (para validar cobertura)
    """
    # Contar por severidad
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for finding in all_findings:
        sev = finding.get("severity", "info")
        if sev in severity_counts:
            severity_counts[sev] += 1

    report = {
        "app": app_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pipeline_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "pipeline_url": os.environ.get("GITHUB_SERVER_URL", "")
        + "/"
        + os.environ.get("GITHUB_REPOSITORY", "")
        + "/actions/runs/"
        + os.environ.get("GITHUB_RUN_ID", ""),
        "summary": {
            "total": len(all_findings),
            **severity_counts,
        },
        "scans_completed": scans_completed,
        "findings": all_findings,
    }

    return report


def main():
    parser = argparse.ArgumentParser(
        description="Unifica resultados de múltiples scanners de seguridad."
    )
    parser.add_argument(
        "--app",
        required=True,
        help="Nombre de la aplicación escaneada",
    )
    parser.add_argument(
        "--headers",
        default="results/headers.json",
        help="Ruta al JSON de resultados de headers",
    )
    parser.add_argument(
        "--zap",
        default="results/zap.json",
        help="Ruta al JSON de resultados de ZAP",
    )
    parser.add_argument(
        "--tls",
        default="results/tls.json",
        help="Ruta al JSON de resultados de testssl",
    )
    parser.add_argument(
        "--output",
        default="results/latest.json",
        help="Ruta donde guardar el reporte unificado",
    )
    args = parser.parse_args()

    print(f"🔄 Normalizando resultados para: {args.app}")
    print(f"{'='*50}")

    all_findings = []
    scans_completed = []

    # ── Parsear cada scanner ──
    print("\n📂 Cargando resultados de scanners:")

    # Headers
    header_findings = parse_headers_results(args.headers)
    if header_findings or os.path.exists(args.headers):
        all_findings.extend(header_findings)
        scans_completed.append("headers")

    # ZAP
    zap_findings = parse_zap_results(args.zap)
    if zap_findings or os.path.exists(args.zap):
        all_findings.extend(zap_findings)
        scans_completed.append("zap")

    # TLS
    tls_findings = parse_testssl_results(args.tls)
    if tls_findings or os.path.exists(args.tls):
        all_findings.extend(tls_findings)
        scans_completed.append("tls")

    # ── Construir reporte unificado ──
    report = build_unified_report(args.app, all_findings, scans_completed)

    # ── Guardar ──
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    # ── Resumen ──
    print(f"\n{'='*50}")
    print(f"📊 Reporte unificado generado")
    print(f"{'='*50}")
    print(f"  App:          {args.app}")
    print(f"  Scans:        {', '.join(scans_completed)}")
    print(f"  Total:        {report['summary']['total']} findings")
    print(f"  🔴 Critical:  {report['summary']['critical']}")
    print(f"  🟠 High:      {report['summary']['high']}")
    print(f"  🟡 Medium:    {report['summary']['medium']}")
    print(f"  🔵 Low:       {report['summary']['low']}")
    print(f"  ⚪ Info:      {report['summary']['info']}")
    print(f"  Output:       {args.output}")
    print(f"{'='*50}")

    if not scans_completed:
        print("\n⚠️  ADVERTENCIA: No se encontraron resultados de ningún scanner.")
        print("   Verifica que los archivos de entrada existen.")
        sys.exit(1)


if __name__ == "__main__":
    main()
