#!/usr/bin/env python3
"""
security_gate.py — Security Gate (Breaking Build)
===================================================
Lee el reporte unificado de seguridad (results/latest.json) y decide
si el pipeline de despliegue debe continuar o romperse.

Este script es ejecutado por Pipeline B en el stage "security-gate".

Uso:
    # Modo strict: rompe en critical + high
    python security_gate.py --input results/latest.json --policy strict

    # Modo moderate: rompe solo en critical
    python security_gate.py --input results/latest.json --policy moderate

    # Modo permissive: solo logea, nunca rompe
    python security_gate.py --input results/latest.json --policy permissive

    # Custom: definir exactamente qué severidades rompen
    python security_gate.py --input results/latest.json --fail-on critical,high

    # Validar que el scan sea reciente (máximo 48 horas)
    python security_gate.py --input results/latest.json --max-age-hours 48

Exit codes:
    0 = PASS (deploy puede continuar)
    1 = BREAK (deploy debe detenerse)
"""

import argparse
import json
import sys
import os
from datetime import datetime, timedelta, timezone


# ============================================================
# POLÍTICAS PREDEFINIDAS
# ============================================================
# Cada política define:
#   - fail_on: severidades que ROMPEN el build
#   - warn_on: severidades que muestran WARNING pero no rompen
#   - require_recent_scan: si el scan debe ser reciente
#   - required_scans: qué scanners deben haberse ejecutado
# ============================================================

POLICIES = {
    "strict": {
        "description": "Rompe en Critical y High. Requiere scan reciente.",
        "fail_on": ["critical", "high"],
        "warn_on": ["medium"],
        "max_age_hours": 24,
        "required_scans": ["headers", "zap", "tls"],
    },
    "moderate": {
        "description": "Rompe solo en Critical. Warning en High.",
        "fail_on": ["critical", "high"],
        "warn_on": ["medium"],
        "max_age_hours": 72,
        "required_scans": ["headers"],  # Al menos headers
    },
    "permissive": {
        "description": "Solo logea, nunca rompe el build.",
        "fail_on": [],
        "warn_on": ["critical", "high", "medium"],
        "max_age_hours": 168,  # 7 días
        "required_scans": [],
    },
}


def load_report(filepath):
    """
    Carga el reporte unificado de seguridad.

    Si el archivo no existe, retorna None (el gate decidirá qué hacer
    según la política: strict rompe, permissive continúa).
    """
    if not os.path.exists(filepath):
        return None

    with open(filepath) as f:
        return json.load(f)


def check_scan_age(report, max_age_hours):
    """
    Verifica que el scan no sea demasiado antiguo.

    Retorna:
        (is_valid, age_message)
        - is_valid: True si el scan es suficientemente reciente
        - age_message: mensaje descriptivo sobre la antigüedad
    """
    timestamp_str = report.get("timestamp", "")
    if not timestamp_str:
        return False, "No se encontró timestamp en el reporte"

    try:
        scan_time = datetime.fromisoformat(timestamp_str)
        # Asegurar que tenga timezone
        if scan_time.tzinfo is None:
            scan_time = scan_time.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        age = now - scan_time
        age_hours = age.total_seconds() / 3600

        if age_hours > max_age_hours:
            return False, (
                f"Scan tiene {age_hours:.1f} horas de antigüedad "
                f"(máximo permitido: {max_age_hours}h)"
            )
        return True, f"Scan tiene {age_hours:.1f} horas (dentro del límite de {max_age_hours}h)"

    except (ValueError, TypeError) as e:
        return False, f"Error parseando timestamp: {e}"


def check_required_scans(report, required_scans):
    """
    Verifica que todos los scanners requeridos se hayan ejecutado.

    Retorna:
        (is_valid, missing_scans)
    """
    completed = set(report.get("scans_completed", []))
    required = set(required_scans)
    missing = required - completed

    if missing:
        return False, list(missing)
    return True, []


def evaluate_findings(report, fail_on, warn_on):
    """
    Evalúa los findings contra las severidades configuradas.

    Retorna:
        (blockers, warnings)
        - blockers: findings que deben ROMPER el build
        - warnings: findings que solo generan WARNING
    """
    findings = report.get("findings", [])
    blockers = []
    warnings = []

    for finding in findings:
        severity = finding.get("severity", "info").lower()
        status = finding.get("status", "open").lower()

        # Los findings "accepted" o "resolved" no bloquean
        if status in ("accepted", "resolved", "false_positive"):
            continue

        if severity in fail_on:
            blockers.append(finding)
        elif severity in warn_on:
            warnings.append(finding)

    return blockers, warnings


def print_separator():
    print(f"{'─'*60}")


def print_header(text):
    print(f"\n{'═'*60}")
    print(f"  {text}")
    print(f"{'═'*60}")


def print_findings_table(findings, icon="🔴"):
    """Imprime una tabla formateada de findings."""
    for f in findings:
        severity = f.get("severity", "?").upper()
        title = f.get("title", "Unknown")
        category = f.get("category", "N/A")
        print(f"  {icon} [{severity:8s}] [{category:7s}] {title}")

        # Mostrar detalle si existe
        detail = f.get("detail", "")
        if detail:
            # Truncar si es muy largo
            if len(detail) > 100:
                detail = detail[:100] + "..."
            print(f"     └─ {detail}")


def main():
    parser = argparse.ArgumentParser(
        description="Security Gate — Decide si romper el build basado en findings de seguridad."
    )
    parser.add_argument(
        "--input",
        default="results/latest.json",
        help="Ruta al reporte unificado de seguridad",
    )
    parser.add_argument(
        "--policy",
        default="moderate",
        choices=["strict", "moderate", "permissive"],
        help="Política predefinida a aplicar (default: moderate)",
    )
    parser.add_argument(
        "--fail-on",
        default=None,
        help="Override: severidades que rompen el build, separadas por coma (ej: critical,high)",
    )
    parser.add_argument(
        "--max-age-hours",
        type=int,
        default=None,
        help="Override: antigüedad máxima del scan en horas",
    )
    args = parser.parse_args()

    # ── Cargar política ──
    policy = POLICIES[args.policy].copy()

    # Aplicar overrides si se especificaron
    if args.fail_on is not None:
        policy["fail_on"] = [s.strip().lower() for s in args.fail_on.split(",") if s.strip()]
    if args.max_age_hours is not None:
        policy["max_age_hours"] = args.max_age_hours

    # ══════════════════════════════════════════
    #  INICIO DEL SECURITY GATE
    # ══════════════════════════════════════════
    print_header("🛡️  SECURITY GATE — Breaking Build Check")

    print(f"\n  📋 Política:     {args.policy}")
    print(f"  📝 Descripción:  {POLICIES[args.policy]['description']}")
    print(f"  🚫 Rompe en:     {', '.join(policy['fail_on']) or 'nada (permissive)'}")
    print(f"  ⚠️  Warning en:   {', '.join(policy.get('warn_on', []))}")
    print(f"  ⏰ Max age:      {policy['max_age_hours']}h")
    print(f"  📄 Input:        {args.input}")

    # ── Paso 1: Cargar reporte ──
    print_separator()
    print("\n  📂 Paso 1: Cargando reporte de seguridad...")

    report = load_report(args.input)
    if report is None:
        print(f"\n  ❌ No se encontró el reporte: {args.input}")
        if args.policy == "strict":
            print("\n  🚨 POLICY STRICT: Sin reporte de seguridad = BUILD ROTO")
            print("     (Ejecuta Pipeline A primero para generar el reporte)\n")
            sys.exit(1)
        else:
            print(f"\n  ⚠️  POLICY {args.policy.upper()}: Continuando sin reporte...")
            print("     (Se recomienda ejecutar Pipeline A)\n")
            sys.exit(0)

    app_name = report.get("app", "unknown")
    print(f"  ✅ Reporte cargado para: {app_name}")

    # ── Paso 2: Verificar antigüedad ──
    print_separator()
    print("\n  ⏰ Paso 2: Verificando antigüedad del scan...")

    age_valid, age_msg = check_scan_age(report, policy["max_age_hours"])
    if age_valid:
        print(f"  ✅ {age_msg}")
    else:
        print(f"  ❌ {age_msg}")
        if args.policy == "strict":
            print("\n  🚨 POLICY STRICT: Scan demasiado antiguo = BUILD ROTO")
            print("     (Re-ejecuta Pipeline A para obtener resultados frescos)\n")
            sys.exit(1)
        else:
            print(f"  ⚠️  Continuando con warning...")

    # ── Paso 3: Verificar cobertura de scans ──
    print_separator()
    print("\n  🔍 Paso 3: Verificando cobertura de scanners...")

    required = policy.get("required_scans", [])
    scans_valid, missing = check_required_scans(report, required)
    completed = report.get("scans_completed", [])
    print(f"  Completados: {', '.join(completed) or 'ninguno'}")
    print(f"  Requeridos:  {', '.join(required) or 'ninguno'}")

    if scans_valid:
        print(f"  ✅ Todos los scans requeridos están presentes")
    else:
        print(f"  ❌ Scans faltantes: {', '.join(missing)}")
        if args.policy == "strict":
            print("\n  🚨 POLICY STRICT: Scans incompletos = BUILD ROTO\n")
            sys.exit(1)
        else:
            print(f"  ⚠️  Continuando con warning...")

    # ── Paso 4: Evaluar findings ──
    print_separator()
    print("\n  📊 Paso 4: Evaluando findings...")

    summary = report.get("summary", {})
    print(f"\n  Resumen del scan:")
    print(f"    Total:    {summary.get('total', 0)}")
    print(f"    Critical: {summary.get('critical', 0)}")
    print(f"    High:     {summary.get('high', 0)}")
    print(f"    Medium:   {summary.get('medium', 0)}")
    print(f"    Low:      {summary.get('low', 0)}")
    print(f"    Info:     {summary.get('info', 0)}")

    blockers, warnings = evaluate_findings(
        report, policy["fail_on"], policy.get("warn_on", [])
    )

    # Mostrar warnings
    if warnings:
        print(f"\n  ⚠️  Warnings ({len(warnings)}):")
        print_findings_table(warnings, icon="⚠️")

    # Mostrar blockers
    if blockers:
        print(f"\n  🚫 Blockers ({len(blockers)}):")
        print_findings_table(blockers, icon="🔴")

    # ══════════════════════════════════════════
    #  DECISIÓN FINAL
    # ══════════════════════════════════════════
    print_header("📋 RESULTADO DEL SECURITY GATE")

    if blockers:
        print(f"\n  ❌ SECURITY GATE: FAILED")
        print(f"  🚨 BUILD ROTO — {len(blockers)} blocking finding(s) encontrado(s)")
        print(f"\n  Severidades que bloquean: {', '.join(policy['fail_on'])}")
        print(f"  Findings bloqueantes:     {len(blockers)}")
        print(f"\n  📌 Para resolver:")
        print(f"     1. Revisa los findings listados arriba")
        print(f"     2. Corrige las vulnerabilidades en tu aplicación")
        print(f"     3. Re-ejecuta Pipeline A para obtener nuevos resultados")
        print(f"     4. Vuelve a intentar el deploy")
        print(f"\n  💡 Alternativas:")
        print(f"     - Usa --policy permissive para modo solo-log")
        print(f"     - Marca findings como 'accepted' en el reporte si el riesgo es aceptado\n")
        sys.exit(1)
    else:
        print(f"\n  ✅ SECURITY GATE: PASSED")
        print(f"  🚀 Deploy puede continuar")
        if warnings:
            print(f"  ⚠️  ({len(warnings)} warnings que NO bloquean)")
        print(f"\n  App:     {app_name}")
        print(f"  Policy:  {args.policy}")
        print(f"  Scans:   {', '.join(completed)}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
