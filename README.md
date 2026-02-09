# 🛡️ POC — Breaking Build con Security Gate Desacoplado

Prueba de concepto (POC) de un sistema de **Breaking Build** basado en el patrón **Decoupled Security Gate**, donde las pruebas de seguridad DAST se ejecutan de forma independiente y los pipelines de despliegue consultan los resultados para decidir si continúan o se rompen.

---

## ⚙️ ¿Cómo funciona?

Separamos la ejecución de los scans de la decisión de bloqueo:

| Componente | Responsabilidad | Tiempo |
|---|---|---|
| **Pipeline A** (Scanner) | Ejecuta los scans de seguridad y almacena resultados | 5-15 min (independiente) |
| **Pipeline B** (Deploy) | Lee los resultados y decide si romper el build | ~2 segundos (solo consulta) |

```
Pipeline A ──commitea──→ results/latest.json ──lee──→ Pipeline B
```

---

## 📁 Estructura del proyecto

```
mi-poc-breaking-build/
├── .github/workflows/
│   ├── pipeline-a-scanner.yml        ← Ejecuta los scans
│   └── pipeline-b-deploy.yml         ← Deploy con security gate
├── scripts/
│   ├── check_headers.py              ← Scanner de headers HTTP
│   ├── normalize_results.py          ← Unifica resultados de los 3 scanners
│   └── security_gate.py              ← Evalúa resultados y rompe el build
├── results/
│   └── latest.json                   ← Resultados (generado por Pipeline A)
└── README.md
```

---

## ✅ Requisitos previos

- Una cuenta de GitHub (gratuita) con el repositorio público
- **Todo corre en GitHub Actions**, no necesitas instalar nada localmente

Para ejecución local (opcional): Python 3.10+ y Docker.

---

## 🚀 Ejecución paso a paso

### Paso 1 — Ejecutar Pipeline A

1. Ve a **Actions** → selecciona **"Pipeline A — Security Scanner"**
2. Click en **"Run workflow"** (deja `juice-shop` como app)
3. Espera ~5-10 minutos a que termine
4. Verifica que exista `results/latest.json` en tu repo

### Paso 2 — Ejecutar Pipeline B

1. Ve a **Actions** → selecciona **"Pipeline B — Deploy (Breaking Build)"**
2. Click en **"Run workflow"** y elige la política:

| Política | Resultado esperado |
|---|---|
| `strict` | ❌ Rompe — Juice Shop tiene vulns critical + high |
| `moderate` | ❌ Rompe — Juice Shop tiene vulns critical |
| `permissive` | ✅ Pasa — Solo logea, nunca rompe |

3. Prueba con `moderate` para ver el build roto
4. Prueba con `permissive` para ver el build exitoso

### Paso 3 — Revisar logs del Security Gate

El job "🛡️ Security Gate" muestra un reporte como este:

```
═══════════════════════════════════════════
  🛡️  SECURITY GATE — Breaking Build Check
═══════════════════════════════════════════
  📋 Política:     moderate
  🚫 Rompe en:     critical

  🚫 Blockers (2):
  🔴 [CRITICAL] [dast] SQL Injection
  🔴 [CRITICAL] [dast] Cross-Site Scripting (Reflected)

  ❌ SECURITY GATE: FAILED
  🚨 BUILD ROTO — 2 blocking finding(s)
═══════════════════════════════════════════
```

---

## 📏 Políticas de seguridad

| Política | Rompe en | Warning en | Max age scan | Ideal para |
|---|---|---|---|---|
| **strict** | Critical + High | Medium | 24h | Apps de alto riesgo |
| **moderate** | Critical | High + Medium | 72h | Mayoría de apps en producción |
| **permissive** | Nada | Todo | 168h (7 días) | Onboarding / observación |

Política custom:
```bash
python scripts/security_gate.py --input results/latest.json --fail-on critical,high,medium
```

---

## 💻 Ejecución local (opcional)

```bash
# Levantar Juice Shop
docker run -d -p 3000:3000 bkimminich/juice-shop

# Scan de headers
python scripts/check_headers.py --url http://localhost:3000 --output results/headers.json

# Normalizar resultados
python scripts/normalize_results.py \
  --app juice-shop \
  --headers results/headers.json \
  --output results/latest.json

# Security gate
python scripts/security_gate.py --input results/latest.json --policy moderate

# Verificar exit code
echo $?   # 1 = build roto, 0 = build exitoso

# Detener Juice Shop
docker stop $(docker ps -q --filter ancestor=bkimminich/juice-shop)
```


## 🛠️ Herramientas utilizadas

| Herramienta | Uso |
|---|---|
| [OWASP ZAP](https://www.zaproxy.org/) | Scanner DAST |
| [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) | App vulnerable de prueba |
| [testssl.sh](https://testssl.sh/) | Scanner TLS/SSL |
| [Python 3.12](https://www.python.org/) | Scripts de análisis |
| [GitHub Actions](https://github.com/features/actions) | CI/CD pipelines |
