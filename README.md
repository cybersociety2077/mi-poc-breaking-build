# 🛡️ POC — Breaking Build con Security Gate Desacoplado

Prueba de concepto (POC) de un sistema de **Breaking Build** basado en el patrón **Decoupled Security Gate**, donde las pruebas de seguridad DAST se ejecutan de forma independiente y los pipelines de despliegue consultan los resultados para decidir si continúan o se rompen.

## 📋 Tabla de Contenido

- [¿Qué es esto?](#-qué-es-esto)
- [¿Cómo funciona?](#-cómo-funciona)
- [Arquitectura](#-arquitectura)
- [Estructura del proyecto](#-estructura-del-proyecto)
- [¿Para qué sirve cada archivo?](#-para-qué-sirve-cada-archivo)
- [Cómo se creó este proyecto](#-cómo-se-creó-este-proyecto)
- [Requisitos previos](#-requisitos-previos)
- [Ejecución paso a paso](#-ejecución-paso-a-paso)
- [Políticas de seguridad](#-políticas-de-seguridad)
- [Formato del reporte unificado](#-formato-del-reporte-unificado)
- [Ejecución local (opcional)](#-ejecución-local-opcional)
- [Preguntas frecuentes](#-preguntas-frecuentes)
- [Cómo lo implementan grandes empresas](#-cómo-lo-implementan-grandes-empresas)
- [Próximos pasos y mejoras](#-próximos-pasos-y-mejoras)

---

## 🤔 ¿Qué es esto?

En DevSecOps, **"Breaking the Build"** significa romper el pipeline de despliegue cuando se detectan vulnerabilidades de seguridad que violan las políticas definidas. Es como un guardia en la puerta: si tu código no cumple con los estándares de seguridad, **no se despliega**.

El problema con el enfoque tradicional (meter los scans de seguridad dentro del pipeline de deploy) es que los scans DAST pueden tardar **15-60 minutos**, lo cual bloquea cada despliegue.

### La solución: Decoupled Security Gate

Separamos la ejecución de los scans de la decisión de bloqueo:

| Componente | Responsabilidad | Tiempo |
|---|---|---|
| **Pipeline A** (Scanner) | Ejecuta los scans de seguridad y almacena resultados | 5-15 min (independiente) |
| **Pipeline B** (Deploy) | Lee los resultados y decide si romper el build | ~2 segundos (solo consulta) |

Esto significa que el pipeline de deploy **nunca espera** a que los scans terminen. Solo consulta los últimos resultados disponibles.

---

## ⚙️ ¿Cómo funciona?

El flujo completo funciona así:

### Pipeline A (se ejecuta de forma independiente)

```
1. Levanta OWASP Juice Shop (app vulnerable de prueba)
2. Ejecuta 3 scanners de seguridad:
   ├── check_headers.py  → Verifica headers HTTP de seguridad
   ├── OWASP ZAP         → Busca vulnerabilidades web (XSS, SQLi, etc.)
   └── testssl.sh        → Verifica configuración TLS/SSL
3. Normaliza los 3 resultados en un único JSON
4. Commitea results/latest.json al repositorio
```

### Pipeline B (se ejecuta en cada deploy)

```
1. Build de la aplicación
2. Tests unitarios
3. 🛡️ Security Gate:
   ├── Lee results/latest.json
   ├── Evalúa findings contra la política (strict/moderate/permissive)
   └── DECIDE:
       ├── ✅ PASS → continúa al deploy
       └── ❌ BREAK → pipeline se rompe, NO despliega
4. Deploy a Staging (solo si pasó el gate)
5. Deploy a Producción (solo si pasó el gate)
```

### ¿Cómo se comunican?

Pipeline A commitea los resultados en `results/latest.json` en el repositorio. Pipeline B simplemente lee ese archivo. No necesitan APIs, bases de datos ni servicios adicionales.

```
Pipeline A ──commitea──→ results/latest.json ──lee──→ Pipeline B
```

---

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────────────┐
│                        REPOSITORIO GITHUB                       │
│                                                                 │
│  ┌──────────────┐    results/latest.json    ┌──────────────┐   │
│  │  PIPELINE A   │ ─────────────────────── → │  PIPELINE B   │   │
│  │  (Scanner)    │    (JSON commiteado)      │  (Deploy)     │   │
│  │               │                           │               │   │
│  │ ┌───────────┐ │                           │ ┌───────────┐ │   │
│  │ │ Juice Shop│ │                           │ │   Build    │ │   │
│  │ │ (Docker)  │ │                           │ ├───────────┤ │   │
│  │ ├───────────┤ │                           │ │   Tests    │ │   │
│  │ │ ZAP Scan  │ │                           │ ├───────────┤ │   │
│  │ ├───────────┤ │                           │ │ 🛡️ Security│ │   │
│  │ │ Headers   │ │                           │ │    Gate    │ │   │
│  │ ├───────────┤ │                           │ ├───────────┤ │   │
│  │ │ TLS Check │ │                           │ │  Deploy    │ │   │
│  │ ├───────────┤ │                           │ │  Staging   │ │   │
│  │ │ Normalize │ │                           │ ├───────────┤ │   │
│  │ └───────────┘ │                           │ │  Deploy    │ │   │
│  │               │                           │ │  Prod      │ │   │
│  └──────────────┘                           └──────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📁 Estructura del proyecto

```
mi-poc-breaking-build/
├── .github/
│   └── workflows/
│       ├── pipeline-a-scanner.yml    ← Pipeline A: ejecuta los scans
│       └── pipeline-b-deploy.yml     ← Pipeline B: deploy con security gate
├── scripts/
│   ├── check_headers.py              ← Scanner de headers HTTP
│   ├── normalize_results.py          ← Unifica resultados de los 3 scanners
│   └── security_gate.py              ← Evalúa resultados y rompe el build
├── results/
│   └── latest.json                   ← Resultados (generado por Pipeline A)
├── .gitignore
└── README.md
```

---

## 📄 ¿Para qué sirve cada archivo?

### Scripts

#### `scripts/check_headers.py` — Scanner de Security Headers

**¿Qué hace?** Hace una petición HTTP a la URL objetivo y verifica si los headers de seguridad están presentes y correctamente configurados.

**¿Qué revisa?**
- **Headers requeridos:** `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `X-XSS-Protection`
- **Headers prohibidos:** `Server` y `X-Powered-By` (exponen información del servidor)

**¿Qué genera?** Un archivo JSON con la lista de findings y sus severidades.

```bash
# Uso
python scripts/check_headers.py --url http://localhost:3000 --output results/headers.json
```

---

#### `scripts/normalize_results.py` — Unificador de resultados

**¿Qué hace?** Toma los JSON de los 3 scanners (que tienen formatos diferentes) y los unifica en un solo archivo con formato estándar.

**¿Por qué es necesario?**
- OWASP ZAP genera su propio formato con "alerts" y "riskcode"
- testssl.sh genera otro formato con "scanResult" y "vulnerabilities"
- check_headers.py ya genera nuestro formato estándar

Este script traduce todo a un formato común que el security gate puede leer.

**¿Qué genera?** El archivo `results/latest.json` con todos los findings normalizados.

```bash
# Uso
python scripts/normalize_results.py \
  --app juice-shop \
  --headers results/headers.json \
  --zap results/zap.json \
  --tls results/tls.json \
  --output results/latest.json
```

---

#### `scripts/security_gate.py` — El Breaking Build

**¿Qué hace?** Es el archivo más importante. Lee `results/latest.json`, evalúa los findings contra la política de seguridad definida y decide si el pipeline de deploy debe continuar o romperse.

**Ejecuta 4 pasos:**
1. **Cargar reporte** — Verifica que exista `results/latest.json`
2. **Verificar antigüedad** — El scan no debe ser demasiado viejo
3. **Verificar cobertura** — Los scanners requeridos deben haberse ejecutado
4. **Evaluar findings** — Clasifica en blockers (rompen) y warnings (informan)

**Exit codes:**
- `exit 0` = ✅ PASS (deploy continúa)
- `exit 1` = ❌ BREAK (pipeline se rompe)

```bash
# Uso con política predefinida
python scripts/security_gate.py --input results/latest.json --policy strict

# Uso con severidades custom
python scripts/security_gate.py --input results/latest.json --fail-on critical,high

# Modo solo-log (nunca rompe)
python scripts/security_gate.py --input results/latest.json --policy permissive
```

---

### Workflows de GitHub Actions

#### `.github/workflows/pipeline-a-scanner.yml` — Pipeline A

**¿Qué hace?** Orquesta la ejecución de los 3 scanners de seguridad.

**¿Cómo funciona paso a paso?**
1. Levanta OWASP Juice Shop como servicio Docker
2. Espera a que esté listo (health check)
3. Ejecuta `check_headers.py` contra Juice Shop
4. Ejecuta OWASP ZAP en modo baseline (scan rápido, no intrusivo)
5. Ejecuta verificación TLS (en la POC genera un finding porque Juice Shop es HTTP)
6. Ejecuta `normalize_results.py` para unificar los 3 resultados
7. Commitea `results/latest.json` al repositorio

**¿Cuándo se ejecuta?**
- Manualmente desde GitHub Actions UI
- Automáticamente cada día a las 2am UTC (cron)

**Detalle importante:** Este pipeline **nunca falla** por findings. Usa `continue-on-error: true` en los scans porque su trabajo es solo recolectar resultados, no bloquear nada.

---

#### `.github/workflows/pipeline-b-deploy.yml` — Pipeline B

**¿Qué hace?** Simula un pipeline de despliegue con un security gate integrado.

**Flujo de jobs:**

```
build → test → security-gate → deploy-staging → deploy-production
                    │
              Si falla (exit 1)
                    │
              ❌ Pipeline ROTO
              (deploy-staging y deploy-production NO se ejecutan)
```

**¿Cuándo se ejecuta?**
- Manualmente (puedes elegir la política desde un dropdown)
- En cada push a `main` (excepto cambios en `results/` para evitar loops)

**Detalle importante:** El `paths-ignore` en el trigger excluye cambios en `results/` y archivos `.md`. Esto evita un loop infinito: Pipeline A commitea → trigger push → Pipeline B se ejecuta → etc.

---

## 🛠️ Cómo se creó este proyecto

### Decisiones de diseño

Este proyecto se diseñó respondiendo estas preguntas clave:

| Pregunta | Decisión | Razón |
|---|---|---|
| ¿GitHub o GitLab? | **GitHub** | Minutos ilimitados de CI/CD en repos públicos |
| ¿Repo público o privado? | **Público** | Minutos ilimitados + transparencia para la POC |
| ¿Cuántos repos? | **1 solo** | Múltiples workflows en un repo simplifican la comunicación |
| ¿App objetivo? | **OWASP Juice Shop** | App vulnerable a propósito, ZAP encuentra cosas reales |
| ¿Dónde guardar resultados? | **JSON en el repo** | Sin infraestructura extra, Pipeline B solo hace checkout |
| ¿Alcance de scans? | **ZAP + headers + TLS** | POC completa con los 3 tipos de check |

### Patrón: Decoupled Security Gate

El patrón elegido se llama **Decoupled Security Gate** y es usado por empresas como Netflix, AWS y Fluid Attacks. La idea central es:

> Separar la **ejecución** de pruebas de seguridad de la **decisión** de bloqueo en los pipelines de despliegue.

**Ventajas sobre el enfoque inline (meter scans dentro del pipeline de deploy):**
- El pipeline de deploy solo tarda ~2 segundos en consultar resultados (vs 15-60 min esperando scans)
- Un Pipeline A puede cubrir N aplicaciones
- Las políticas se definen centralmente
- Se puede empezar en modo permissive y escalar gradualmente

---

## ✅ Requisitos previos

Para ejecutar esta POC solo necesitas:

- Una cuenta de GitHub (gratuita)
- El repositorio ya creado y público

#### NOTA: No necesitas instalar nada localmente. Todo corre en GitHub Actions.

Si quieres ejecutar los scripts localmente (opcional), necesitas:

- Python 3.10+
- Docker (para Juice Shop)

#### Instalar dependencias locales (opcional)

```bash
$ pip install requests
```

---

## 🚀 Ejecución paso a paso

### Paso 1 — Ejecutar Pipeline A (generar resultados de seguridad)

Pipeline A debe ejecutarse **primero** para que existan resultados que Pipeline B pueda consultar.

#### 1.1 Ve a la pestaña Actions de tu repositorio

```
https://github.com/TU-USUARIO/mi-poc-breaking-build/actions
```

#### 1.2 En el panel izquierdo, selecciona "Pipeline A — Security Scanner"

#### 1.3 Click en "Run workflow"

Verás un campo para el nombre de la app. Déjalo como `juice-shop` y dale click a **"Run workflow"**.

#### 1.4 Espera a que termine (~5-10 minutos)

El pipeline va a:
1. Levantar Juice Shop
2. Ejecutar los 3 scans
3. Commitear `results/latest.json` en tu repo

#### 1.5 Verifica que los resultados existan

Después de que Pipeline A termine, deberías ver una carpeta `results/` en tu repo con el archivo `latest.json`.

#### NOTA: Si Pipeline A falla, revisa los logs en GitHub Actions. El problema más común es que Juice Shop tarde mucho en arrancar. Si pasa, re-ejecuta el workflow.

---

### Paso 2 — Ejecutar Pipeline B (probar el Breaking Build)

Ahora que existen resultados, Pipeline B puede evaluarlos.

#### 2.1 En la pestaña Actions, selecciona "Pipeline B — Deploy (Breaking Build)"

#### 2.2 Click en "Run workflow"

Verás un dropdown para elegir la política de seguridad:

| Política | Comportamiento esperado |
|---|---|
| `strict` | ❌ **VA A ROMPER** — Juice Shop tiene muchas vulns critical + high |
| `moderate` | ❌ **VA A ROMPER** — Juice Shop tiene vulns critical |
| `permissive` | ✅ **VA A PASAR** — Solo logea, nunca rompe |

#### 2.3 Prueba con `moderate` primero

Deberías ver que el pipeline se rompe en el job "🛡️ Security Gate" y los jobs de deploy **nunca se ejecutan**.

#### 2.4 Ahora prueba con `permissive`

Deberías ver que el pipeline pasa completo y llega hasta "Deploy Production".

#### NOTA: El objetivo de la POC es que veas ambos escenarios: el build roto y el build exitoso. Eso demuestra que el security gate funciona correctamente.

---

### Paso 3 — Revisar los logs del Security Gate

Cuando Pipeline B se ejecuta, el job "🛡️ Security Gate" muestra un reporte detallado en los logs:

```
═══════════════════════════════════════════
  🛡️  SECURITY GATE — Breaking Build Check
═══════════════════════════════════════════

  📋 Política:     moderate
  🚫 Rompe en:     critical
  ⚠️  Warning en:   high, medium
  ⏰ Max age:      72h

  📊 Paso 4: Evaluando findings...

  Resumen del scan:
    Total:    15
    Critical: 2
    High:     5
    Medium:   6
    Low:      2

  🚫 Blockers (2):
  🔴 [CRITICAL] [dast   ] SQL Injection
  🔴 [CRITICAL] [dast   ] Cross-Site Scripting (Reflected)

═══════════════════════════════════════════
  ❌ SECURITY GATE: FAILED
  🚨 BUILD ROTO — 2 blocking finding(s) encontrado(s)
═══════════════════════════════════════════
```

---

## 📏 Políticas de seguridad

El security gate soporta 3 políticas predefinidas:

### Strict

```
Rompe en:           Critical + High
Warning en:         Medium
Max age del scan:   24 horas
Scans requeridos:   headers, zap, tls (los 3)
```

Ideal para: aplicaciones de alto riesgo (pagos, datos sensibles).

### Moderate

```
Rompe en:           Critical
Warning en:         High + Medium
Max age del scan:   72 horas
Scans requeridos:   headers (mínimo)
```

Ideal para: la mayoría de aplicaciones en producción.

### Permissive

```
Rompe en:           Nada
Warning en:         Critical + High + Medium
Max age del scan:   168 horas (7 días)
Scans requeridos:   Ninguno
```

Ideal para: onboarding, aplicaciones internas, fase de observación.

### Política custom

También puedes definir exactamente qué severidades rompen:

```bash
python scripts/security_gate.py --input results/latest.json --fail-on critical,high,medium
```

---

## 📊 Formato del reporte unificado

El archivo `results/latest.json` tiene este formato estándar (el "contrato" entre Pipeline A y Pipeline B):

```json
{
  "app": "juice-shop",
  "timestamp": "2026-02-07T10:30:00+00:00",
  "pipeline_id": "12345678",
  "summary": {
    "total": 15,
    "critical": 2,
    "high": 5,
    "medium": 6,
    "low": 2,
    "info": 0
  },
  "scans_completed": ["headers", "zap", "tls"],
  "findings": [
    {
      "title": "Missing header: Content-Security-Policy",
      "severity": "high",
      "category": "headers",
      "description": "Controla qué recursos puede cargar la página.",
      "status": "open"
    },
    {
      "title": "Cross-Site Scripting (Reflected)",
      "severity": "high",
      "category": "dast",
      "description": "...",
      "status": "open"
    }
  ]
}
```

**Campos clave:**
- `summary`: conteos por severidad (lo que Pipeline B evalúa rápidamente)
- `scans_completed`: qué scanners se ejecutaron (para validar cobertura)
- `findings[].severity`: `critical`, `high`, `medium`, `low`, `info`
- `findings[].status`: `open` (bloquea), `accepted` (ignorado), `resolved` (cerrado)

---

## 💻 Ejecución local (opcional)

Si quieres probar los scripts en tu máquina antes de ejecutarlos en GitHub Actions:

### Levantar Juice Shop

```bash
$ docker run -d -p 3000:3000 bkimminich/juice-shop
```

#### Espera unos segundos y verifica que esté corriendo

```bash
$ curl http://localhost:3000
```

### Ejecutar el scan de headers

```bash
$ python scripts/check_headers.py --url http://localhost:3000 --output results/headers.json
```

### Ejecutar el normalizador (solo con headers por ahora)

```bash
$ mkdir -p results
$ python scripts/normalize_results.py \
    --app juice-shop \
    --headers results/headers.json \
    --output results/latest.json
```

### Ejecutar el security gate

```bash
# Modo moderate (va a romper si hay critical findings)
$ python scripts/security_gate.py --input results/latest.json --policy moderate

# Modo permissive (solo logea)
$ python scripts/security_gate.py --input results/latest.json --policy permissive
```

#### NOTA: El exit code del security gate es lo que rompe el pipeline. En local puedes verificarlo con:

```bash
$ python scripts/security_gate.py --input results/latest.json --policy strict
$ echo $?
# 1 = falló (build roto)
# 0 = pasó (build exitoso)
```

### Detener Juice Shop

```bash
$ docker stop $(docker ps -q --filter ancestor=bkimminich/juice-shop)
```

---

## ❓ Preguntas frecuentes

### ¿Por qué Pipeline A no rompe el build cuando encuentra vulnerabilidades?

Porque su trabajo es **recolectar datos**, no tomar decisiones. Pipeline A usa `continue-on-error: true` para que los scans siempre se completen y los resultados se guarden. La decisión de romper el build es responsabilidad exclusiva de Pipeline B.

### ¿Qué pasa si Pipeline B se ejecuta antes de Pipeline A?

Si no existe `results/latest.json`:
- En **strict**: rompe el build (sin evidencia de seguridad = no deploy)
- En **moderate/permissive**: continúa con un warning

### ¿Qué pasa si el scan es muy viejo?

Cada política tiene un `max_age_hours`. Si el scan es más viejo que ese límite:
- En **strict**: rompe el build
- En **moderate**: muestra warning pero continúa
- En **permissive**: ignora la antigüedad

### ¿Por qué se commitean los resultados en el repo?

Es la solución más simple para una POC: no necesita bases de datos, APIs ni servicios externos. Pipeline A commitea y Pipeline B lee. En producción, usarías una base de datos, S3, o una herramienta como DefectDojo.

### ¿Cómo evitamos el loop infinito?

Pipeline B tiene `paths-ignore: results/**` en su trigger. Esto significa que cuando Pipeline A commitea en `results/`, ese push **no** triggerea Pipeline B.

### ¿Se puede aceptar un riesgo sin arreglar la vulnerabilidad?

Sí. Si un finding tiene `"status": "accepted"` en el JSON, el security gate lo ignora automáticamente. Esto permite gestionar excepciones de forma controlada.

---

## 🌍 Cómo lo implementan grandes empresas

| Empresa/Herramienta | Patrón | Cómo funciona |
|---|---|---|
| **Netflix / FAANG** | API centralizada | Servicio interno que agrega findings de múltiples scanners. Los pipelines consultan la API. |
| **Fluid Attacks** | CI/CD Agent | Un agente consulta la plataforma ARM y rompe el build si hay vulnerabilidades abiertas. |
| **AWS** | Security Hub | ZAP post-deploy envía findings a Security Hub vía Lambda. CodePipeline usa approval gates. |
| **DefectDojo** | Vulnerability Management | Los scanners importan resultados vía API. Los pipelines consultan findings activos y deduplicados. |
| **GitLab Ultimate** | Security Dashboard nativo | DAST integrado con policies que bloquean merge requests por threshold de severidad. |

**Esta POC implementa una versión simplificada del patrón Netflix/FAANG**: un almacenamiento central de findings (JSON en el repo) que los pipelines de deploy consultan antes de desplegar.

---

## 🔮 Próximos pasos y mejoras

Si quieres evolucionar esta POC a algo más robusto, estos son los pasos recomendados:

### Fase 1 — Observar (lo que hace esta POC)
- [x] Implementar Pipeline A con 3 scanners
- [x] Almacenar resultados en el repo
- [x] Pipeline B consulta y logea findings
- [x] Probar breaking build con diferentes políticas

### Fase 2 — Alertar
- [ ] Agregar notificaciones a Slack/email cuando hay findings critical
- [ ] Implementar dashboard de resultados (GitHub Pages)
- [ ] Ajustar falsos positivos en las reglas de ZAP

### Fase 3 — Bloquear gradual
- [ ] Activar breaking build en `moderate` para apps de alto riesgo
- [ ] Implementar proceso de aceptación de riesgos (exceptions)
- [ ] Agregar templates de Nuclei para checks custom

### Fase 4 — Madurez
- [ ] Migrar storage a DefectDojo o base de datos
- [ ] Métricas: MTTR, % builds rotos, tendencias
- [ ] Agregar IAST y SCA al Pipeline A
- [ ] Breaking build en `strict` para todas las apps en producción

---

## 📝 Licencia

Este proyecto es una POC educativa. Úsalo como base para implementar tu propio sistema de breaking build.

---

## 🛠️ Herramientas utilizadas

| Herramienta | Versión | Uso |
|---|---|---|
| [OWASP ZAP](https://www.zaproxy.org/) | Latest (Docker) | Scanner DAST |
| [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) | Latest (Docker) | App vulnerable de prueba |
| [testssl.sh](https://testssl.sh/) | Latest (Docker) | Scanner TLS/SSL |
| [Python](https://www.python.org/) | 3.12 | Scripts de análisis |
| [GitHub Actions](https://github.com/features/actions) | N/A | CI/CD pipelines |
