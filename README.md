# @dotsetlabs/gluon

**Runtime Security Telemetry for Modern Applications.**  
Detect secret leaks, track network activity, and monitor runtime behavior without changing your code.

[![npm version](https://img.shields.io/npm/v/@dotsetlabs/gluon)](https://www.npmjs.com/package/@dotsetlabs/gluon)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

> **Axion protects your secrets at rest. Gluon watches them in motion.**

---

## Why Gluon?

Existing security tools focus on:
- **Static analysis** — Scan code for hardcoded secrets (GitGuardian, TruffleHog)
- **Secret storage** — Manage secrets at rest (Vault, Doppler, Axion)
- **APM** — General application monitoring (Datadog, New Relic)

**The gap:** No tool monitors what happens _after_ secrets are loaded into your application.

**Gluon fills this gap.** It watches your application at runtime and detects:
- 🔐 Secrets leaking into logs or stdout
- 🌐 Unusual network connections
- 📦 Runtime dependencies (actual imports, not just package.json)

## Killer Features

### 1. Zero-Config Secret Leak Detection

```bash
# Just wrap your command — no code changes required
gln run -- npm start

# Detects:
# ✓ API keys in logs
# ✓ Tokens in error stack traces  
# ✓ Credentials in stdout/stderr
```

### 2. "Secrets in Motion" Alerts

When integrated with Axion:
```
⚠️ ALERT: Secret 'STRIPE_SECRET_KEY' from Axion project 'payments-api'
   was detected in stdout at 2025-01-15 14:32:01 UTC
   
   Context: ...Processing payment with sk_live_****...
```

### 3. Runtime SBOM (Enterprise)

Generate a Software Bill of Materials from **actual runtime imports**:

```bash
gln sbom --format cyclonedx > sbom.json
```

Compliance teams need this. Static SBOMs miss dynamic imports.

## Quick Start

### 1. Install

```bash
npm install -g @dotsetlabs/gluon
```

Or use directly with npx:
```bash
npx @dotsetlabs/gluon run -- npm start
```

### 2. Initialize (optional)

```bash
gln init
```

Creates `.gluon/config.yaml` with sensible defaults.

### 3. Run with monitoring

```bash
gln run -- npm start
gln run -- node dist/index.js
gln run -- python app.py
```

### 4. View telemetry

```bash
gln status
```

## Commands

| Command | Description |
|:--------|:------------|
| `gln init` | Initialize a Gluon project |
| `gln run -- <cmd>` | Run command with security monitoring |
| `gln status` | View telemetry summary and events |
| `gln status --type <type>` | Filter events by type (e.g., secret_exposure) |
| `gln status --severity <level>` | Filter by severity (info, warning, error, critical) |
| `gln status --since <duration>` | Filter events from duration ago (e.g., 1h, 24h, 7d) |
| `gln config` | View or edit configuration |
| `gln dashboard` | Launch local web dashboard |
| `gln sbom` | Generate runtime SBOM (Business tier) |
| `gln login` | Authenticate with Gluon Cloud |
| `gln link <projectId>` | Link to a cloud project |
| `gln unlink` | Unlink from cloud project |
| `gln push` | Sync local telemetry to cloud |

## Axion Integration

Gluon works seamlessly with [@dotsetlabs/axion](https://github.com/dotsetlabs/axion):

```bash
# Install both
npm install -g @dotsetlabs/axion @dotsetlabs/gluon

# Run with Axion secrets + Gluon monitoring
axn run -- gln run -- npm start
```

| Product | Role |
|:--------|:-----|
| **Axion** | Protects secrets at rest (encryption, storage, sync) |
| **Gluon** | Monitors secrets in motion (runtime exposure detection) |

When Gluon detects an Axion project (`.axion/` directory):
- Automatically tracks all ENV values from Axion
- Provides rich alerts with Axion project context
- Correlates secret leaks with Axion manifests

## Pricing

| Plan | Price | Includes |
|:-----|:------|:---------|
| **Free** | $0 | 3 projects, 14-day retention, 12 secret patterns |
| **Pro** | $10/mo or $96/yr | Unlimited projects, 30-day retention, custom patterns, cloud sync |
| **Business** | $25/mo or $240/yr | 90-day retention, SBOM export, webhooks |

### Feature Comparison

| Feature | Free | Pro | Business |
|:--------|:----:|:---:|:--------:|
| **Secret Detection** | 12 patterns | All + custom | All + custom |
| **Retention** | 14 days | 30 days | 90 days |
| **Projects** | 3 | Unlimited | Unlimited |
| **Cloud Sync** | — | ✓ | ✓ |
| **SBOM Export** | — | — | ✓ |
| **Webhooks** | — | — | ✓ |
| **Support** | Community | Email | Priority email |

## Configuration

### .gluon/config.yaml

```yaml
version: "1"
projectName: my-app
tier: free  # free, pro, business

secrets:
  enabled: true
  customPatterns: []  # Pro+
  trackedEnvVars:
    - DATABASE_URL
    - API_SECRET

network:
  enabled: true
  ignoredDomains:
    - localhost
    - 127.0.0.1
  alertOnNewDomains: true

modules:
  enabled: true
  generateSbom: true

telemetry:
  enabled: true
  storagePath: .gluon/telemetry.log
  bufferSize: 100
  flushIntervalMs: 5000

axion:
  enabled: false
  detected: false
```

## How It Works

```
┌────────────────────────────────────────────────────┐
│              Your Application                       │
├────────────────────────────────────────────────────┤
│  stdout ──────┬───────────────────────────────────▸│
│               │    ┌─────────────────┐             │
│               └───▸│ Secret Scanner  │             │
│                    └────────┬────────┘             │
│  stderr ──────────────────▸ │                      │
│                             ▼                      │
│                    ┌─────────────────┐             │
│                    │   Telemetry     │             │
│                    │   Collector     │             │
│                    └────────┬────────┘             │
│                             │                      │
│                             ▼                      │
│                    .gluon/telemetry.log            │
└────────────────────────────────────────────────────┘
```

1. Gluon spawns your application as a child process
2. stdout/stderr pipe through monitoring hooks
3. Pattern matchers scan for secrets in real-time
4. Events are buffered and stored locally
5. View events with `gln status`

## Secret Detection Patterns

Built-in patterns detect:

| Pattern | Examples |
|:--------|:---------|
| **Stripe** | `sk_live_*`, `sk_test_*` |
| **GitHub** | `ghp_*`, `gho_*`, `github_pat_*` |
| **AWS** | `AKIA*` (Access Key ID) |
| **Google** | `AIza*` (API Key) |
| **JWT** | `eyJ*` tokens |
| **Generic** | Bearer tokens, passwords in config |

### Custom Patterns (Pro+)

```yaml
secrets:
  customPatterns:
    - name: "Internal API Key"
      pattern: "MYAPP-[a-zA-Z0-9]{32}"
      severity: critical
      enabled: true
```

## Environment Variables

| Variable | Description |
|:---------|:------------|
| `GLUON_API_URL` | Custom API URL (for self-hosted) |
| `GLUON_SESSION_ID` | Injected into child processes |

## Competitive Positioning

| Product | Focus | Gluon Advantage |
|:--------|:------|:----------------|
| **GitGuardian** | Static code scanning | Gluon catches runtime leaks |
| **Snyk** | Dependency vulnerabilities | Gluon shows actual runtime deps |
| **Datadog APM** | Performance monitoring | Gluon is security-focused, zero-config |
| **Vault/Axion** | Secret storage | Gluon monitors after retrieval |

## The Name: Gluon

In particle physics, **gluons** are exchange particles that mediate the strong force—they literally _bind_ quarks together.

| Physics | Product |
|:--------|:--------|
| Gluons bind quarks | Gluon binds security to your app |
| Never observed alone | Monitors without modifying code |
| Force gets stronger at distance | Value increases as your app scales |

Part of the **dotset labs** particle physics product family:
- **Axion** — Protects secrets at rest
- **Gluon** — Watches secrets in motion

## Roadmap

- [x] Secret detection in stdout/stderr
- [x] Axion integration detection
- [x] Tier-based feature gating
- [x] Network connection monitoring
- [x] Module/dependency tracking
- [x] Local web dashboard
- [x] Gluon Cloud for teams
- [ ] Multi-language support (Python, Go)

## License

MIT — See [LICENSE](LICENSE)

## Related Projects

- [@dotsetlabs/axion](https://github.com/dotsetlabs/axion) — Zero-Disk Secret Plane
- [dotset labs](https://dotsetlabs.com) — Developer tools for security, performance, and DX
