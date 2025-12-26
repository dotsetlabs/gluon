# @dotsetlabs/gluon

**Security Module for the dotset Platform.**  
Runtime telemetry that detects secret leaks and tracks network activity.

[![npm version](https://img.shields.io/npm/v/@dotsetlabs/gluon)](https://www.npmjs.com/package/@dotsetlabs/gluon)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Installation

### CLI Usage

Install the unified CLI to use Gluon via command line:

```bash
npm install -g @dotsetlabs/cli
```

### SDK Usage

Install the SDK package for programmatic access:

```bash
npm install @dotsetlabs/gluon
```

## Quick Start

### With CLI

```bash
dotset init --gluon
dotset run -- npm start           # Monitor for leaks
dotset scan                       # Static analysis
dotset sbom --static              # Generate SBOM
```

### With SDK

```typescript
import { SecretsMonitor, TelemetryCollector } from '@dotsetlabs/gluon';
import { loadConfig } from '@dotsetlabs/gluon/config';

const config = await loadConfig();
const monitor = new SecretsMonitor(config);

// Scan output for secrets
const matches = monitor.scan(outputBuffer, 'stdout');
```

## Features

- **Secret Leak Detection** — Monitor stdout/stderr for exposed secrets
- **Network Monitoring** — Track all outbound HTTP/HTTPS connections
- **Module Tracking** — Monitor runtime dependencies
- **SBOM Generation** — CycloneDX and SPDX format support
- **Three Protection Modes** — Detect, redact, or block secret exposure

## Protection Modes

| Mode | Behavior |
|:-----|:---------|
| `detect` | Log exposure but allow output (default) |
| `redact` | Replace secrets with `[REDACTED]` |
| `block` | Suppress output containing secrets entirely |

```bash
dotset run --mode redact -- npm start
```

## SDK Exports

```typescript
// Monitors
import { SecretsMonitor, NetworkMonitor, ModuleMonitor } from '@dotsetlabs/gluon/monitors';

// Telemetry
import { TelemetryCollector } from '@dotsetlabs/gluon/telemetry';

// Hooks
import { HookManager } from '@dotsetlabs/gluon/hooks';

// Config
import { loadConfig, GluonConfig } from '@dotsetlabs/gluon/config';
```

## Documentation

Full documentation: [docs.dotsetlabs.com/gluon](https://docs.dotsetlabs.com/gluon/quickstart)

## Part of the dotset Platform

Gluon is the Security module of the dotset developer platform:
- **Axion** — Zero-disk encrypted secrets
- **Gluon** — Runtime security telemetry *(this package)*
- **Hadron** — Local CI runner
- **Tachyon** — Zero-trust dev tunnels

## License

MIT
