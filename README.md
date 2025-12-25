# @dotsetlabs/gluon

**Runtime Security Telemetry.**  
Monitor secrets exposure, track network activity, and generate SBOMs.

[![npm version](https://img.shields.io/npm/v/@dotsetlabs/gluon)](https://www.npmjs.com/package/@dotsetlabs/gluon)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Documentation

Full documentation is available at [docs.dotsetlabs.com](https://docs.dotsetlabs.com/gluon/quickstart).

## Features

- **Secret Protection** — Detect, redact, or block secret exposure in logs.
- **Network Monitoring** — Track outbound HTTP/HTTPS requests.
- **SBOM Generation** — Generate CycloneDX or SPDX Software Bills of Materials.
- **Static Analysis** — Scan your codebase for vulnerabilities and misconfigurations.

## Quick Start

```bash
npm install -g @dotsetlabs/gluon

# Initialize Gluon
gln init

# Analyze codebase
gln analyze

# Run with monitoring
gln run -- npm start
```

## License

MIT
