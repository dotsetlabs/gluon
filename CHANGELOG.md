# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2025-12-21

### Added

#### Core CLI
- `gln init` - Initialize a Gluon project with tier-aware configuration
- `gln run -- <command>` - Run commands with security monitoring
- `gln status` - View telemetry summary and recent events
- `gln config` - View or edit project configuration
- `gln dashboard` - Local development dashboard (placeholder)
- `gln sbom` - Runtime SBOM generation (Business tier)

#### Secret Detection
- 12 built-in patterns for common secrets (Stripe, GitHub, AWS, Google, JWT)
- Real-time stdout/stderr scanning
- Environment variable tracking
- Redacted snippets in alerts for safe logging
- Custom patterns support (Pro+)

#### Tier System

| Tier | Price | Projects | Retention |
|:-----|:------|:---------|:----------|
| Free | $0 | 3 | 14 days |
| Pro | $10/mo | Unlimited | 30 days |
| Business | $25/mo | Unlimited | 90 days |

#### Telemetry
- Event buffering with configurable flush intervals
- Local storage to `.gluon/telemetry.log`
- Session ID correlation across runs
- Event types: secret_exposure, network_connection, module_load, process_lifecycle

#### Monitors (Foundation)
- Secrets monitor with pattern matching
- Network monitor structure (implementation pending)
- Module monitor structure (implementation pending)

### Security
- Zero-knowledge local-first architecture
- No secrets transmitted to cloud without explicit opt-in
- Redacted output to prevent secondary exposure

### Documentation
- Comprehensive README with pricing structure
- Killer features and competitive positioning
