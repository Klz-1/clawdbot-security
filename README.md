# Clawdbot Security Manager

> **Community-built** security management tool for any Clawdbot installation - Made simple for everyone.

[![npm version](https://img.shields.io/badge/version-0.5.0-blue.svg)](https://npmjs.org/package/clawdbot-security)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org)

## 🎯 Overview

Clawdbot Security Manager is a **community-developed** security tool that provides comprehensive, automated security hardening for **any Clawdbot installation**. Works with all channels (Telegram, Discord, WhatsApp, Slack, etc.), all skills, and all configurations. From beginners to enterprise deployments, get a **90/100+ security score in 5 minutes** with zero security expertise required.

> **Note**: This is an independent community project, not an official Anthropic tool. It works alongside any Clawdbot installation without modifying the core Clawdbot codebase.

### Key Features

- 🔒 **Automated Hardening** - nginx rate limiting, fail2ban, mDNS detection
- 📊 **Security Scoring** - Real-time 0-100 security score with actionable recommendations
- 🎭 **Security Profiles** - Basic, Standard, Paranoid modes
- 🛡️ **CVE Tracking** - Automated vulnerability scanning (npm, Python, system packages)
- 📋 **Compliance Reports** - HTML/JSON reports for auditing
- 🔄 **Auto-Updates** - Scheduled security patches with backup/rollback
- 🚨 **mDNS Detection** - Protects against service discovery exposure
- 📈 **Real-time Dashboard** - Security monitoring and metrics
- 🎯 **One-Click Setup** - Interactive wizard for complete configuration

## 📦 Installation

### Quick Install

```bash
# From source (recommended)
git clone https://github.com/Klz-1/clawdbot-security
cd clawdbot-security
npm install
npm run build
npm link

# Quick setup with default profile
clawdbot-security setup
```

### Automated Install Script

```bash
# Interactive install
curl -fsSL https://raw.githubusercontent.com/Klz-1/clawdbot-security/main/install.sh | bash

# Non-interactive with specific profile
curl -fsSL https://raw.githubusercontent.com/Klz-1/clawdbot-security/main/install.sh | PROFILE=standard bash
```

### Docker

```bash
# Using docker-compose
docker-compose up -d

# Or build manually
docker build -t clawdbot-security .
docker run -p 18789:18789 clawdbot-security
```

## 🚀 Quick Start

### 5-Minute Security Setup

```bash
# Step 1: Run interactive setup wizard
clawdbot-security setup

# Step 2: Verify security status
clawdbot-security status

# Step 3: Run comprehensive audit
clawdbot-security audit --deep

# Step 4: Open real-time dashboard
clawdbot-security dashboard
```

**Expected Result:** Security score jumps from ~60 to 90+ immediately.

## 📚 Command Reference

### Core Commands

#### `setup` - Security Setup Wizard
```bash
# Interactive setup (recommended)
clawdbot-security setup

# Non-interactive with profile
clawdbot-security setup --profile=standard --non-interactive

# With nginx and fail2ban
clawdbot-security setup --nginx --fail2ban
```

#### `status` - Security Status
```bash
# Show current security status
clawdbot-security status

# JSON output
clawdbot-security status --json
```

#### `audit` - Comprehensive Audit
```bash
# Basic audit (11 checks)
clawdbot-security audit

# Deep audit with CVE scanning (14 checks)
clawdbot-security audit --deep

# JSON output for CI/CD
clawdbot-security audit --json
```

#### `score` - Security Score
```bash
# Calculate security score
clawdbot-security score

# Show detailed breakdown
clawdbot-security score --json
```

### Hardening Commands

#### `harden` - Apply Security Hardening
```bash
# Apply all hardening (requires sudo)
sudo clawdbot-security harden

# Preview changes (dry-run)
clawdbot-security harden --dry-run

# Apply nginx only
sudo clawdbot-security harden --nginx

# Apply fail2ban only
sudo clawdbot-security harden --fail2ban
```

#### `profile` - Switch Security Profile
```bash
# Apply profile
clawdbot-security profile standard

# Preview changes
clawdbot-security profile paranoid --dry-run
```

### Monitoring Commands

#### `dashboard` - Real-time Dashboard
```bash
# One-time display
clawdbot-security dashboard

# Auto-refresh every 5 seconds
clawdbot-security dashboard --refresh 5
```

#### `logs` - View Security Logs
```bash
# View recent logs
clawdbot-security logs

# Filter by time
clawdbot-security logs --since 1h

# Filter by severity
clawdbot-security logs --severity high

# Filter by type
clawdbot-security logs --type security:rate-limit

# Limit results
clawdbot-security logs --limit 10
```

### Updates & CVE

#### `cve` - CVE Status
```bash
# Check CVE status
clawdbot-security cve

# JSON output
clawdbot-security cve --json
```

#### `update` - Security Updates
```bash
# Check for updates
clawdbot-security update --check

# Apply updates (requires sudo)
sudo clawdbot-security update --apply

# Dry-run
clawdbot-security update --dry-run

# Enable auto-updates
clawdbot-security update --enable-auto
```

### Reporting

#### `report` - Generate Reports
```bash
# Text report
clawdbot-security report

# HTML report
clawdbot-security report --format=html --output=report.html

# JSON report
clawdbot-security report --format=json --output=report.json

# Compliance checklist
clawdbot-security report --compliance
```

## 🎭 Security Profiles

### Basic Profile
**Best for:** Personal use, learning, development

- **nginx**: 20r/s rate limiting, basic security headers
- **fail2ban**: 5 max retries, 1-hour bans (consumer-friendly)
- **Updates**: Security-only auto-updates
- **Trade-off**: Maximum usability, good security

### Standard Profile (Recommended)
**Best for:** Most users, small teams, production

- **nginx**: 10r/s rate limiting, comprehensive headers, path traversal protection
- **fail2ban**: 2 max retries, 24-hour bans (balanced)
- **Updates**: All security updates auto-applied
- **Trade-off**: Excellent balance of security and usability

### Paranoid Profile
**Best for:** High-security environments, enterprise, compliance

- **nginx**: 5r/s rate limiting, maximum headers, CSP, aggressive blocking
- **fail2ban**: 1 max retry, permanent bans (zero tolerance)
- **Updates**: All updates auto-applied with verification
- **Trade-off**: Maximum security, some usability restrictions

## 🛡️ Security Checks

### Comprehensive Audit (17 Checks - Works with ANY Clawdbot Setup)

**Infrastructure Security (4 checks):**
1. **File Permissions** - Config, state, .env, secrets/, credentials/, all token files
2. **Gateway Authentication** - Auth mode and bind address validation
3. **Network Exposure** - Public port scanning and exposure detection
4. **mDNS/Avahi Detection** ⚠️ - Service discovery exposure (CVE-2025-MDNS)

**Channel Security (1 check - DYNAMIC):**
5. **Channel Policies** - **Automatically detects ALL channels** (Telegram, Discord, WhatsApp, Slack, etc.) and validates DM/group policies

**Secrets & Credentials (2 checks):**
6. **Secrets Management** - Detects hardcoded secrets in config (should be in .env)
7. **Token Storage** - Validates token file locations and permissions

**Skills & Tools Security (2 checks):**
8. **Skills Security** - Checks for untrusted npm package skills
9. **Tools Security** - Validates tool capabilities (shell access, filesystem access)

**Hooks & Extensions (1 check):**
10. **Hooks Security** - Static code analysis for dangerous patterns (eval, exec, child_process)

**Model Security (1 check):**
11. **Model Configuration** - Validates model provider trust

**Workspace (1 check):**
12. **Workspace Isolation** - Checks workspace permissions and isolation

**Hardening (3 checks):**
13. **nginx Configuration** - Installation, status, hardening verification
14. **fail2ban Status** - Service and jail configuration
15. **Security Profile** - Profile configuration validation

**Vulnerabilities (2 checks - deep mode):**
16. **CVE Status** - npm, Python, system package vulnerabilities
17. **Dependency Security** - Supply chain security (package-lock.json verification)

### 🌐 Universal Channel Support

Unlike tools hard-coded for specific channels, this security manager **automatically detects and validates ALL channels** configured in your Clawdbot installation:

- ✅ **Telegram** - DM policies, group policies
- ✅ **Discord** - DM policies, server policies
- ✅ **WhatsApp** - DM policies, group policies
- ✅ **Slack** - DM policies, workspace policies
- ✅ **Any future channel** - Dynamically detected from config

No manual configuration needed - it reads your `channels` configuration and validates security for whatever you have installed.

### mDNS/Avahi Detection

Based on real-world security audit findings, the system detects and prevents service discovery exposure:

- ✅ Checks if Avahi daemon is running
- ✅ Checks if Avahi is enabled (will start on boot)
- ✅ Scans for active mDNS broadcasts
- ✅ Detects `_clawdbot-gw._tcp` service exposure
- ✅ Provides clear remediation steps

**Risk:** Avahi broadcasts hostname, service type, and port information on LAN, enabling reconnaissance.

## 📊 Security Scoring

### Scoring Algorithm

- **100 points** - Perfect score (rare)
- **90-99** - EXCELLENT (production-ready)
- **75-89** - GOOD (minor improvements needed)
- **60-74** - FAIR (hardening recommended)
- **<60** - POOR (immediate action required)

### Score Components

| Component | Points | Description |
|-----------|--------|-------------|
| Gateway Auth | 20 | Authentication mode |
| Gateway Bind | 10 | Binding configuration |
| Telegram DM | 15 | DM policy |
| Discord DM | 15 | DM policy |
| Security Profile | 10 | Profile configuration |
| File Permissions | 10 | Config/state security |
| nginx Hardening | 10 | Rate limiting & headers |
| fail2ban | 10 | Attack protection |

## 🔄 Automated Updates

### Enable Auto-Updates

```bash
# Enable with default schedule (2-5 AM)
clawdbot-security update --enable-auto

# Custom update window
clawdbot-security update --enable-auto --window=2-5
```

### Update Flow

1. **Check** (every 6 hours) - Scan for npm, Python, system CVEs
2. **Notify** - Terminal/Telegram/email alerts
3. **Backup** - Automatic configuration snapshots
4. **Apply** (during update window) - Install security patches
5. **Validate** - Test services operational
6. **Rollback** (if failure) - Restore from backup

## 🐳 Docker Deployment

### Pre-Hardened Container

```bash
# Clone and build
git clone https://github.com/Klz-1/clawdbot-security
cd clawdbot-security
docker-compose up -d

# Access dashboard
open http://localhost:18789
```

### Container Features

- ✅ Pre-configured with standard security profile
- ✅ nginx and fail2ban pre-installed
- ✅ Automatic health checks
- ✅ Persistent volumes for config/logs/backups
- ✅ Resource limits (2 CPU, 2GB RAM)

## 📋 Compliance Reporting

### Generate Reports

```bash
# HTML report for management
clawdbot-security report --format=html --output=compliance.html

# JSON report for automation
clawdbot-security report --format=json --output=compliance.json

# Compliance checklist
clawdbot-security report --compliance
```

### Report Contents

- **Security Score** - Overall rating and score
- **Component Status** - PASS/FAIL/WARNING for each component
- **Issue Details** - Specific problems and remediation steps
- **Recommendations** - Prioritized action items
- **Metadata** - Hostname, platform, Node.js version

## 🔧 Configuration

### Configuration Files

```
~/.clawdbot/
├── clawdbot.json          # Main Clawdbot config (if exists)
├── security.json          # Standalone security config (fallback)
├── nginx/
│   └── clawdbot-security.conf    # Generated nginx config
├── fail2ban/
│   ├── clawdbot.local             # fail2ban jails
│   └── filters/
│       └── clawdbot-nginx.conf    # fail2ban filters
├── logs/
│   └── security-audit.jsonl       # JSONL event log
└── backups/
    └── nginx-20260126-123456/     # Timestamped backups
```

### Security Configuration Schema

```json
{
  "security": {
    "profile": "standard",
    "profiles": {
      "standard": {
        "level": "standard",
        "nginx": {
          "rateLimiting": "strict",
          "fail2ban": "aggressive",
          "securityHeaders": true
        },
        "updates": {
          "autoCheck": true,
          "autoApply": "all_security",
          "applyWindow": {
            "startHour": 2,
            "endHour": 5
          }
        }
      }
    }
  }
}
```

## 🧪 Testing

### Run Tests

```bash
# Build project
npm run build

# Test all commands
node dist/cli.js audit --deep
node dist/cli.js report --format=html --output=/tmp/report.html

# Test installation script
./install.sh --help
```

### CI/CD Integration

```yaml
# .github/workflows/security.yml
name: Security Audit
on: [push]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
      - run: npm install -g clawdbot-security
      - run: clawdbot-security audit --json > audit.json
      - run: clawdbot-security report --format=html --output=report.html
      - uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: report.html
```

## 📖 Documentation

- [Phase 1 Report](PHASE1-IMPLEMENTATION.md) - Core Framework
- [Phase 2 Testing](PHASE2-TESTING.md) - Setup Wizard
- [Phase 3 Testing](PHASE3-TESTING.md) - Hardening System
- [Phase 4 & 5 Testing](PHASE4-5-TESTING.md) - Monitoring & CVE
- [Audit Enhancement](AUDIT-ENHANCEMENT-TESTING.md) - mDNS Detection
- [Status Overview](STATUS.md) - Project Status

## 🤝 Contributing

Contributions are welcome! Please see CONTRIBUTING.md for details.

### Development Setup

```bash
# Clone repository
git clone https://github.com/Klz-1/clawdbot-security
cd clawdbot-security

# Install dependencies
npm install

# Build
npm run build

# Link for local testing
npm link

# Run tests
npm test
```

## 📄 License

MIT License - see LICENSE for details.

## 🙏 Acknowledgments

- Built for the [Clawdbot](https://github.com/Klz-1/clawdbot) community
- Inspired by production security best practices
- Special thanks to all contributors and security researchers

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/Klz-1/clawdbot-security/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Klz-1/clawdbot-security/discussions)
- **Documentation**: See docs/ directory

## 🚀 Roadmap

- [x] Phase 1: Core Security Framework
- [x] Phase 2: Setup Wizard
- [x] Phase 3: Templates & Hardening
- [x] Phase 4: Monitoring & Events
- [x] Phase 5: Automated Updates & CVE Tracking
- [x] Phase 6: Distribution & Documentation
- [ ] Phase 7: Web UI Dashboard (planned)
- [ ] Phase 8: ML-based Anomaly Detection (planned)
- [ ] Phase 9: Multi-tenant Support (planned)

## ⭐ Show Your Support

If Clawdbot Security Manager helps secure your installation, please:
- ⭐ Star the repository
- 🐛 Report bugs and request features
- 📣 Share with the community
- 🤝 Contribute improvements

---

Made with 🔒 by the Clawdbot Security Team | Version 0.5.0
