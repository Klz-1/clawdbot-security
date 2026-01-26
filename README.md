# Clawdbot Security Manager

Comprehensive security management system for Clawdbot installations. Automated hardening, CVE tracking, compliance reporting, and more.

## Features

### ✅ Phase 1: Core Security Framework (IMPLEMENTED)
- **Security Profiles**: Pre-configured profiles (Basic, Standard, Paranoid)
- **Security Scoring**: Calculate security score (0-100) based on configuration
- **Status Dashboard**: View overall security posture at a glance
- **Profile Management**: Apply and switch between security profiles

### 🚧 Coming Soon

- **Phase 2**: Interactive Setup Wizard
- **Phase 3**: nginx/fail2ban Hardening Templates
- **Phase 4**: Security Event Monitoring & Dashboard
- **Phase 5**: CVE Tracking & Auto-Updates
- **Phase 6**: Compliance Reporting

## Installation

```bash
npm install -g clawdbot-security
```

## Quick Start

```bash
# Check security status
clawdbot-security status

# Calculate security score
clawdbot-security score

# Apply security profile
clawdbot-security profile standard

# Get help
clawdbot-security --help
```

## Requirements

- Node.js >= 18.0.0
- Existing Clawdbot installation (installed via `npm install -g clawdbot`)
- Configuration directory at `~/.clawdbot/`

## Commands

### `status`
Show overall security status with score, profile, and recommendations.

```bash
clawdbot-security status
clawdbot-security status --json
```

### `score`
Calculate detailed security score with breakdown.

```bash
clawdbot-security score
clawdbot-security score --json
```

### `profile <name>`
Apply a security profile to your Clawdbot installation.

```bash
clawdbot-security profile basic
clawdbot-security profile standard
clawdbot-security profile paranoid
clawdbot-security profile <name> --dry-run  # Preview without applying
```

## Security Profiles

### Basic
- Gateway auth: token
- Gateway bind: loopback
- Channel DM policies: pairing
- nginx rate limiting: moderate
- fail2ban: basic (5 attempts, 1-hour ban)
- Auto-updates: security_only

**Best for**: Personal use, beginners

### Standard (Recommended)
- Gateway auth: token
- Gateway bind: loopback
- Channel DM policies: pairing
- nginx rate limiting: strict
- fail2ban: aggressive (2 attempts, 24-hour ban)
- Security headers: enabled
- Auto-updates: all_security
- Security logs: enabled

**Best for**: Most users, production use

### Paranoid
- Gateway auth: OAuth only
- MFA: required
- Channel DM policies: explicit allowlist
- nginx rate limiting: very_strict
- fail2ban: zero tolerance (1 attempt, permanent ban)
- Security headers: enabled
- All commands logged
- Credential rotation: 30 days
- Auto-updates: all_security_updates

**Best for**: Maximum security, enterprise environments

## How It Works

### Standalone Operation
`clawdbot-security` is a standalone CLI tool that works **alongside** your existing Clawdbot installation:

1. Detects Clawdbot installation at `~/.clawdbot/`
2. Reads/writes to Clawdbot's `clawdbot.json` configuration
3. Adds a `security` section if it doesn't exist
4. Does not modify Clawdbot's core files
5. Can be uninstalled without affecting Clawdbot

### Integration
- **Non-invasive**: Works with existing Clawdbot installations
- **Compatible**: Integrates with Clawdbot's configuration format
- **Safe**: Creates backups before making changes
- **Reversible**: Can be removed without side effects

## Development

### Setup
```bash
# Clone repository
git clone https://github.com/clawdbot-security/clawdbot-security.git
cd clawdbot-security

# Install dependencies
npm install

# Build
npm run build

# Link for local testing
npm link

# Test
clawdbot-security status
```

### Project Structure
```
clawdbot-security/
├── src/
│   ├── cli/              # CLI commands
│   ├── core/             # Core types and config
│   ├── scoring/          # Security scoring logic
│   ├── profiles/         # Security profiles
│   ├── audit/            # Security auditing
│   ├── wizard/           # Interactive wizards
│   ├── templates/        # nginx/fail2ban templates
│   ├── hooks/            # Security hooks
│   ├── monitoring/       # Event monitoring
│   ├── cve/              # CVE tracking
│   └── utils/            # Utilities
├── templates/            # Configuration templates
│   ├── nginx/
│   └── fail2ban/
├── dist/                 # Compiled output
└── package.json
```

## Contributing

This project is in active development! Contributions are welcome.

### Current Status
- ✅ Phase 1: Core Security Framework (COMPLETE)
- 🚧 Phase 2-6: In Progress

### How to Contribute
1. Fork the repository
2. Create a feature branch
3. Implement your feature
4. Add tests
5. Submit a pull request

## Roadmap

See [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md) for the full 6-phase implementation plan.

## License

MIT License - see [LICENSE](./LICENSE) file for details.

## Support

- GitHub Issues: https://github.com/clawdbot-security/clawdbot-security/issues
- Documentation: https://github.com/clawdbot-security/clawdbot-security#readme

## Acknowledgments

Built for the Clawdbot community. This is a community tool and is not officially affiliated with Anthropic or the Clawdbot project.
