#!/bin/bash
# Clawdbot Security Manager - Installation Script
# Version: 0.5.0
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
PROFILE="${PROFILE:-standard}"
NON_INTERACTIVE="${NON_INTERACTIVE:-false}"
SKIP_SETUP="${SKIP_SETUP:-false}"

# Function to print colored output
print_info() {
    echo -e "${CYAN}ℹ ${NC}$1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_header() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo ""
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"

    local all_good=true

    # Check Node.js
    if command_exists node; then
        local node_version=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
        if [ "$node_version" -ge 18 ]; then
            print_success "Node.js $(node --version) found"
        else
            print_error "Node.js version 18+ required (found: $(node --version))"
            all_good=false
        fi
    else
        print_error "Node.js is not installed"
        print_info "Install from: https://nodejs.org/"
        all_good=false
    fi

    # Check npm
    if command_exists npm; then
        print_success "npm $(npm --version) found"
    else
        print_error "npm is not installed"
        all_good=false
    fi

    # Check optional dependencies
    if command_exists nginx; then
        print_success "nginx $(nginx -v 2>&1 | cut -d'/' -f2) found (optional)"
    else
        print_warning "nginx not found (optional - needed for web hardening)"
    fi

    if command_exists fail2ban-client; then
        print_success "fail2ban found (optional)"
    else
        print_warning "fail2ban not found (optional - will be installed if needed)"
    fi

    if [ "$all_good" = false ]; then
        print_error "Prerequisites not met. Please install required dependencies."
        exit 1
    fi

    echo ""
}

# Function to install clawdbot-security
install_package() {
    print_header "Installing Clawdbot Security Manager"

    if [ -f "package.json" ]; then
        # Installing from local directory
        print_info "Installing from local directory..."
        npm install
        npm run build
        npm link
        print_success "Installed from local directory"
    else
        # Installing from npm (future)
        print_info "Installing from npm..."
        npm install -g clawdbot-security
        print_success "Installed from npm"
    fi

    echo ""
}

# Function to run security setup
run_setup() {
    print_header "Security Setup"

    if [ "$SKIP_SETUP" = "true" ]; then
        print_warning "Skipping security setup (SKIP_SETUP=true)"
        return
    fi

    if [ "$NON_INTERACTIVE" = "true" ]; then
        print_info "Running non-interactive setup with profile: $PROFILE"
        clawdbot-security setup --profile="$PROFILE" --non-interactive
    else
        print_info "Starting interactive security setup wizard..."
        clawdbot-security setup
    fi

    print_success "Security setup complete"
    echo ""
}

# Function to install optional components
install_optional() {
    print_header "Optional Components"

    # Check if nginx is available for hardening
    if command_exists nginx; then
        if [ "$NON_INTERACTIVE" = "false" ]; then
            read -p "Apply nginx hardening? [Y/n] " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
                print_info "Applying nginx hardening..."
                sudo clawdbot-security harden --nginx || print_warning "nginx hardening requires sudo"
            fi
        else
            print_info "Applying nginx hardening (non-interactive mode)..."
            sudo clawdbot-security harden --nginx || print_warning "nginx hardening requires sudo"
        fi
    fi

    # Check/install fail2ban
    if ! command_exists fail2ban-client; then
        if [ "$NON_INTERACTIVE" = "false" ]; then
            read -p "Install and configure fail2ban? [Y/n] " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
                print_info "Installing fail2ban..."
                if command_exists apt-get; then
                    sudo apt-get update && sudo apt-get install -y fail2ban
                elif command_exists yum; then
                    sudo yum install -y fail2ban
                else
                    print_warning "Unknown package manager - cannot install fail2ban"
                    return
                fi
                print_info "Configuring fail2ban..."
                sudo clawdbot-security harden --fail2ban
            fi
        fi
    else
        print_info "fail2ban detected - configuring..."
        sudo clawdbot-security harden --fail2ban || print_warning "fail2ban configuration requires sudo"
    fi

    echo ""
}

# Function to run final audit
run_audit() {
    print_header "Security Audit"

    print_info "Running comprehensive security audit..."
    clawdbot-security audit --deep || true

    echo ""
}

# Function to display completion message
show_completion() {
    local score=$(clawdbot-security score --json 2>/dev/null | grep -o '"score":[0-9]*' | cut -d':' -f2 || echo "N/A")

    print_header "Installation Complete"

    echo -e "${GREEN}✓ Clawdbot Security Manager installed successfully!${NC}"
    echo ""
    echo -e "Security Score: ${CYAN}${score}/100${NC}"
    echo ""
    echo "Available Commands:"
    echo "  ${CYAN}clawdbot-security status${NC}        - Check security status"
    echo "  ${CYAN}clawdbot-security audit${NC}         - Run security audit"
    echo "  ${CYAN}clawdbot-security setup${NC}         - Run setup wizard"
    echo "  ${CYAN}clawdbot-security dashboard${NC}     - Open security dashboard"
    echo "  ${CYAN}clawdbot-security update${NC}        - Check for updates"
    echo "  ${CYAN}clawdbot-security --help${NC}        - Show all commands"
    echo ""
    echo "Next Steps:"
    echo "  1. Review security status: ${CYAN}clawdbot-security status${NC}"
    echo "  2. Open dashboard: ${CYAN}clawdbot-security dashboard${NC}"
    echo "  3. Check documentation: ~/.clawdbot-security/docs/"
    echo ""
    echo -e "${GREEN}Happy Securing! 🔒${NC}"
    echo ""
}

# Main installation flow
main() {
    print_header "Clawdbot Security Manager Installer"

    echo "Profile: $PROFILE"
    echo "Mode: $([ "$NON_INTERACTIVE" = "true" ] && echo "Non-Interactive" || echo "Interactive")"
    echo ""

    # Step 1: Check prerequisites
    check_prerequisites

    # Step 2: Install package
    install_package

    # Step 3: Run security setup
    run_setup

    # Step 4: Install optional components
    if [ "$NON_INTERACTIVE" = "false" ]; then
        install_optional
    fi

    # Step 5: Run final audit
    run_audit

    # Step 6: Show completion message
    show_completion
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --profile)
            PROFILE="$2"
            shift 2
            ;;
        --non-interactive)
            NON_INTERACTIVE="true"
            shift
            ;;
        --skip-setup)
            SKIP_SETUP="true"
            shift
            ;;
        --help)
            echo "Clawdbot Security Manager Installer"
            echo ""
            echo "Usage: ./install.sh [options]"
            echo ""
            echo "Options:"
            echo "  --profile PROFILE        Security profile (basic/standard/paranoid)"
            echo "  --non-interactive        Skip interactive prompts"
            echo "  --skip-setup            Skip security setup wizard"
            echo "  --help                  Show this help message"
            echo ""
            echo "Environment Variables:"
            echo "  PROFILE                 Security profile (default: standard)"
            echo "  NON_INTERACTIVE         Skip prompts (default: false)"
            echo "  SKIP_SETUP             Skip setup (default: false)"
            echo ""
            echo "Examples:"
            echo "  ./install.sh"
            echo "  ./install.sh --profile=paranoid"
            echo "  PROFILE=basic NON_INTERACTIVE=true ./install.sh"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Run main installation
main
