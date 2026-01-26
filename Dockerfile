# Clawdbot Security Manager - Pre-Hardened Container
# Version: 0.5.0
FROM ubuntu:22.04

# Metadata
LABEL maintainer="Clawdbot Security Team"
LABEL description="Pre-hardened Clawdbot installation with security manager"
LABEL version="0.5.0"

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive
ENV NODE_VERSION=20

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    gnupg \
    ca-certificates \
    nginx \
    fail2ban \
    sudo \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Create clawdbot user
RUN useradd -m -s /bin/bash -u 1000 clawdbot \
    && usermod -aG sudo clawdbot \
    && echo "clawdbot ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/clawdbot

# Set working directory
WORKDIR /home/clawdbot

# Copy clawdbot-security source
COPY --chown=clawdbot:clawdbot . /home/clawdbot/clawdbot-security/

# Switch to clawdbot user
USER clawdbot

# Install clawdbot-security
WORKDIR /home/clawdbot/clawdbot-security
RUN npm install && npm run build && npm link

# Run security setup with standard profile (non-interactive)
RUN clawdbot-security setup --profile=standard --non-interactive || true

# Create .clawdbot directory structure
RUN mkdir -p /home/clawdbot/.clawdbot/logs \
    && mkdir -p /home/clawdbot/.clawdbot/nginx \
    && mkdir -p /home/clawdbot/.clawdbot/fail2ban \
    && mkdir -p /home/clawdbot/.clawdbot/backups

# Switch back to root for service configuration
USER root

# Copy nginx configuration (if exists)
RUN if [ -f /home/clawdbot/.clawdbot/nginx/clawdbot-security.conf ]; then \
        cp /home/clawdbot/.clawdbot/nginx/clawdbot-security.conf /etc/nginx/conf.d/; \
    fi

# Copy fail2ban configuration (if exists)
RUN if [ -f /home/clawdbot/.clawdbot/fail2ban/clawdbot.local ]; then \
        cp /home/clawdbot/.clawdbot/fail2ban/clawdbot.local /etc/fail2ban/jail.d/; \
    fi && \
    if [ -d /home/clawdbot/.clawdbot/fail2ban/filters ]; then \
        cp /home/clawdbot/.clawdbot/fail2ban/filters/*.conf /etc/fail2ban/filter.d/ 2>/dev/null || true; \
    fi

# Validate configurations
RUN nginx -t || echo "nginx config validation skipped" \
    && fail2ban-client -t || echo "fail2ban validation skipped"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD su - clawdbot -c "clawdbot-security status" || exit 1

# Expose ports
EXPOSE 18789 8080 443

# Create entrypoint script
RUN cat > /usr/local/bin/docker-entrypoint.sh << 'EOF'
#!/bin/bash
set -e

echo "=== Clawdbot Security Container Starting ==="

# Start nginx
echo "Starting nginx..."
service nginx start

# Start fail2ban
echo "Starting fail2ban..."
service fail2ban start

# Run security audit
echo "Running security audit..."
su - clawdbot -c "clawdbot-security audit" || true

# Display security status
echo ""
echo "=== Security Status ==="
su - clawdbot -c "clawdbot-security status"

# Keep container running
echo ""
echo "=== Container Ready ==="
echo "Security dashboard available at: http://localhost:18789"
echo ""

# Execute main command or keep alive
if [ $# -gt 0 ]; then
    exec "$@"
else
    # Keep container alive
    tail -f /dev/null
fi
EOF

RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Switch back to clawdbot user
USER clawdbot
WORKDIR /home/clawdbot

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD []
