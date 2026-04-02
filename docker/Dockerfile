FROM debian:bookworm-slim

# Metadata
LABEL maintainer="Your Organization"
LABEL description="Claude Code + FortiSIEM AI plugin pre-configured environment"

# System deps
RUN apt-get update && apt-get install -y \
    curl \
    git \
    jq \
    vim \
    nano \
    python3 \
    python3-pip \
    python3-venv \
    libxml2-utils \
    ca-certificates \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Node.js LTS (for Claude Code)
RUN curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# GitHub CLI
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
    | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && apt-get update && apt-get install -y gh && rm -rf /var/lib/apt/lists/*

# Claude Code
RUN npm install -g @anthropic-ai/claude-code

# Create non-root user
RUN useradd -m -s /bin/bash fsiem && mkdir -p /home/fsiem/.claude

# Python deps for FortiSIEM scripts
COPY docker/requirements.txt /tmp/requirements.txt
RUN pip3 install --break-system-packages -r /tmp/requirements.txt

# Copy the plugin into the image
COPY . /home/fsiem/fortisiem-ai
RUN chown -R fsiem:fsiem /home/fsiem/fortisiem-ai

USER fsiem
WORKDIR /home/fsiem

# Pre-install plugin into Claude Code
RUN claude plugin marketplace add /home/fsiem/fortisiem-ai/marketplace || true

# Optional project mount point
RUN mkdir -p /home/fsiem/project

COPY docker/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
