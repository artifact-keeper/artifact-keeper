#!/usr/bin/env bash
set -euo pipefail

echo "==> [04] Installing Trivy ${TRIVY_VERSION} and Grype ${GRYPE_VERSION}"

# Trivy
curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.deb" \
  -o /tmp/trivy.deb
dpkg -i /tmp/trivy.deb
rm /tmp/trivy.deb

# Trivy server systemd service
cat > /etc/systemd/system/trivy-server.service <<'EOF'
[Unit]
Description=Trivy vulnerability scanner server
After=network.target

[Service]
Type=simple
User=artifact-keeper
Group=artifact-keeper
ExecStart=/usr/bin/trivy server --listen 127.0.0.1:8090
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable trivy-server

# Grype
curl -fsSL "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.deb" \
  -o /tmp/grype.deb
dpkg -i /tmp/grype.deb
rm /tmp/grype.deb

echo "==> [04] Scanners installed"
