#!/usr/bin/env bash
set -euo pipefail

echo "==> [06] Configuring Nginx reverse proxy"

# Remove default site
rm -f /etc/nginx/sites-enabled/default

# Artifact Keeper site config
cat > /etc/nginx/sites-available/artifact-keeper <<'NGINX'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    client_max_body_size 0;
    proxy_request_buffering off;

    # Frontend static files
    location / {
        root /opt/artifact-keeper/frontend;
        try_files $uri $uri/ /index.html;
    }

    # API and package format endpoints
    location /api/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }

    # Health check
    location /health {
        proxy_pass http://127.0.0.1:8080/health;
    }

    # Package format routes — proxy everything the backend handles
    location ~ ^/(v2|maven2|npm|pypi|cargo|nuget|gems|go|composer|helm|rpm|debian|alpine|opkg|conan|terraform|vagrant|chef|puppet|ansible|hex|pub|swift|cocoapods|cran|sbt|conda|huggingface|mlmodel|vscode|jetbrains|gitlfs|p2|generic)/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
}
NGINX

ln -sf /etc/nginx/sites-available/artifact-keeper /etc/nginx/sites-enabled/artifact-keeper

nginx -t
systemctl enable nginx

echo "==> [06] Nginx configured"
