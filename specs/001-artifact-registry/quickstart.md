# Quickstart: Indiana Jones Artifact Registry

Get the artifact registry running locally in under 5 minutes.

## Prerequisites

- **Docker** and **Docker Compose** (for quick start)
- **Rust 1.75+** (for development)
- **Node.js 20+** (for frontend development)
- **PostgreSQL 15+** (or use Docker)

## Quick Start with Docker

```bash
# Clone the repository
git clone https://github.com/yourorg/indiana-jones.git
cd indiana-jones

# Start all services
docker compose up -d

# Wait for services to be ready
docker compose logs -f backend  # Watch for "Listening on 0.0.0.0:8080"

# Open the web UI
open http://localhost:8080
```

Default credentials:
- **Username**: `admin`
- **Password**: `admin123` (change immediately!)

## Manual Setup (Development)

### 1. Start PostgreSQL

```bash
# Using Docker
docker run -d \
  --name registry-postgres \
  -e POSTGRES_DB=artifact_registry \
  -e POSTGRES_USER=registry \
  -e POSTGRES_PASSWORD=registry \
  -p 5432:5432 \
  postgres:15

# Or use an existing PostgreSQL instance
export DATABASE_URL="postgres://registry:registry@localhost:5432/artifact_registry"
```

### 2. Build and Run Backend

```bash
cd backend

# Install dependencies and build
cargo build --release

# Run database migrations
cargo run --bin migrate

# Start the server
cargo run --release

# Server starts on http://localhost:8080
```

### 3. Build and Run Frontend

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev

# Frontend starts on http://localhost:5173 (proxies to backend)
```

### 4. Build for Production

```bash
# Build backend
cd backend && cargo build --release

# Build frontend (output to backend/static)
cd frontend && npm run build
```

## Configuration

Configuration via environment variables:

```bash
# Database
DATABASE_URL=postgres://user:pass@localhost:5432/artifact_registry

# Server
BIND_ADDRESS=0.0.0.0:8080
LOG_LEVEL=info

# Storage (choose one)
STORAGE_BACKEND=filesystem
STORAGE_PATH=/var/lib/registry/artifacts
# or
STORAGE_BACKEND=s3
S3_BUCKET=my-artifacts
S3_REGION=us-east-1
AWS_ACCESS_KEY_ID=xxx
AWS_SECRET_ACCESS_KEY=xxx

# Authentication
JWT_SECRET=<random-32-bytes>
SESSION_EXPIRY=24h

# Optional: OIDC
OIDC_ENABLED=true
OIDC_ISSUER=https://auth.example.com
OIDC_CLIENT_ID=artifact-registry
OIDC_CLIENT_SECRET=xxx
```

## Create Your First Repository

### Via Web UI

1. Log in at http://localhost:8080
2. Navigate to **Repositories** → **Create Repository**
3. Fill in:
   - **Key**: `my-maven-repo`
   - **Name**: `My Maven Repository`
   - **Format**: Maven
   - **Type**: Local
4. Click **Create**

### Via API

```bash
# Get access token
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | jq -r '.access_token')

# Create Maven repository
curl -X POST http://localhost:8080/api/v1/repositories \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key": "my-maven-repo",
    "name": "My Maven Repository",
    "format": "maven",
    "repo_type": "local"
  }'
```

## Use Package Managers

### Maven

Add to `~/.m2/settings.xml`:

```xml
<settings>
  <servers>
    <server>
      <id>indiana-jones</id>
      <username>admin</username>
      <password>admin123</password>
    </server>
  </servers>
</settings>
```

Add to your `pom.xml`:

```xml
<repositories>
  <repository>
    <id>indiana-jones</id>
    <url>http://localhost:8080/repository/my-maven-repo</url>
  </repository>
</repositories>

<distributionManagement>
  <repository>
    <id>indiana-jones</id>
    <url>http://localhost:8080/repository/my-maven-repo</url>
  </repository>
</distributionManagement>
```

Deploy an artifact:

```bash
mvn deploy
```

### npm

```bash
# Configure registry
npm config set @myorg:registry http://localhost:8080/repository/my-npm-repo/
npm config set //localhost:8080/repository/my-npm-repo/:_authToken "YOUR_API_TOKEN"

# Publish
npm publish

# Install
npm install @myorg/my-package
```

### Docker

```bash
# Login
docker login localhost:8080

# Tag and push
docker tag myimage:latest localhost:8080/my-docker-repo/myimage:latest
docker push localhost:8080/my-docker-repo/myimage:latest

# Pull
docker pull localhost:8080/my-docker-repo/myimage:latest
```

### pip (PyPI)

```bash
# Upload
pip install twine
twine upload --repository-url http://localhost:8080/repository/my-pypi-repo/ dist/*

# Install
pip install --index-url http://localhost:8080/repository/my-pypi-repo/simple/ mypackage
```

## Deploy Edge Node

```bash
# On edge server
docker run -d \
  --name registry-edge \
  -e PRIMARY_URL=https://primary.example.com \
  -e EDGE_API_KEY=<from-primary-ui> \
  -e STORAGE_PATH=/var/lib/registry/cache \
  -p 8080:8080 \
  -v registry-cache:/var/lib/registry/cache \
  indiana-jones-edge:latest
```

Configure replication in primary UI:
1. **Admin** → **Edge Nodes** → Select your node
2. **Sync Tasks** → **Add Repository**
3. Choose sync mode: On-demand, Scheduled, or Eager

## Next Steps

- [API Documentation](./contracts/openapi.yaml)
- [Architecture Guide](../docs/architecture.md)
- [Deployment Guide](../docs/deployment.md)
- [Plugin Development](../docs/plugins.md)

## Troubleshooting

### Connection refused

```bash
# Check if backend is running
docker compose ps
curl http://localhost:8080/api/v1/health
```

### Authentication fails

```bash
# Verify credentials
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

### Storage issues

```bash
# Check storage permissions
ls -la /var/lib/registry/artifacts

# Check disk space
df -h
```

### Database connection

```bash
# Test database connectivity
psql $DATABASE_URL -c "SELECT 1"

# Check migrations
cargo run --bin migrate -- status
```
