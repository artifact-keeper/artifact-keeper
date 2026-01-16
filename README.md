# Artifact Keeper

[![CI](https://github.com/YOUR_USERNAME/artifact-keeper/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/artifact-keeper/actions/workflows/ci.yml)
[![Docker Publish](https://github.com/YOUR_USERNAME/artifact-keeper/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/YOUR_USERNAME/artifact-keeper/actions/workflows/docker-publish.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An enterprise-grade artifact registry supporting 11+ package formats, built with Rust and React.

## Features

- **Multi-Format Support** - Maven, PyPI, NPM, Docker, Helm, RPM, Debian, Go, NuGet, Cargo, Generic
- **Repository Types** - Local, Remote (proxy), and Virtual (aggregation)
- **Authentication** - JWT-based auth with role-based access control
- **Modern UI** - React TypeScript frontend with Ant Design
- **API-First** - Complete REST API with OpenAPI documentation
- **Containerized** - Docker and Docker Compose support

## Quick Start

### Using Docker Compose

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/artifact-keeper.git
cd artifact-keeper

# Start all services
docker compose up -d

# Access the UI
open http://localhost:3000
```

Default credentials: `admin` / `admin`

### Manual Installation

```bash
# Backend
cargo build --release
./target/release/artifact-keeper

# Frontend
cd frontend
npm install
npm run dev
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Artifact Keeper                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐       │
│   │   Frontend  │────▶│   Backend   │────▶│  PostgreSQL │       │
│   │   (React)   │     │   (Rust)    │     │             │       │
│   └─────────────┘     └──────┬──────┘     └─────────────┘       │
│                              │                                   │
│                              ▼                                   │
│                       ┌─────────────┐                            │
│                       │   Storage   │                            │
│                       │ (S3/Local)  │                            │
│                       └─────────────┘                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Supported Package Formats

| Format | Type | Description |
|--------|------|-------------|
| Maven | Java | Java/Kotlin/Scala packages |
| PyPI | Python | Python packages |
| NPM | Node.js | JavaScript/TypeScript packages |
| Docker | Containers | OCI container images |
| Helm | Kubernetes | Helm charts |
| RPM | Red Hat | RPM packages |
| Debian | Ubuntu/Debian | DEB packages |
| Go | Go | Go modules |
| NuGet | .NET | .NET packages |
| Cargo | Rust | Rust crates |
| Generic | Any | Any file type |

## CI/CD Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                        GitHub Actions                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐    │
│   │   Lint   │──▶│   Test   │──▶│  Build   │──▶│   E2E    │    │
│   │          │   │          │   │          │   │  Tests   │    │
│   └──────────┘   └──────────┘   └──────────┘   └──────────┘    │
│                                                      │          │
│                                                      ▼          │
│   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐    │
│   │ Security │   │  Docker  │   │ Release  │   │ Publish  │    │
│   │  Audit   │   │  Build   │   │          │   │          │    │
│   └──────────┘   └──────────┘   └──────────┘   └──────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Workflows

| Workflow | Trigger | Description |
|----------|---------|-------------|
| `ci.yml` | Push/PR | Lint, test, build, E2E tests |
| `docker-publish.yml` | Push to main/tags | Build and push Docker images |
| `release.yml` | Version tags | Create GitHub releases |
| `scheduled-tests.yml` | Daily | Nightly E2E and security scans |

## Testing

### Local Testing

```bash
# Backend tests
cargo test --workspace

# Frontend unit tests
cd frontend && npm run test:run

# E2E tests (Docker)
./scripts/run-e2e-tests.sh
```

### Test Coverage

| Type | Framework | Location |
|------|-----------|----------|
| Backend Unit | Cargo | `backend/src/**/*.rs` |
| Backend Integration | Cargo | `backend/tests/` |
| Frontend Unit | Vitest | `frontend/src/**/*.test.ts` |
| Frontend Component | RTL | `frontend/src/**/*.test.tsx` |
| E2E | Playwright | `frontend/e2e/` |

See [TESTING.md](TESTING.md) for detailed testing documentation.

## API Documentation

- **OpenAPI Spec**: `specs/001-artifact-registry/contracts/openapi.yaml`
- **Swagger UI**: Available at `/api/docs` when running

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `JWT_SECRET` | Secret for JWT tokens | Required |
| `STORAGE_PATH` | Local storage path | `/data/storage` |
| `S3_BUCKET` | S3 bucket name | - |
| `S3_ENDPOINT` | S3 endpoint URL | - |
| `RUST_LOG` | Log level | `info` |

### Docker Compose Files

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Production deployment |
| `docker-compose.test.yml` | Automated E2E testing |
| `deploy/docker/docker-compose.yml` | Full stack with MinIO |

## Development

### Prerequisites

- Rust 1.75+
- Node.js 20+
- PostgreSQL 16+
- Docker (optional)

### Project Structure

```
artifact-keeper/
├── backend/           # Rust backend
├── frontend/          # React frontend
├── edge/              # Edge node service
├── specs/             # OpenAPI specifications
├── scripts/           # Utility scripts
├── deploy/            # Deployment configs
└── .github/           # CI/CD workflows
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

---

Built with ❤️ using Rust, React, and TypeScript
