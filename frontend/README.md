# Artifact Keeper Frontend

A React TypeScript web UI for the Artifact Keeper artifact registry.

## Tech Stack

- **React 18** - UI framework
- **TypeScript 5** - Type safety
- **Vite** - Build tool and dev server
- **Ant Design 5** - UI component library
- **React Query** - Data fetching and caching
- **React Router 6** - Client-side routing
- **Axios** - HTTP client

## Features

- **Authentication** - JWT-based login/logout with automatic token refresh
- **Repository Management** - Create, edit, delete repositories with filtering and sorting
- **Artifact Browser** - Upload, download, search, and manage artifacts
- **Artifact Details** - View checksums, metadata, and copy download URLs
- **Admin Dashboard** - System health monitoring and statistics
- **User Management** - View and manage users (admin only)
- **Responsive UI** - Works on desktop and tablet devices

## Getting Started

### Prerequisites

- Node.js 18+ or Bun
- Backend server running on `http://localhost:9080`

### Installation

```bash
# Install dependencies
npm install
# or
bun install
```

### Development

```bash
# Start development server
npm run dev
# or
bun dev
```

The app will be available at `http://localhost:5173`

### Build

```bash
# Build for production
npm run build
# or
bun run build
```

### Environment Variables

Create a `.env` file (see `.env.example`):

```env
VITE_API_URL=http://localhost:9080
```

## Project Structure

```
src/
├── api/              # API client and endpoint functions
│   ├── client.ts     # Axios instance with auth interceptors
│   ├── auth.ts       # Authentication endpoints
│   ├── repositories.ts
│   ├── artifacts.ts
│   └── admin.ts
├── components/       # Reusable components
│   ├── layout/       # Header, Sidebar
│   └── ErrorBoundary.tsx
├── contexts/         # React contexts
│   └── AuthContext.tsx
├── hooks/            # Custom hooks
│   └── useDocumentTitle.ts
├── pages/            # Page components
│   ├── Dashboard.tsx
│   ├── Login.tsx
│   ├── Repositories.tsx
│   ├── RepositoryDetail.tsx
│   ├── Users.tsx
│   ├── Settings.tsx
│   └── NotFound.tsx
├── types/            # TypeScript type definitions
├── App.tsx           # Main app component with routing
├── main.tsx          # Entry point
└── index.css         # Global styles
```

## Supported Artifact Formats

- Maven (Java)
- PyPI (Python)
- NPM (Node.js)
- Docker (Containers)
- Helm (Kubernetes)
- RPM (Red Hat)
- Debian (Ubuntu)
- Go Modules
- NuGet (.NET)
- Cargo (Rust)
- Generic (Any file type)

## Default Credentials

For development, use the default admin account:

- **Username:** `admin`
- **Password:** `admin`

## License

MIT
