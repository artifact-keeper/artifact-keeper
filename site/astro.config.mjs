import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightClientMermaid from '@pasqal-io/starlight-client-mermaid';
import tailwind from '@astrojs/tailwind';

export default defineConfig({
  site: 'https://artifactkeeper.com',
  integrations: [
    starlight({
      title: 'Artifact Keeper',
      description: 'The open-source artifact registry. Documentation, guides, and API reference.',
      plugins: [starlightClientMermaid()],
      logo: {
        light: './src/assets/logo-light.svg',
        dark: './src/assets/logo-dark.svg',
        replacesTitle: false,
      },
      social: {
        github: 'https://github.com/artifact-keeper/artifact-keeper',
      },
      customCss: ['./src/styles/custom.css'],
      disable404Route: true,
      sidebar: [
        {
          label: 'Getting Started',
          items: [
            { label: 'Welcome', slug: 'docs' },
            { label: 'Architecture', slug: 'docs/getting-started/architecture' },
            { label: 'Quickstart', slug: 'docs/getting-started/quickstart' },
            { label: 'Installation', slug: 'docs/getting-started/installation' },
            { label: 'Configuration', slug: 'docs/getting-started/configuration' },
          ],
        },
        {
          label: 'Package Formats',
          items: [
            { label: 'Overview', slug: 'docs/package-formats' },
            { label: 'Docker / OCI', slug: 'docs/guides/docker' },
            { label: 'Maven', slug: 'docs/guides/maven' },
            { label: 'npm', slug: 'docs/guides/npm' },
            { label: 'PyPI', slug: 'docs/guides/pypi' },
            { label: 'Cargo', slug: 'docs/guides/cargo' },
            { label: 'Helm', slug: 'docs/guides/helm' },
          ],
        },
        {
          label: 'Security',
          items: [
            { label: 'Vulnerability Scanning', slug: 'docs/security/scanning' },
            { label: 'Security Policies', slug: 'docs/security/policies' },
            { label: 'Artifact Signing', slug: 'docs/security/signing' },
          ],
        },
        {
          label: 'Migration',
          items: [
            { label: 'From Artifactory', slug: 'docs/migration/from-artifactory' },
          ],
        },
        {
          label: 'Advanced',
          items: [
            { label: 'Authentication & RBAC', slug: 'docs/advanced/auth' },
            { label: 'Storage Backends', slug: 'docs/advanced/storage' },
            { label: 'Edge Nodes', slug: 'docs/advanced/edge-nodes' },
            { label: 'WASM Plugins', slug: 'docs/advanced/plugins' },
            { label: 'Webhooks', slug: 'docs/advanced/webhooks' },
            { label: 'Backup & Recovery', slug: 'docs/advanced/backup' },
          ],
        },
        {
          label: 'Deployment',
          items: [
            { label: 'Docker Compose', slug: 'docs/deployment/docker' },
            { label: 'Kubernetes', slug: 'docs/deployment/kubernetes' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'REST API', slug: 'docs/reference/api' },
            { label: 'Client Configuration', slug: 'docs/reference/cli' },
            { label: 'Environment Variables', slug: 'docs/reference/environment' },
          ],
        },
      ],
    }),
    tailwind({
      applyBaseStyles: false,
    }),
  ],
});
