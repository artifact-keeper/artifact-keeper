import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://docs.artifactkeeper.com',
  integrations: [
    starlight({
      title: 'Artifact Keeper',
      description: 'The open-source artifact registry. Documentation, guides, and API reference.',
      logo: {
        light: './src/assets/logo-light.svg',
        dark: './src/assets/logo-dark.svg',
        replacesTitle: false,
      },
      social: {
        github: 'https://github.com/brandonrc/artifact-keeper',
      },
      customCss: ['./src/styles/custom.css'],
      sidebar: [
        {
          label: 'Getting Started',
          items: [
            { label: 'Welcome', slug: 'index' },
            { label: 'Quickstart', slug: 'getting-started/quickstart' },
            { label: 'Installation', slug: 'getting-started/installation' },
            { label: 'Configuration', slug: 'getting-started/configuration' },
          ],
        },
        {
          label: 'Package Formats',
          items: [
            { label: 'Overview', slug: 'package-formats' },
            { label: 'Docker / OCI', slug: 'guides/docker' },
            { label: 'Maven', slug: 'guides/maven' },
            { label: 'npm', slug: 'guides/npm' },
            { label: 'PyPI', slug: 'guides/pypi' },
            { label: 'Cargo', slug: 'guides/cargo' },
            { label: 'Helm', slug: 'guides/helm' },
          ],
        },
        {
          label: 'Security',
          items: [
            { label: 'Vulnerability Scanning', slug: 'security/scanning' },
            { label: 'Security Policies', slug: 'security/policies' },
            { label: 'Artifact Signing', slug: 'security/signing' },
          ],
        },
        {
          label: 'Migration',
          items: [
            { label: 'From Artifactory', slug: 'migration/from-artifactory' },
          ],
        },
        {
          label: 'Advanced',
          items: [
            { label: 'Authentication & RBAC', slug: 'advanced/auth' },
            { label: 'Storage Backends', slug: 'advanced/storage' },
            { label: 'Edge Nodes', slug: 'advanced/edge-nodes' },
            { label: 'WASM Plugins', slug: 'advanced/plugins' },
            { label: 'Webhooks', slug: 'advanced/webhooks' },
            { label: 'Backup & Recovery', slug: 'advanced/backup' },
          ],
        },
        {
          label: 'Deployment',
          items: [
            { label: 'Docker Compose', slug: 'deployment/docker' },
            { label: 'Kubernetes', slug: 'deployment/kubernetes' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'REST API', slug: 'reference/api' },
            { label: 'Client Configuration', slug: 'reference/cli' },
            { label: 'Environment Variables', slug: 'reference/environment' },
          ],
        },
      ],
    }),
  ],
});
