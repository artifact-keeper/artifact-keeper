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
        src: './src/assets/logo.png',
        replacesTitle: false,
      },
      favicon: '/favicon.png',
      social: {
        github: 'https://github.com/artifact-keeper',
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
            { label: 'NuGet', slug: 'docs/guides/nuget' },
            { label: 'Go Modules', slug: 'docs/guides/go' },
            { label: 'RubyGems', slug: 'docs/guides/rubygems' },
            { label: 'Composer / PHP', slug: 'docs/guides/composer' },
            { label: 'Helm', slug: 'docs/guides/helm' },
            { label: 'C / C++', slug: 'docs/guides/cpp' },
            { label: 'System Packages', slug: 'docs/guides/system-packages' },
            { label: 'Infrastructure', slug: 'docs/guides/infrastructure' },
            { label: 'More Languages', slug: 'docs/guides/more-languages' },
            { label: 'More Formats', slug: 'docs/guides/more-formats' },
          ],
        },
        {
          label: 'Security',
          items: [
            { label: 'Vulnerability Scanning', slug: 'docs/security/scanning' },
            { label: 'OpenSCAP Compliance', slug: 'docs/security/openscap' },
            { label: 'SBOM & Dependency-Track', slug: 'docs/security/sbom' },
            { label: 'Security Policies', slug: 'docs/security/policies' },
            { label: 'Artifact Signing', slug: 'docs/security/signing' },
            { label: 'Security Testing', slug: 'docs/security/red-team' },
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
            { label: 'Staging & Promotion', slug: 'docs/advanced/staging-promotion' },
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
            { label: 'AWS', slug: 'docs/deployment/aws' },
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
