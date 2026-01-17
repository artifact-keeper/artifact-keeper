import React from 'react';
import { Typography, Space, Divider } from 'antd';
import type { Repository } from '../../../types';
import { CodeBlock } from './CodeBlock';
import { spacing } from '../../../styles/tokens';

const { Title, Paragraph } = Typography;

export interface NpmSetupProps {
  repository: Repository;
  baseUrl: string;
}

export const NpmSetup: React.FC<NpmSetupProps> = ({ repository, baseUrl }) => {
  const registryUrl = `${baseUrl}/npm/${repository.key}/`;

  const npmrcConfig = `registry=${registryUrl}
//${new URL(registryUrl).host}${new URL(registryUrl).pathname}:_authToken=\${NPM_TOKEN}
always-auth=true`;

  const npmrcScoped = `@myorg:registry=${registryUrl}
//${new URL(registryUrl).host}${new URL(registryUrl).pathname}:_authToken=\${NPM_TOKEN}`;

  const packageJsonRegistry = `{
  "name": "my-package",
  "version": "1.0.0",
  "publishConfig": {
    "registry": "${registryUrl}"
  }
}`;

  const npmInstallCommand = `npm config set registry ${registryUrl}
npm login --registry=${registryUrl}
npm install <package-name>`;

  const npmPublishCommand = `npm publish --registry=${registryUrl}`;

  const yarnConfig = `yarn config set registry ${registryUrl}`;

  const pnpmConfig = `pnpm config set registry ${registryUrl}`;

  return (
    <Space orientation="vertical" size="large" style={{ width: '100%' }}>
      <div>
        <Title level={5} style={{ marginBottom: spacing.xs }}>
          Registry URL
        </Title>
        <CodeBlock code={registryUrl} />
      </div>

      <Divider style={{ margin: `${spacing.sm}px 0` }} />

      <div>
        <Title level={5} style={{ marginBottom: spacing.xs }}>
          Configure .npmrc
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: spacing.md }}>
          Add the following configuration to your .npmrc file (in your project root or ~/.npmrc for global config).
        </Paragraph>
        <CodeBlock code={npmrcConfig} title=".npmrc" showLineNumbers />
      </div>

      <Divider style={{ margin: `${spacing.sm}px 0` }} />

      <div>
        <Title level={5} style={{ marginBottom: spacing.xs }}>
          Scoped Package Configuration
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: spacing.md }}>
          For scoped packages (@myorg/package-name), configure the registry for your scope.
        </Paragraph>
        <CodeBlock code={npmrcScoped} title=".npmrc (scoped)" showLineNumbers />
      </div>

      <Divider style={{ margin: `${spacing.sm}px 0` }} />

      <div>
        <Title level={5} style={{ marginBottom: spacing.xs }}>
          Install Packages
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: spacing.md }}>
          Configure npm and install packages from this registry.
        </Paragraph>
        <CodeBlock code={npmInstallCommand} language="bash" title="npm commands" />
      </div>

      <Divider style={{ margin: `${spacing.sm}px 0` }} />

      <div>
        <Title level={5} style={{ marginBottom: spacing.xs }}>
          package.json Configuration
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: spacing.md }}>
          Configure your package.json for publishing to this registry.
        </Paragraph>
        <CodeBlock code={packageJsonRegistry} language="json" title="package.json" showLineNumbers />
      </div>

      <Divider style={{ margin: `${spacing.sm}px 0` }} />

      <div>
        <Title level={5} style={{ marginBottom: spacing.xs }}>
          Publish Package
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: spacing.md }}>
          Publish your package to this registry.
        </Paragraph>
        <CodeBlock code={npmPublishCommand} language="bash" title="Publish command" />
      </div>

      <Divider style={{ margin: `${spacing.sm}px 0` }} />

      <div>
        <Title level={5} style={{ marginBottom: spacing.xs }}>
          Alternative Package Managers
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: spacing.md }}>
          Configure other package managers to use this registry.
        </Paragraph>
        <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
          <CodeBlock code={yarnConfig} language="bash" title="Yarn" />
          <CodeBlock code={pnpmConfig} language="bash" title="pnpm" />
        </Space>
      </div>
    </Space>
  );
};

export default NpmSetup;
