import React from 'react';
import { Typography, Space, Divider } from 'antd';
import type { Repository } from '../../../types';
import { CodeBlock } from './CodeBlock';
import { spacing } from '../../../styles/tokens';

const { Title, Paragraph, Text } = Typography;

export interface PyPISetupProps {
  repository: Repository;
  baseUrl: string;
}

export const PyPISetup: React.FC<PyPISetupProps> = ({ repository, baseUrl }) => {
  const simpleUrl = `${baseUrl}/pypi/${repository.key}/simple/`;
  const uploadUrl = `${baseUrl}/pypi/${repository.key}/`;

  const pipConfConfig = `[global]
index-url = ${simpleUrl}
trusted-host = ${new URL(baseUrl).host}

[install]
extra-index-url = https://pypi.org/simple/`;

  const pipInstallCommand = `pip install --index-url ${simpleUrl} <package-name>`;

  const pipInstallWithAuth = `pip install --index-url https://\${ARTIFACT_KEEPER_USER}:\${ARTIFACT_KEEPER_PASSWORD}@${new URL(simpleUrl).host}${new URL(simpleUrl).pathname} <package-name>`;

  const requirementsTxt = `--index-url ${simpleUrl}
--extra-index-url https://pypi.org/simple/

requests>=2.28.0
numpy>=1.24.0
my-private-package>=1.0.0`;

  const pypircConfig = `[distutils]
index-servers =
    ${repository.key}

[${repository.key}]
repository = ${uploadUrl}
username = __token__
password = <your-api-token>`;

  const twineUploadCommand = `twine upload --repository ${repository.key} dist/*`;

  const setupPyUpload = `python setup.py sdist bdist_wheel
twine upload --repository-url ${uploadUrl} dist/*`;

  const poetryConfig = `[[tool.poetry.source]]
name = "${repository.key}"
url = "${simpleUrl}"
priority = "primary"`;

  const poetryPublishConfig = `[tool.poetry.repositories.${repository.key}]
url = "${uploadUrl}"`;

  const poetryAuthCommand = `poetry config http-basic.${repository.key} $ARTIFACT_KEEPER_USER $ARTIFACT_KEEPER_PASSWORD`;

  return (
    <Space orientation="vertical" size="large" style={{ width: '100%' }}>
      <div>
        <Title level={5} style={{ marginBottom: spacing.xs }}>
          Repository URL
        </Title>
        <CodeBlock code={simpleUrl} />
      </div>

      <Divider style={{ margin: `${spacing.sm}px 0` }} />

      <div>
        <Title level={5} style={{ marginBottom: spacing.xs }}>
          Configure pip.conf
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: spacing.md }}>
          Add the following configuration to your pip.conf file (typically at ~/.config/pip/pip.conf on Linux/macOS or %APPDATA%\pip\pip.ini on Windows).
        </Paragraph>
        <CodeBlock code={pipConfConfig} title="pip.conf" showLineNumbers />
      </div>

      <Divider style={{ margin: `${spacing.sm}px 0` }} />

      <div>
        <Title level={5} style={{ marginBottom: spacing.xs }}>
          Install Packages
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: spacing.md }}>
          Install packages from this repository using pip.
        </Paragraph>
        <CodeBlock code={pipInstallCommand} language="bash" title="pip install" />
        <Text type="secondary" style={{ display: 'block', marginTop: spacing.sm }}>
          With authentication:
        </Text>
        <div style={{ marginTop: spacing.xs }}>
          <CodeBlock code={pipInstallWithAuth} language="bash" title="pip install (authenticated)" />
        </div>
      </div>

      <Divider style={{ margin: `${spacing.sm}px 0` }} />

      <div>
        <Title level={5} style={{ marginBottom: spacing.xs }}>
          requirements.txt Configuration
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: spacing.md }}>
          Configure your requirements.txt to use this repository.
        </Paragraph>
        <CodeBlock code={requirementsTxt} title="requirements.txt" showLineNumbers />
      </div>

      <Divider style={{ margin: `${spacing.sm}px 0` }} />

      <div>
        <Title level={5} style={{ marginBottom: spacing.xs }}>
          Configure .pypirc for Upload
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: spacing.md }}>
          Add the following to ~/.pypirc to enable uploading packages.
        </Paragraph>
        <CodeBlock code={pypircConfig} title="~/.pypirc" showLineNumbers />
      </div>

      <Divider style={{ margin: `${spacing.sm}px 0` }} />

      <div>
        <Title level={5} style={{ marginBottom: spacing.xs }}>
          Upload with Twine
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: spacing.md }}>
          Upload packages to this repository using twine.
        </Paragraph>
        <CodeBlock code={twineUploadCommand} language="bash" title="Twine upload" />
        <Text type="secondary" style={{ display: 'block', marginTop: spacing.sm }}>
          Or build and upload in one step:
        </Text>
        <div style={{ marginTop: spacing.xs }}>
          <CodeBlock code={setupPyUpload} language="bash" title="Build and upload" />
        </div>
      </div>

      <Divider style={{ margin: `${spacing.sm}px 0` }} />

      <div>
        <Title level={5} style={{ marginBottom: spacing.xs }}>
          Poetry Configuration
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: spacing.md }}>
          Configure Poetry to use this repository. Add to pyproject.toml.
        </Paragraph>
        <CodeBlock code={poetryConfig} language="toml" title="pyproject.toml (source)" showLineNumbers />
        <Text type="secondary" style={{ display: 'block', marginTop: spacing.sm }}>
          For publishing, add:
        </Text>
        <div style={{ marginTop: spacing.xs }}>
          <CodeBlock code={poetryPublishConfig} language="toml" title="pyproject.toml (repository)" />
        </div>
        <Text type="secondary" style={{ display: 'block', marginTop: spacing.sm }}>
          Configure authentication:
        </Text>
        <div style={{ marginTop: spacing.xs }}>
          <CodeBlock code={poetryAuthCommand} language="bash" title="Poetry auth" />
        </div>
      </div>
    </Space>
  );
};

export default PyPISetup;
