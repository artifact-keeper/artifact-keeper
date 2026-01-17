import React from 'react';
import { Typography, Space, Divider } from 'antd';
import type { Repository } from '../../../types';
import { CodeBlock } from './CodeBlock';
import { spacing } from '../../../styles/tokens';

const { Title, Paragraph, Text } = Typography;

export interface DockerSetupProps {
  repository: Repository;
  baseUrl: string;
}

export const DockerSetup: React.FC<DockerSetupProps> = ({ repository, baseUrl }) => {
  const registryHost = new URL(baseUrl).host;
  const registryUrl = `${registryHost}/${repository.key}`;

  const dockerLoginCommand = `docker login ${registryHost}`;

  const dockerPullCommand = `docker pull ${registryUrl}/<image-name>:<tag>`;

  const dockerPushCommand = `docker tag <local-image>:<tag> ${registryUrl}/<image-name>:<tag>
docker push ${registryUrl}/<image-name>:<tag>`;

  const dockerfileFromExample = `FROM ${registryUrl}/base-image:latest

# Your Dockerfile instructions here
WORKDIR /app
COPY . .
RUN npm install
CMD ["npm", "start"]`;

  const dockerComposeExample = `version: '3.8'
services:
  app:
    image: ${registryUrl}/my-app:latest
    ports:
      - "3000:3000"
  database:
    image: ${registryUrl}/postgres:14`;

  const dockerCredHelperConfig = `{
  "credHelpers": {
    "${registryHost}": "artifact-keeper"
  }
}`;

  const podmanLoginCommand = `podman login ${registryHost}`;

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
          Docker Login
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: spacing.md }}>
          Authenticate with the Docker registry. You will be prompted for your username and password.
        </Paragraph>
        <CodeBlock code={dockerLoginCommand} language="bash" title="Login command" />
        <Text type="secondary" style={{ display: 'block', marginTop: spacing.sm, fontSize: 12 }}>
          Use your Artifact Keeper username and password or API key.
        </Text>
      </div>

      <Divider style={{ margin: `${spacing.sm}px 0` }} />

      <div>
        <Title level={5} style={{ marginBottom: spacing.xs }}>
          Pull Images
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: spacing.md }}>
          Pull Docker images from this repository.
        </Paragraph>
        <CodeBlock code={dockerPullCommand} language="bash" title="Pull command" />
      </div>

      <Divider style={{ margin: `${spacing.sm}px 0` }} />

      <div>
        <Title level={5} style={{ marginBottom: spacing.xs }}>
          Push Images
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: spacing.md }}>
          Tag and push Docker images to this repository.
        </Paragraph>
        <CodeBlock code={dockerPushCommand} language="bash" title="Push commands" />
      </div>

      <Divider style={{ margin: `${spacing.sm}px 0` }} />

      <div>
        <Title level={5} style={{ marginBottom: spacing.xs }}>
          Dockerfile FROM Example
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: spacing.md }}>
          Use images from this repository as base images in your Dockerfile.
        </Paragraph>
        <CodeBlock code={dockerfileFromExample} language="dockerfile" title="Dockerfile" showLineNumbers />
      </div>

      <Divider style={{ margin: `${spacing.sm}px 0` }} />

      <div>
        <Title level={5} style={{ marginBottom: spacing.xs }}>
          Docker Compose Example
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: spacing.md }}>
          Use images from this repository in docker-compose.yml.
        </Paragraph>
        <CodeBlock code={dockerComposeExample} language="yaml" title="docker-compose.yml" showLineNumbers />
      </div>

      <Divider style={{ margin: `${spacing.sm}px 0` }} />

      <div>
        <Title level={5} style={{ marginBottom: spacing.xs }}>
          Credential Helper Configuration
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: spacing.md }}>
          Configure Docker credential helper for automatic authentication. Add to ~/.docker/config.json.
        </Paragraph>
        <CodeBlock code={dockerCredHelperConfig} language="json" title="~/.docker/config.json" showLineNumbers />
      </div>

      <Divider style={{ margin: `${spacing.sm}px 0` }} />

      <div>
        <Title level={5} style={{ marginBottom: spacing.xs }}>
          Podman Support
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: spacing.md }}>
          You can also use Podman with this registry.
        </Paragraph>
        <CodeBlock code={podmanLoginCommand} language="bash" title="Podman login" />
      </div>
    </Space>
  );
};

export default DockerSetup;
