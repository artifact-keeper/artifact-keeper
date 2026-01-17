import React from 'react';
import { Typography, Space, Divider } from 'antd';
import type { Repository } from '../../../types';
import { CodeBlock } from './CodeBlock';
import { spacing } from '../../../styles/tokens';

const { Title, Text, Paragraph } = Typography;

export interface MavenSetupProps {
  repository: Repository;
  baseUrl: string;
}

export const MavenSetup: React.FC<MavenSetupProps> = ({ repository, baseUrl }) => {
  const repoUrl = `${baseUrl}/maven/${repository.key}`;

  const settingsXml = `<settings>
  <servers>
    <server>
      <id>${repository.key}</id>
      <username>\${env.ARTIFACT_KEEPER_USER}</username>
      <password>\${env.ARTIFACT_KEEPER_PASSWORD}</password>
    </server>
  </servers>
  <profiles>
    <profile>
      <id>${repository.key}-profile</id>
      <repositories>
        <repository>
          <id>${repository.key}</id>
          <url>${repoUrl}</url>
          <releases>
            <enabled>true</enabled>
          </releases>
          <snapshots>
            <enabled>true</enabled>
          </snapshots>
        </repository>
      </repositories>
      <pluginRepositories>
        <pluginRepository>
          <id>${repository.key}</id>
          <url>${repoUrl}</url>
          <releases>
            <enabled>true</enabled>
          </releases>
          <snapshots>
            <enabled>true</enabled>
          </snapshots>
        </pluginRepository>
      </pluginRepositories>
    </profile>
  </profiles>
  <activeProfiles>
    <activeProfile>${repository.key}-profile</activeProfile>
  </activeProfiles>
</settings>`;

  const pomDependency = `<dependency>
  <groupId>com.example</groupId>
  <artifactId>my-artifact</artifactId>
  <version>1.0.0</version>
</dependency>`;

  const pomRepository = `<repositories>
  <repository>
    <id>${repository.key}</id>
    <url>${repoUrl}</url>
  </repository>
</repositories>`;

  const deployPlugin = `<distributionManagement>
  <repository>
    <id>${repository.key}</id>
    <url>${repoUrl}</url>
  </repository>
  <snapshotRepository>
    <id>${repository.key}</id>
    <url>${repoUrl}</url>
  </snapshotRepository>
</distributionManagement>`;

  const deployCommand = `mvn deploy -DaltDeploymentRepository=${repository.key}::default::${repoUrl}`;

  return (
    <Space orientation="vertical" size="large" style={{ width: '100%' }}>
      <div>
        <Title level={5} style={{ marginBottom: spacing.xs }}>
          Repository URL
        </Title>
        <CodeBlock code={repoUrl} />
      </div>

      <Divider style={{ margin: `${spacing.sm}px 0` }} />

      <div>
        <Title level={5} style={{ marginBottom: spacing.xs }}>
          Configure settings.xml
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: spacing.md }}>
          Add the following configuration to your Maven settings.xml file (typically located at ~/.m2/settings.xml).
        </Paragraph>
        <CodeBlock code={settingsXml} language="xml" title="settings.xml" showLineNumbers />
      </div>

      <Divider style={{ margin: `${spacing.sm}px 0` }} />

      <div>
        <Title level={5} style={{ marginBottom: spacing.xs }}>
          Add Repository to pom.xml
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: spacing.md }}>
          Alternatively, add the repository directly to your project's pom.xml file.
        </Paragraph>
        <CodeBlock code={pomRepository} language="xml" title="pom.xml" showLineNumbers />
      </div>

      <Divider style={{ margin: `${spacing.sm}px 0` }} />

      <div>
        <Title level={5} style={{ marginBottom: spacing.xs }}>
          Dependency Example
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: spacing.md }}>
          Add dependencies from this repository to your pom.xml.
        </Paragraph>
        <CodeBlock code={pomDependency} language="xml" title="pom.xml dependency" />
      </div>

      <Divider style={{ margin: `${spacing.sm}px 0` }} />

      <div>
        <Title level={5} style={{ marginBottom: spacing.xs }}>
          Deploy Configuration
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: spacing.md }}>
          Configure your pom.xml for deploying artifacts to this repository.
        </Paragraph>
        <CodeBlock code={deployPlugin} language="xml" title="pom.xml distributionManagement" showLineNumbers />
        <Text type="secondary" style={{ display: 'block', marginTop: spacing.sm }}>
          Or use the command line:
        </Text>
        <div style={{ marginTop: spacing.xs }}>
          <CodeBlock code={deployCommand} language="bash" title="Deploy command" />
        </div>
      </div>
    </Space>
  );
};

export default MavenSetup;
