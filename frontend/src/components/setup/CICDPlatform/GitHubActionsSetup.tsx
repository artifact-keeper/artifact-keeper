import React from 'react';
import { Typography, Space, Divider, Alert, Collapse } from 'antd';
import { SettingOutlined, KeyOutlined, FileTextOutlined } from '@ant-design/icons';
import { spacing } from '../../../styles/tokens';
import type { Repository } from '../../../types';
import { CodeBlock } from './CICDPlatformWizard';

const { Title, Text, Paragraph } = Typography;

export interface GitHubActionsSetupProps {
  repository?: Repository;
  baseUrl: string;
}

export const GitHubActionsSetup: React.FC<GitHubActionsSetupProps> = ({
  repository,
  baseUrl,
}) => {
  const repoKey = repository?.key || 'my-repo';
  const repoFormat = repository?.format || 'generic';

  const genericWorkflow = `name: Build and Publish

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

env:
  ARTIFACT_KEEPER_URL: ${baseUrl}
  ARTIFACT_KEEPER_REPO: ${repoKey}

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Build
        run: |
          echo "Building project..."
          # Add your build steps here

      - name: Test
        run: |
          echo "Running tests..."
          # Add your test steps here

      - name: Publish Artifact
        env:
          AK_USERNAME: \${{ secrets.ARTIFACT_KEEPER_USERNAME }}
          AK_PASSWORD: \${{ secrets.ARTIFACT_KEEPER_PASSWORD }}
        run: |
          curl -u \$AK_USERNAME:\$AK_PASSWORD \\
            -X PUT \\
            -T ./build/artifact.jar \\
            \$ARTIFACT_KEEPER_URL/api/v1/repos/\$ARTIFACT_KEEPER_REPO/artifacts/artifact.jar`;

  const npmWorkflow = `name: npm Publish

on:
  push:
    branches: [ main ]
  release:
    types: [ published ]

env:
  ARTIFACT_KEEPER_URL: ${baseUrl}
  ARTIFACT_KEEPER_REPO: ${repoKey}

jobs:
  build-and-publish:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Configure npm registry
        env:
          AK_USERNAME: \${{ secrets.ARTIFACT_KEEPER_USERNAME }}
          AK_PASSWORD: \${{ secrets.ARTIFACT_KEEPER_PASSWORD }}
        run: |
          npm config set registry \$ARTIFACT_KEEPER_URL/api/v1/npm/\$ARTIFACT_KEEPER_REPO/
          echo "//\${ARTIFACT_KEEPER_URL#https://}/api/v1/npm/\$ARTIFACT_KEEPER_REPO/:_auth=\$(echo -n \$AK_USERNAME:\$AK_PASSWORD | base64)" >> ~/.npmrc

      - name: Install dependencies
        run: npm ci

      - name: Build
        run: npm run build

      - name: Test
        run: npm test

      - name: Publish
        if: github.event_name == 'release'
        run: npm publish`;

  const mavenWorkflow = `name: Maven Build and Deploy

on:
  push:
    branches: [ main ]
  release:
    types: [ published ]

env:
  ARTIFACT_KEEPER_URL: ${baseUrl}
  ARTIFACT_KEEPER_REPO: ${repoKey}

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up JDK 17
        uses: actions/setup-java@v4
        with:
          java-version: '17'
          distribution: 'temurin'
          cache: maven

      - name: Configure Maven settings
        env:
          AK_USERNAME: \${{ secrets.ARTIFACT_KEEPER_USERNAME }}
          AK_PASSWORD: \${{ secrets.ARTIFACT_KEEPER_PASSWORD }}
        run: |
          mkdir -p ~/.m2
          cat > ~/.m2/settings.xml << EOF
          <settings>
            <servers>
              <server>
                <id>artifact-keeper</id>
                <username>\$AK_USERNAME</username>
                <password>\$AK_PASSWORD</password>
              </server>
            </servers>
          </settings>
          EOF

      - name: Build with Maven
        run: mvn -B package --file pom.xml

      - name: Test
        run: mvn test

      - name: Deploy to Artifact Keeper
        if: github.event_name == 'release'
        run: |
          mvn deploy -DaltDeploymentRepository=artifact-keeper::default::\$ARTIFACT_KEEPER_URL/api/v1/maven/\$ARTIFACT_KEEPER_REPO/`;

  const dockerWorkflow = `name: Docker Build and Push

on:
  push:
    branches: [ main ]
    tags: [ 'v*' ]
  pull_request:
    branches: [ main ]

env:
  ARTIFACT_KEEPER_URL: ${baseUrl}
  ARTIFACT_KEEPER_REPO: ${repoKey}
  IMAGE_NAME: my-application

jobs:
  build-and-push:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to Artifact Keeper
        uses: docker/login-action@v3
        with:
          registry: \${{ env.ARTIFACT_KEEPER_URL }}
          username: \${{ secrets.ARTIFACT_KEEPER_USERNAME }}
          password: \${{ secrets.ARTIFACT_KEEPER_PASSWORD }}

      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: \${{ env.ARTIFACT_KEEPER_URL }}/\${{ env.ARTIFACT_KEEPER_REPO }}/\${{ env.IMAGE_NAME }}
          tags: |
            type=ref,event=branch
            type=ref,event=pr
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}
            type=sha

      - name: Build and push Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          push: \${{ github.event_name != 'pull_request' }}
          tags: \${{ steps.meta.outputs.tags }}
          labels: \${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max`;

  const pypiWorkflow = `name: Python Package Publish

on:
  push:
    branches: [ main ]
  release:
    types: [ published ]

env:
  ARTIFACT_KEEPER_URL: ${baseUrl}
  ARTIFACT_KEEPER_REPO: ${repoKey}

jobs:
  build-and-publish:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install build twine

      - name: Build package
        run: python -m build

      - name: Publish to Artifact Keeper
        if: github.event_name == 'release'
        env:
          TWINE_USERNAME: \${{ secrets.ARTIFACT_KEEPER_USERNAME }}
          TWINE_PASSWORD: \${{ secrets.ARTIFACT_KEEPER_PASSWORD }}
        run: |
          twine upload --repository-url \$ARTIFACT_KEEPER_URL/api/v1/pypi/\$ARTIFACT_KEEPER_REPO/ dist/*`;

  const helmWorkflow = `name: Helm Chart Publish

on:
  push:
    branches: [ main ]
    paths:
      - 'charts/**'
  release:
    types: [ published ]

env:
  ARTIFACT_KEEPER_URL: ${baseUrl}
  ARTIFACT_KEEPER_REPO: ${repoKey}

jobs:
  publish-chart:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Install Helm
        uses: azure/setup-helm@v3
        with:
          version: v3.12.0

      - name: Package Helm chart
        run: |
          helm package charts/my-chart

      - name: Push to Artifact Keeper
        env:
          AK_USERNAME: \${{ secrets.ARTIFACT_KEEPER_USERNAME }}
          AK_PASSWORD: \${{ secrets.ARTIFACT_KEEPER_PASSWORD }}
        run: |
          helm registry login \$ARTIFACT_KEEPER_URL -u \$AK_USERNAME -p \$AK_PASSWORD
          helm push my-chart-*.tgz oci://\$ARTIFACT_KEEPER_URL/\$ARTIFACT_KEEPER_REPO`;

  const getRelevantWorkflow = () => {
    switch (repoFormat) {
      case 'npm':
        return { code: npmWorkflow, name: 'npm' };
      case 'maven':
        return { code: mavenWorkflow, name: 'Maven' };
      case 'docker':
        return { code: dockerWorkflow, name: 'Docker' };
      case 'pypi':
        return { code: pypiWorkflow, name: 'PyPI' };
      case 'helm':
        return { code: helmWorkflow, name: 'Helm' };
      default:
        return { code: genericWorkflow, name: 'generic' };
    }
  };

  const relevantWorkflow = getRelevantWorkflow();

  const collapseItems = [
    {
      key: 'npm',
      label: 'npm Workflow',
      children: <CodeBlock code={npmWorkflow} filename=".github/workflows/npm-publish.yml" />,
    },
    {
      key: 'maven',
      label: 'Maven Workflow',
      children: <CodeBlock code={mavenWorkflow} filename=".github/workflows/maven-build.yml" />,
    },
    {
      key: 'docker',
      label: 'Docker Workflow',
      children: <CodeBlock code={dockerWorkflow} filename=".github/workflows/docker-publish.yml" />,
    },
    {
      key: 'pypi',
      label: 'PyPI Workflow',
      children: <CodeBlock code={pypiWorkflow} filename=".github/workflows/python-publish.yml" />,
    },
    {
      key: 'helm',
      label: 'Helm Workflow',
      children: <CodeBlock code={helmWorkflow} filename=".github/workflows/helm-publish.yml" />,
    },
    {
      key: 'generic',
      label: 'Generic Workflow',
      children: <CodeBlock code={genericWorkflow} filename=".github/workflows/build.yml" />,
    },
  ];

  return (
    <div>
      <Space orientation="vertical" size="large" style={{ width: '100%' }}>
        <div>
          <Title level={5}>
            <KeyOutlined style={{ marginRight: spacing.xs }} />
            Step 1: Configure Repository Secrets
          </Title>
          <Paragraph type="secondary">
            Add your Artifact Keeper credentials as encrypted secrets in your GitHub repository.
          </Paragraph>

          <Alert
            type="info"
            showIcon
            message="Secrets Configuration"
            description={
              <ol style={{ margin: 0, paddingLeft: spacing.lg }}>
                <li>Navigate to your repository on GitHub</li>
                <li>Go to <Text code>Settings &gt; Secrets and variables &gt; Actions</Text></li>
                <li>Click <Text code>New repository secret</Text></li>
                <li>Add <Text code>ARTIFACT_KEEPER_USERNAME</Text> with your username</li>
                <li>Add <Text code>ARTIFACT_KEEPER_PASSWORD</Text> with your API key or password</li>
              </ol>
            }
            style={{ marginBottom: spacing.md }}
          />
        </div>

        <Divider style={{ margin: `${spacing.sm}px 0` }} />

        <div>
          <Title level={5}>
            <FileTextOutlined style={{ marginRight: spacing.xs }} />
            Step 2: Create Workflow File
          </Title>
          <Paragraph type="secondary">
            Create a workflow file in your repository. Below is an example
            {repository && ` configured for your ${relevantWorkflow.name} repository`}.
          </Paragraph>

          <CodeBlock
            code={relevantWorkflow.code}
            filename={`.github/workflows/${repoFormat === 'generic' ? 'build' : repoFormat}-publish.yml`}
          />

          {(!repository || repoFormat === 'generic') && (
            <>
              <Paragraph type="secondary" style={{ marginTop: spacing.md }}>
                Additional workflow examples for different package types:
              </Paragraph>
              <Collapse items={collapseItems} />
            </>
          )}
        </div>

        <Divider style={{ margin: `${spacing.sm}px 0` }} />

        <div>
          <Title level={5}>
            <SettingOutlined style={{ marginRight: spacing.xs }} />
            Step 3: Commit and Push
          </Title>
          <Paragraph type="secondary">
            Commit the workflow file to your repository:
          </Paragraph>

          <CodeBlock
            code={`mkdir -p .github/workflows
# Create your workflow file in .github/workflows/
git add .github/workflows/
git commit -m "Add CI/CD workflow for Artifact Keeper"
git push origin main`}
            language="bash"
            filename="Terminal"
          />
        </div>

        <Divider style={{ margin: `${spacing.sm}px 0` }} />

        <div>
          <Title level={5}>Available Secrets</Title>
          <Paragraph type="secondary">
            The following secrets should be configured in your repository:
          </Paragraph>

          <CodeBlock
            code={`ARTIFACT_KEEPER_USERNAME  # Your Artifact Keeper username
ARTIFACT_KEEPER_PASSWORD  # Your API key or password`}
            language="bash"
            filename="Required Secrets"
          />

          <Alert
            type="warning"
            showIcon
            message="Security Note"
            description="Never commit credentials directly in your workflow files. Always use GitHub Secrets for sensitive values."
            style={{ marginTop: spacing.md }}
          />
        </div>
      </Space>
    </div>
  );
};

export default GitHubActionsSetup;
