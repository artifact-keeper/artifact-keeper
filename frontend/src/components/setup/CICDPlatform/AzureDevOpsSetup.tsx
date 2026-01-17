import React from 'react';
import { Typography, Space, Divider, Alert, Collapse } from 'antd';
import { SettingOutlined, KeyOutlined, FileTextOutlined, ApiOutlined } from '@ant-design/icons';
import { spacing } from '../../../styles/tokens';
import type { Repository } from '../../../types';
import { CodeBlock } from './CICDPlatformWizard';

const { Title, Text, Paragraph } = Typography;

export interface AzureDevOpsSetupProps {
  repository?: Repository;
  baseUrl: string;
}

export const AzureDevOpsSetup: React.FC<AzureDevOpsSetupProps> = ({
  repository,
  baseUrl,
}) => {
  const repoKey = repository?.key || 'my-repo';
  const repoFormat = repository?.format || 'generic';

  const genericAzurePipeline = `trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

variables:
  ARTIFACT_KEEPER_URL: '${baseUrl}'
  ARTIFACT_KEEPER_REPO: '${repoKey}'

stages:
  - stage: Build
    jobs:
      - job: BuildJob
        steps:
          - script: |
              echo "Building project..."
              # Add your build steps here
            displayName: 'Build'

  - stage: Test
    jobs:
      - job: TestJob
        steps:
          - script: |
              echo "Running tests..."
              # Add your test steps here
            displayName: 'Test'

  - stage: Publish
    condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
    jobs:
      - job: PublishJob
        steps:
          - task: Bash@3
            inputs:
              targetType: 'inline'
              script: |
                curl -u $(ARTIFACT_KEEPER_USERNAME):$(ARTIFACT_KEEPER_PASSWORD) \\
                  -X PUT \\
                  -T ./build/artifact.jar \\
                  $(ARTIFACT_KEEPER_URL)/api/v1/repos/$(ARTIFACT_KEEPER_REPO)/artifacts/artifact.jar
            displayName: 'Publish to Artifact Keeper'`;

  const npmAzurePipeline = `trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

variables:
  ARTIFACT_KEEPER_URL: '${baseUrl}'
  ARTIFACT_KEEPER_REPO: '${repoKey}'

stages:
  - stage: Build
    jobs:
      - job: BuildJob
        steps:
          - task: NodeTool@0
            inputs:
              versionSpec: '20.x'
            displayName: 'Install Node.js'

          - task: Bash@3
            inputs:
              targetType: 'inline'
              script: |
                npm config set registry $(ARTIFACT_KEEPER_URL)/api/v1/npm/$(ARTIFACT_KEEPER_REPO)/
                echo "//\${ARTIFACT_KEEPER_URL#https://}/api/v1/npm/$(ARTIFACT_KEEPER_REPO)/:_auth=$(echo -n $(ARTIFACT_KEEPER_USERNAME):$(ARTIFACT_KEEPER_PASSWORD) | base64)" >> ~/.npmrc
            displayName: 'Configure npm registry'

          - script: npm ci
            displayName: 'Install dependencies'

          - script: npm run build
            displayName: 'Build'

          - script: npm test
            displayName: 'Test'

  - stage: Publish
    condition: and(succeeded(), startsWith(variables['Build.SourceBranch'], 'refs/tags/'))
    jobs:
      - job: PublishJob
        steps:
          - task: NodeTool@0
            inputs:
              versionSpec: '20.x'

          - task: Bash@3
            inputs:
              targetType: 'inline'
              script: |
                npm config set registry $(ARTIFACT_KEEPER_URL)/api/v1/npm/$(ARTIFACT_KEEPER_REPO)/
                echo "//\${ARTIFACT_KEEPER_URL#https://}/api/v1/npm/$(ARTIFACT_KEEPER_REPO)/:_auth=$(echo -n $(ARTIFACT_KEEPER_USERNAME):$(ARTIFACT_KEEPER_PASSWORD) | base64)" >> ~/.npmrc
                npm publish
            displayName: 'Publish to Artifact Keeper'`;

  const mavenAzurePipeline = `trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

variables:
  ARTIFACT_KEEPER_URL: '${baseUrl}'
  ARTIFACT_KEEPER_REPO: '${repoKey}'
  MAVEN_CACHE_FOLDER: $(Pipeline.Workspace)/.m2/repository

stages:
  - stage: Build
    jobs:
      - job: BuildJob
        steps:
          - task: Maven@3
            inputs:
              mavenPomFile: 'pom.xml'
              goals: 'clean package'
              options: '-DskipTests'
              javaHomeOption: 'JDKVersion'
              jdkVersionOption: '1.17'
            displayName: 'Maven Build'

          - task: Maven@3
            inputs:
              mavenPomFile: 'pom.xml'
              goals: 'test'
              javaHomeOption: 'JDKVersion'
              jdkVersionOption: '1.17'
            displayName: 'Maven Test'

  - stage: Deploy
    condition: and(succeeded(), startsWith(variables['Build.SourceBranch'], 'refs/tags/'))
    jobs:
      - job: DeployJob
        steps:
          - task: Bash@3
            inputs:
              targetType: 'inline'
              script: |
                mkdir -p ~/.m2
                cat > ~/.m2/settings.xml << EOF
                <settings>
                  <servers>
                    <server>
                      <id>artifact-keeper</id>
                      <username>$(ARTIFACT_KEEPER_USERNAME)</username>
                      <password>$(ARTIFACT_KEEPER_PASSWORD)</password>
                    </server>
                  </servers>
                </settings>
                EOF
            displayName: 'Configure Maven settings'

          - task: Maven@3
            inputs:
              mavenPomFile: 'pom.xml'
              goals: 'deploy'
              options: '-DaltDeploymentRepository=artifact-keeper::default::$(ARTIFACT_KEEPER_URL)/api/v1/maven/$(ARTIFACT_KEEPER_REPO)/'
              javaHomeOption: 'JDKVersion'
              jdkVersionOption: '1.17'
            displayName: 'Deploy to Artifact Keeper'`;

  const dockerAzurePipeline = `trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

variables:
  ARTIFACT_KEEPER_URL: '${baseUrl}'
  ARTIFACT_KEEPER_REPO: '${repoKey}'
  IMAGE_NAME: 'my-application'

stages:
  - stage: Build
    jobs:
      - job: BuildJob
        steps:
          - task: Docker@2
            inputs:
              command: 'build'
              Dockerfile: '**/Dockerfile'
              tags: |
                $(Build.BuildId)
                latest
            displayName: 'Build Docker image'

  - stage: Push
    condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
    jobs:
      - job: PushJob
        steps:
          - task: Docker@2
            inputs:
              containerRegistry: 'artifact-keeper-connection'
              repository: '$(ARTIFACT_KEEPER_REPO)/$(IMAGE_NAME)'
              command: 'buildAndPush'
              Dockerfile: '**/Dockerfile'
              tags: |
                $(Build.BuildId)
                $(Build.SourceVersion)
                latest
            displayName: 'Build and Push to Artifact Keeper'`;

  const nugetAzurePipeline = `trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

variables:
  ARTIFACT_KEEPER_URL: '${baseUrl}'
  ARTIFACT_KEEPER_REPO: '${repoKey}'
  buildConfiguration: 'Release'

stages:
  - stage: Build
    jobs:
      - job: BuildJob
        steps:
          - task: DotNetCoreCLI@2
            inputs:
              command: 'restore'
              projects: '**/*.csproj'
              feedsToUse: 'config'
              nugetConfigPath: 'nuget.config'
            displayName: 'Restore packages'

          - task: DotNetCoreCLI@2
            inputs:
              command: 'build'
              projects: '**/*.csproj'
              arguments: '--configuration $(buildConfiguration)'
            displayName: 'Build'

          - task: DotNetCoreCLI@2
            inputs:
              command: 'test'
              projects: '**/*Tests/*.csproj'
              arguments: '--configuration $(buildConfiguration)'
            displayName: 'Test'

  - stage: Publish
    condition: and(succeeded(), startsWith(variables['Build.SourceBranch'], 'refs/tags/'))
    jobs:
      - job: PublishJob
        steps:
          - task: DotNetCoreCLI@2
            inputs:
              command: 'pack'
              projects: '**/*.csproj'
              arguments: '--configuration $(buildConfiguration) --output $(Build.ArtifactStagingDirectory)'
            displayName: 'Pack NuGet package'

          - task: NuGetCommand@2
            inputs:
              command: 'push'
              packagesToPush: '$(Build.ArtifactStagingDirectory)/**/*.nupkg'
              nuGetFeedType: 'external'
              publishFeedCredentials: 'artifact-keeper-nuget'
            displayName: 'Push to Artifact Keeper'`;

  const helmAzurePipeline = `trigger:
  - main
  paths:
    include:
      - charts/*

pool:
  vmImage: 'ubuntu-latest'

variables:
  ARTIFACT_KEEPER_URL: '${baseUrl}'
  ARTIFACT_KEEPER_REPO: '${repoKey}'
  CHART_PATH: 'charts/my-chart'

stages:
  - stage: Lint
    jobs:
      - job: LintJob
        steps:
          - task: HelmInstaller@1
            inputs:
              helmVersionToInstall: '3.12.0'
            displayName: 'Install Helm'

          - script: helm lint $(CHART_PATH)
            displayName: 'Lint Helm chart'

  - stage: Package
    jobs:
      - job: PackageJob
        steps:
          - task: HelmInstaller@1
            inputs:
              helmVersionToInstall: '3.12.0'

          - script: helm package $(CHART_PATH)
            displayName: 'Package Helm chart'

          - task: PublishPipelineArtifact@1
            inputs:
              targetPath: '$(System.DefaultWorkingDirectory)/*.tgz'
              artifactName: 'helm-chart'

  - stage: Publish
    condition: and(succeeded(), startsWith(variables['Build.SourceBranch'], 'refs/tags/'))
    jobs:
      - job: PublishJob
        steps:
          - task: DownloadPipelineArtifact@2
            inputs:
              artifactName: 'helm-chart'
              targetPath: '$(System.DefaultWorkingDirectory)'

          - task: HelmInstaller@1
            inputs:
              helmVersionToInstall: '3.12.0'

          - task: Bash@3
            inputs:
              targetType: 'inline'
              script: |
                helm registry login $(ARTIFACT_KEEPER_URL) -u $(ARTIFACT_KEEPER_USERNAME) -p $(ARTIFACT_KEEPER_PASSWORD)
                helm push *.tgz oci://$(ARTIFACT_KEEPER_URL)/$(ARTIFACT_KEEPER_REPO)
                helm registry logout $(ARTIFACT_KEEPER_URL) || true
            displayName: 'Push to Artifact Keeper'`;

  const getRelevantPipeline = () => {
    switch (repoFormat) {
      case 'npm':
        return { code: npmAzurePipeline, name: 'npm' };
      case 'maven':
        return { code: mavenAzurePipeline, name: 'Maven' };
      case 'docker':
        return { code: dockerAzurePipeline, name: 'Docker' };
      case 'nuget':
        return { code: nugetAzurePipeline, name: 'NuGet' };
      case 'helm':
        return { code: helmAzurePipeline, name: 'Helm' };
      default:
        return { code: genericAzurePipeline, name: 'generic' };
    }
  };

  const relevantPipeline = getRelevantPipeline();

  const collapseItems = [
    {
      key: 'npm',
      label: 'npm Pipeline',
      children: <CodeBlock code={npmAzurePipeline} filename="azure-pipelines.yml" />,
    },
    {
      key: 'maven',
      label: 'Maven Pipeline',
      children: <CodeBlock code={mavenAzurePipeline} filename="azure-pipelines.yml" />,
    },
    {
      key: 'docker',
      label: 'Docker Pipeline',
      children: <CodeBlock code={dockerAzurePipeline} filename="azure-pipelines.yml" />,
    },
    {
      key: 'nuget',
      label: 'NuGet Pipeline',
      children: <CodeBlock code={nugetAzurePipeline} filename="azure-pipelines.yml" />,
    },
    {
      key: 'helm',
      label: 'Helm Pipeline',
      children: <CodeBlock code={helmAzurePipeline} filename="azure-pipelines.yml" />,
    },
    {
      key: 'generic',
      label: 'Generic Pipeline',
      children: <CodeBlock code={genericAzurePipeline} filename="azure-pipelines.yml" />,
    },
  ];

  return (
    <div>
      <Space orientation="vertical" size="large" style={{ width: '100%' }}>
        <div>
          <Title level={5}>
            <ApiOutlined style={{ marginRight: spacing.xs }} />
            Step 1: Create Service Connection
          </Title>
          <Paragraph type="secondary">
            Create a service connection to authenticate with Artifact Keeper.
          </Paragraph>

          <Alert
            type="info"
            showIcon
            message="Service Connection Setup"
            description={
              <ol style={{ margin: 0, paddingLeft: spacing.lg }}>
                <li>Navigate to <Text code>Project Settings &gt; Service connections</Text></li>
                <li>Click <Text code>New service connection</Text></li>
                <li>For Docker: Select <Text code>Docker Registry</Text></li>
                <li>For NuGet: Select <Text code>NuGet</Text></li>
                <li>For others: Select <Text code>Generic</Text></li>
                <li>Enter your Artifact Keeper URL: <Text code>{baseUrl}</Text></li>
                <li>Enter your credentials and save</li>
              </ol>
            }
            style={{ marginBottom: spacing.md }}
          />
        </div>

        <Divider style={{ margin: `${spacing.sm}px 0` }} />

        <div>
          <Title level={5}>
            <KeyOutlined style={{ marginRight: spacing.xs }} />
            Step 2: Configure Pipeline Variables
          </Title>
          <Paragraph type="secondary">
            Add pipeline variables for authentication.
          </Paragraph>

          <Alert
            type="info"
            showIcon
            message="Variable Configuration"
            description={
              <ol style={{ margin: 0, paddingLeft: spacing.lg }}>
                <li>Navigate to <Text code>Pipelines &gt; Library</Text></li>
                <li>Create a new variable group named <Text code>artifact-keeper-credentials</Text></li>
                <li>Add <Text code>ARTIFACT_KEEPER_USERNAME</Text> with your username</li>
                <li>Add <Text code>ARTIFACT_KEEPER_PASSWORD</Text> (mark as secret)</li>
                <li>Save the variable group</li>
                <li>Link the variable group to your pipeline</li>
              </ol>
            }
            style={{ marginBottom: spacing.md }}
          />

          <CodeBlock
            code={`# Link variable group in your pipeline
variables:
  - group: artifact-keeper-credentials
  - name: ARTIFACT_KEEPER_URL
    value: '${baseUrl}'
  - name: ARTIFACT_KEEPER_REPO
    value: '${repoKey}'`}
            filename="Variable Group Reference"
          />
        </div>

        <Divider style={{ margin: `${spacing.sm}px 0` }} />

        <div>
          <Title level={5}>
            <FileTextOutlined style={{ marginRight: spacing.xs }} />
            Step 3: Create azure-pipelines.yml
          </Title>
          <Paragraph type="secondary">
            Add an <Text code>azure-pipelines.yml</Text> file to your repository root. Below is an example
            {repository && ` configured for your ${relevantPipeline.name} repository`}.
          </Paragraph>

          <CodeBlock code={relevantPipeline.code} filename="azure-pipelines.yml" />

          {(!repository || repoFormat === 'generic') && (
            <>
              <Paragraph type="secondary" style={{ marginTop: spacing.md }}>
                Additional pipeline examples for different package types:
              </Paragraph>
              <Collapse items={collapseItems} />
            </>
          )}
        </div>

        <Divider style={{ margin: `${spacing.sm}px 0` }} />

        <div>
          <Title level={5}>
            <SettingOutlined style={{ marginRight: spacing.xs }} />
            Step 4: Azure DevOps Tasks
          </Title>
          <Paragraph type="secondary">
            Common Azure DevOps tasks for artifact management:
          </Paragraph>

          <CodeBlock
            code={`# Download from Artifact Keeper
- task: Bash@3
  inputs:
    targetType: 'inline'
    script: |
      curl -u $(ARTIFACT_KEEPER_USERNAME):$(ARTIFACT_KEEPER_PASSWORD) \\
        -O $(ARTIFACT_KEEPER_URL)/api/v1/repos/$(ARTIFACT_KEEPER_REPO)/artifacts/path/to/artifact.jar
  displayName: 'Download Artifact'

# Upload to Artifact Keeper
- task: Bash@3
  inputs:
    targetType: 'inline'
    script: |
      curl -u $(ARTIFACT_KEEPER_USERNAME):$(ARTIFACT_KEEPER_PASSWORD) \\
        -X PUT \\
        -T ./build/artifact.jar \\
        $(ARTIFACT_KEEPER_URL)/api/v1/repos/$(ARTIFACT_KEEPER_REPO)/artifacts/artifact.jar
  displayName: 'Upload Artifact'

# Docker login and push
- task: Docker@2
  inputs:
    containerRegistry: 'artifact-keeper-connection'
    repository: '$(ARTIFACT_KEEPER_REPO)/my-image'
    command: 'buildAndPush'
    Dockerfile: '**/Dockerfile'
    tags: '$(Build.BuildId)'`}
            filename="Common Tasks"
          />
        </div>

        <Divider style={{ margin: `${spacing.sm}px 0` }} />

        <div>
          <Title level={5}>Required Configuration</Title>
          <Paragraph type="secondary">
            Summary of required configuration items:
          </Paragraph>

          <CodeBlock
            code={`# Service Connections (Project Settings > Service connections)
- artifact-keeper-connection     # Docker Registry or Generic
- artifact-keeper-nuget          # NuGet (if applicable)

# Variable Group (Pipelines > Library)
Group: artifact-keeper-credentials
  - ARTIFACT_KEEPER_USERNAME     # Your username
  - ARTIFACT_KEEPER_PASSWORD     # Your API key (secret)`}
            language="bash"
            filename="Required Configuration"
          />

          <Alert
            type="warning"
            showIcon
            message="Security Note"
            description="Always mark sensitive variables as secret. Use service connections where possible for better security management."
            style={{ marginTop: spacing.md }}
          />
        </div>
      </Space>
    </div>
  );
};

export default AzureDevOpsSetup;
