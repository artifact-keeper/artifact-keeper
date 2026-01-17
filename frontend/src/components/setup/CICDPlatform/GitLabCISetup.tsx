import React from 'react';
import { Typography, Space, Divider, Alert, Collapse } from 'antd';
import { SettingOutlined, KeyOutlined, FileTextOutlined } from '@ant-design/icons';
import { spacing } from '../../../styles/tokens';
import type { Repository } from '../../../types';
import { CodeBlock } from './CICDPlatformWizard';

const { Title, Text, Paragraph } = Typography;

export interface GitLabCISetupProps {
  repository?: Repository;
  baseUrl: string;
}

export const GitLabCISetup: React.FC<GitLabCISetupProps> = ({
  repository,
  baseUrl,
}) => {
  const repoKey = repository?.key || 'my-repo';
  const repoFormat = repository?.format || 'generic';

  const genericGitLabCI = `stages:
  - build
  - test
  - publish

variables:
  ARTIFACT_KEEPER_URL: ${baseUrl}
  ARTIFACT_KEEPER_REPO: ${repoKey}

build:
  stage: build
  script:
    - echo "Building project..."
    # Add your build steps here

test:
  stage: test
  script:
    - echo "Running tests..."
    # Add your test steps here

publish:
  stage: publish
  script:
    - |
      curl -u $ARTIFACT_KEEPER_USERNAME:$ARTIFACT_KEEPER_PASSWORD \\
        -X PUT \\
        -T ./build/artifact.jar \\
        $ARTIFACT_KEEPER_URL/api/v1/repos/$ARTIFACT_KEEPER_REPO/artifacts/artifact.jar
  only:
    - main
    - tags`;

  const npmGitLabCI = `stages:
  - install
  - build
  - test
  - publish

variables:
  ARTIFACT_KEEPER_URL: ${baseUrl}
  ARTIFACT_KEEPER_REPO: ${repoKey}

.npm_setup: &npm_setup
  before_script:
    - npm config set registry $ARTIFACT_KEEPER_URL/api/v1/npm/$ARTIFACT_KEEPER_REPO/
    - echo "//$\{ARTIFACT_KEEPER_URL#https://}/api/v1/npm/$ARTIFACT_KEEPER_REPO/:_auth=$(echo -n $ARTIFACT_KEEPER_USERNAME:$ARTIFACT_KEEPER_PASSWORD | base64)" >> ~/.npmrc

install:
  stage: install
  image: node:20
  <<: *npm_setup
  script:
    - npm ci
  cache:
    key: $CI_COMMIT_REF_SLUG
    paths:
      - node_modules/

build:
  stage: build
  image: node:20
  script:
    - npm run build
  cache:
    key: $CI_COMMIT_REF_SLUG
    paths:
      - node_modules/

test:
  stage: test
  image: node:20
  script:
    - npm test
  cache:
    key: $CI_COMMIT_REF_SLUG
    paths:
      - node_modules/

publish:
  stage: publish
  image: node:20
  <<: *npm_setup
  script:
    - npm publish
  only:
    - tags`;

  const mavenGitLabCI = `stages:
  - build
  - test
  - deploy

variables:
  ARTIFACT_KEEPER_URL: ${baseUrl}
  ARTIFACT_KEEPER_REPO: ${repoKey}
  MAVEN_OPTS: "-Dmaven.repo.local=$CI_PROJECT_DIR/.m2/repository"

.maven_setup: &maven_setup
  before_script:
    - |
      mkdir -p ~/.m2
      cat > ~/.m2/settings.xml << EOF
      <settings>
        <servers>
          <server>
            <id>artifact-keeper</id>
            <username>$ARTIFACT_KEEPER_USERNAME</username>
            <password>$ARTIFACT_KEEPER_PASSWORD</password>
          </server>
        </servers>
      </settings>
      EOF

build:
  stage: build
  image: maven:3.9-eclipse-temurin-17
  <<: *maven_setup
  script:
    - mvn clean package -DskipTests
  cache:
    key: $CI_COMMIT_REF_SLUG
    paths:
      - .m2/repository
  artifacts:
    paths:
      - target/*.jar

test:
  stage: test
  image: maven:3.9-eclipse-temurin-17
  script:
    - mvn test
  cache:
    key: $CI_COMMIT_REF_SLUG
    paths:
      - .m2/repository

deploy:
  stage: deploy
  image: maven:3.9-eclipse-temurin-17
  <<: *maven_setup
  script:
    - mvn deploy -DaltDeploymentRepository=artifact-keeper::default::$ARTIFACT_KEEPER_URL/api/v1/maven/$ARTIFACT_KEEPER_REPO/
  only:
    - tags`;

  const dockerGitLabCI = `stages:
  - build
  - push

variables:
  ARTIFACT_KEEPER_URL: ${baseUrl}
  ARTIFACT_KEEPER_REPO: ${repoKey}
  IMAGE_NAME: my-application

build:
  stage: build
  image: docker:24
  services:
    - docker:24-dind
  variables:
    DOCKER_TLS_CERTDIR: "/certs"
  script:
    - docker build -t $IMAGE_NAME:$CI_COMMIT_SHA .
    - docker tag $IMAGE_NAME:$CI_COMMIT_SHA $IMAGE_NAME:$CI_COMMIT_REF_SLUG
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
    - if: $CI_COMMIT_TAG

push:
  stage: push
  image: docker:24
  services:
    - docker:24-dind
  variables:
    DOCKER_TLS_CERTDIR: "/certs"
  before_script:
    - echo $ARTIFACT_KEEPER_PASSWORD | docker login $ARTIFACT_KEEPER_URL -u $ARTIFACT_KEEPER_USERNAME --password-stdin
  script:
    - docker build -t $ARTIFACT_KEEPER_URL/$ARTIFACT_KEEPER_REPO/$IMAGE_NAME:$CI_COMMIT_SHA .
    - docker push $ARTIFACT_KEEPER_URL/$ARTIFACT_KEEPER_REPO/$IMAGE_NAME:$CI_COMMIT_SHA
    - |
      if [ -n "$CI_COMMIT_TAG" ]; then
        docker tag $ARTIFACT_KEEPER_URL/$ARTIFACT_KEEPER_REPO/$IMAGE_NAME:$CI_COMMIT_SHA $ARTIFACT_KEEPER_URL/$ARTIFACT_KEEPER_REPO/$IMAGE_NAME:$CI_COMMIT_TAG
        docker push $ARTIFACT_KEEPER_URL/$ARTIFACT_KEEPER_REPO/$IMAGE_NAME:$CI_COMMIT_TAG
      fi
    - |
      if [ "$CI_COMMIT_BRANCH" == "$CI_DEFAULT_BRANCH" ]; then
        docker tag $ARTIFACT_KEEPER_URL/$ARTIFACT_KEEPER_REPO/$IMAGE_NAME:$CI_COMMIT_SHA $ARTIFACT_KEEPER_URL/$ARTIFACT_KEEPER_REPO/$IMAGE_NAME:latest
        docker push $ARTIFACT_KEEPER_URL/$ARTIFACT_KEEPER_REPO/$IMAGE_NAME:latest
      fi
  after_script:
    - docker logout $ARTIFACT_KEEPER_URL || true
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
    - if: $CI_COMMIT_TAG`;

  const pypiGitLabCI = `stages:
  - build
  - test
  - publish

variables:
  ARTIFACT_KEEPER_URL: ${baseUrl}
  ARTIFACT_KEEPER_REPO: ${repoKey}

build:
  stage: build
  image: python:3.11
  script:
    - pip install build
    - python -m build
  artifacts:
    paths:
      - dist/

test:
  stage: test
  image: python:3.11
  script:
    - pip install pytest
    - pip install -e .
    - pytest

publish:
  stage: publish
  image: python:3.11
  script:
    - pip install twine
    - |
      twine upload \\
        --repository-url $ARTIFACT_KEEPER_URL/api/v1/pypi/$ARTIFACT_KEEPER_REPO/ \\
        -u $ARTIFACT_KEEPER_USERNAME \\
        -p $ARTIFACT_KEEPER_PASSWORD \\
        dist/*
  only:
    - tags`;

  const helmGitLabCI = `stages:
  - lint
  - package
  - publish

variables:
  ARTIFACT_KEEPER_URL: ${baseUrl}
  ARTIFACT_KEEPER_REPO: ${repoKey}
  CHART_PATH: charts/my-chart

lint:
  stage: lint
  image:
    name: alpine/helm:3.12.0
    entrypoint: [""]
  script:
    - helm lint $CHART_PATH

package:
  stage: package
  image:
    name: alpine/helm:3.12.0
    entrypoint: [""]
  script:
    - helm package $CHART_PATH
  artifacts:
    paths:
      - "*.tgz"

publish:
  stage: publish
  image:
    name: alpine/helm:3.12.0
    entrypoint: [""]
  before_script:
    - helm registry login $ARTIFACT_KEEPER_URL -u $ARTIFACT_KEEPER_USERNAME -p $ARTIFACT_KEEPER_PASSWORD
  script:
    - helm push *.tgz oci://$ARTIFACT_KEEPER_URL/$ARTIFACT_KEEPER_REPO
  after_script:
    - helm registry logout $ARTIFACT_KEEPER_URL || true
  only:
    - tags`;

  const getRelevantConfig = () => {
    switch (repoFormat) {
      case 'npm':
        return { code: npmGitLabCI, name: 'npm' };
      case 'maven':
        return { code: mavenGitLabCI, name: 'Maven' };
      case 'docker':
        return { code: dockerGitLabCI, name: 'Docker' };
      case 'pypi':
        return { code: pypiGitLabCI, name: 'PyPI' };
      case 'helm':
        return { code: helmGitLabCI, name: 'Helm' };
      default:
        return { code: genericGitLabCI, name: 'generic' };
    }
  };

  const relevantConfig = getRelevantConfig();

  const collapseItems = [
    {
      key: 'npm',
      label: 'npm Configuration',
      children: <CodeBlock code={npmGitLabCI} filename=".gitlab-ci.yml" />,
    },
    {
      key: 'maven',
      label: 'Maven Configuration',
      children: <CodeBlock code={mavenGitLabCI} filename=".gitlab-ci.yml" />,
    },
    {
      key: 'docker',
      label: 'Docker Configuration',
      children: <CodeBlock code={dockerGitLabCI} filename=".gitlab-ci.yml" />,
    },
    {
      key: 'pypi',
      label: 'PyPI Configuration',
      children: <CodeBlock code={pypiGitLabCI} filename=".gitlab-ci.yml" />,
    },
    {
      key: 'helm',
      label: 'Helm Configuration',
      children: <CodeBlock code={helmGitLabCI} filename=".gitlab-ci.yml" />,
    },
    {
      key: 'generic',
      label: 'Generic Configuration',
      children: <CodeBlock code={genericGitLabCI} filename=".gitlab-ci.yml" />,
    },
  ];

  return (
    <div>
      <Space orientation="vertical" size="large" style={{ width: '100%' }}>
        <div>
          <Title level={5}>
            <KeyOutlined style={{ marginRight: spacing.xs }} />
            Step 1: Configure CI/CD Variables
          </Title>
          <Paragraph type="secondary">
            Add your Artifact Keeper credentials as CI/CD variables in your GitLab project.
          </Paragraph>

          <Alert
            type="info"
            showIcon
            message="Variables Configuration"
            description={
              <ol style={{ margin: 0, paddingLeft: spacing.lg }}>
                <li>Navigate to your project in GitLab</li>
                <li>Go to <Text code>Settings &gt; CI/CD &gt; Variables</Text></li>
                <li>Click <Text code>Add variable</Text></li>
                <li>Add <Text code>ARTIFACT_KEEPER_USERNAME</Text> (masked, protected)</li>
                <li>Add <Text code>ARTIFACT_KEEPER_PASSWORD</Text> (masked, protected)</li>
                <li>Optionally set the environment scope</li>
              </ol>
            }
            style={{ marginBottom: spacing.md }}
          />
        </div>

        <Divider style={{ margin: `${spacing.sm}px 0` }} />

        <div>
          <Title level={5}>
            <FileTextOutlined style={{ marginRight: spacing.xs }} />
            Step 2: Create .gitlab-ci.yml
          </Title>
          <Paragraph type="secondary">
            Add a <Text code>.gitlab-ci.yml</Text> file to your repository root. Below is an example
            {repository && ` configured for your ${relevantConfig.name} repository`}.
          </Paragraph>

          <CodeBlock code={relevantConfig.code} filename=".gitlab-ci.yml" />

          {(!repository || repoFormat === 'generic') && (
            <>
              <Paragraph type="secondary" style={{ marginTop: spacing.md }}>
                Additional configuration examples for different package types:
              </Paragraph>
              <Collapse items={collapseItems} />
            </>
          )}
        </div>

        <Divider style={{ margin: `${spacing.sm}px 0` }} />

        <div>
          <Title level={5}>
            <SettingOutlined style={{ marginRight: spacing.xs }} />
            Step 3: Job Templates
          </Title>
          <Paragraph type="secondary">
            GitLab CI supports reusable job templates. Here are some useful templates:
          </Paragraph>

          <CodeBlock
            code={`.artifact_keeper_auth: &artifact_keeper_auth
  before_script:
    - |
      # Set up authentication based on package type
      case "$PACKAGE_TYPE" in
        npm)
          npm config set registry $ARTIFACT_KEEPER_URL/api/v1/npm/$ARTIFACT_KEEPER_REPO/
          echo "//$\{ARTIFACT_KEEPER_URL#https://}/api/v1/npm/$ARTIFACT_KEEPER_REPO/:_auth=$(echo -n $ARTIFACT_KEEPER_USERNAME:$ARTIFACT_KEEPER_PASSWORD | base64)" >> ~/.npmrc
          ;;
        docker)
          echo $ARTIFACT_KEEPER_PASSWORD | docker login $ARTIFACT_KEEPER_URL -u $ARTIFACT_KEEPER_USERNAME --password-stdin
          ;;
        helm)
          helm registry login $ARTIFACT_KEEPER_URL -u $ARTIFACT_KEEPER_USERNAME -p $ARTIFACT_KEEPER_PASSWORD
          ;;
      esac

.publish_artifact:
  stage: publish
  <<: *artifact_keeper_auth
  script:
    - echo "Publish logic here"
  only:
    - tags
  when: manual`}
            filename="Job Templates"
          />
        </div>

        <Divider style={{ margin: `${spacing.sm}px 0` }} />

        <div>
          <Title level={5}>Required Variables</Title>
          <Paragraph type="secondary">
            The following CI/CD variables should be configured in your project:
          </Paragraph>

          <CodeBlock
            code={`ARTIFACT_KEEPER_USERNAME  # Your Artifact Keeper username (masked, protected)
ARTIFACT_KEEPER_PASSWORD  # Your API key or password (masked, protected)`}
            language="bash"
            filename="Required Variables"
          />

          <Alert
            type="warning"
            showIcon
            message="Security Note"
            description={
              <>
                Always mark sensitive variables as <Text code>Masked</Text> and <Text code>Protected</Text>.
                Consider using <Text code>Protect variable</Text> to only expose them on protected branches.
              </>
            }
            style={{ marginTop: spacing.md }}
          />
        </div>
      </Space>
    </div>
  );
};

export default GitLabCISetup;
