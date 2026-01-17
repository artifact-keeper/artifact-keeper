import React from 'react';
import { Typography, Space, Divider, Alert, Collapse } from 'antd';
import { SettingOutlined, KeyOutlined, FileTextOutlined } from '@ant-design/icons';
import { spacing } from '../../../styles/tokens';
import type { Repository } from '../../../types';
import { CodeBlock } from './CICDPlatformWizard';

const { Title, Text, Paragraph } = Typography;

export interface JenkinsSetupProps {
  repository?: Repository;
  baseUrl: string;
}

export const JenkinsSetup: React.FC<JenkinsSetupProps> = ({
  repository,
  baseUrl,
}) => {
  const repoKey = repository?.key || 'my-repo';
  const repoFormat = repository?.format || 'generic';

  const jenkinsfileExample = `pipeline {
    agent any

    environment {
        ARTIFACT_KEEPER_URL = '${baseUrl}'
        ARTIFACT_KEEPER_REPO = '${repoKey}'
    }

    stages {
        stage('Build') {
            steps {
                sh 'echo "Building project..."'
                // Add your build steps here
            }
        }

        stage('Test') {
            steps {
                sh 'echo "Running tests..."'
                // Add your test steps here
            }
        }

        stage('Publish Artifact') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'artifact-keeper-credentials',
                    usernameVariable: 'AK_USERNAME',
                    passwordVariable: 'AK_PASSWORD'
                )]) {
                    sh '''
                        curl -u $AK_USERNAME:$AK_PASSWORD \\
                            -X PUT \\
                            -T ./build/artifact.jar \\
                            $ARTIFACT_KEEPER_URL/api/v1/repos/$ARTIFACT_KEEPER_REPO/artifacts/artifact.jar
                    '''
                }
            }
        }
    }

    post {
        always {
            cleanWs()
        }
    }
}`;

  const npmJenkinsfile = `pipeline {
    agent any

    environment {
        ARTIFACT_KEEPER_URL = '${baseUrl}'
        ARTIFACT_KEEPER_REPO = '${repoKey}'
    }

    stages {
        stage('Install Dependencies') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'artifact-keeper-credentials',
                    usernameVariable: 'AK_USERNAME',
                    passwordVariable: 'AK_PASSWORD'
                )]) {
                    sh '''
                        npm config set registry $ARTIFACT_KEEPER_URL/api/v1/npm/$ARTIFACT_KEEPER_REPO/
                        npm config set //$ARTIFACT_KEEPER_URL/api/v1/npm/$ARTIFACT_KEEPER_REPO/:_authToken $(echo -n $AK_USERNAME:$AK_PASSWORD | base64)
                        npm install
                    '''
                }
            }
        }

        stage('Build') {
            steps {
                sh 'npm run build'
            }
        }

        stage('Test') {
            steps {
                sh 'npm test'
            }
        }

        stage('Publish') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'artifact-keeper-credentials',
                    usernameVariable: 'AK_USERNAME',
                    passwordVariable: 'AK_PASSWORD'
                )]) {
                    sh 'npm publish'
                }
            }
        }
    }
}`;

  const mavenJenkinsfile = `pipeline {
    agent any

    environment {
        ARTIFACT_KEEPER_URL = '${baseUrl}'
        ARTIFACT_KEEPER_REPO = '${repoKey}'
    }

    stages {
        stage('Build') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'artifact-keeper-credentials',
                    usernameVariable: 'AK_USERNAME',
                    passwordVariable: 'AK_PASSWORD'
                )]) {
                    sh '''
                        mvn clean package -DskipTests \\
                            -Dartifact.keeper.url=$ARTIFACT_KEEPER_URL \\
                            -Dartifact.keeper.repo=$ARTIFACT_KEEPER_REPO
                    '''
                }
            }
        }

        stage('Test') {
            steps {
                sh 'mvn test'
            }
        }

        stage('Deploy') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'artifact-keeper-credentials',
                    usernameVariable: 'AK_USERNAME',
                    passwordVariable: 'AK_PASSWORD'
                )]) {
                    sh '''
                        mvn deploy \\
                            -DaltDeploymentRepository=artifact-keeper::default::$ARTIFACT_KEEPER_URL/api/v1/maven/$ARTIFACT_KEEPER_REPO/ \\
                            -Dusername=$AK_USERNAME \\
                            -Dpassword=$AK_PASSWORD
                    '''
                }
            }
        }
    }
}`;

  const dockerJenkinsfile = `pipeline {
    agent any

    environment {
        ARTIFACT_KEEPER_URL = '${baseUrl}'
        ARTIFACT_KEEPER_REPO = '${repoKey}'
        IMAGE_NAME = 'my-application'
        IMAGE_TAG = "\${env.BUILD_NUMBER}"
    }

    stages {
        stage('Build Image') {
            steps {
                sh 'docker build -t $IMAGE_NAME:$IMAGE_TAG .'
            }
        }

        stage('Push to Registry') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'artifact-keeper-credentials',
                    usernameVariable: 'AK_USERNAME',
                    passwordVariable: 'AK_PASSWORD'
                )]) {
                    sh '''
                        echo $AK_PASSWORD | docker login $ARTIFACT_KEEPER_URL -u $AK_USERNAME --password-stdin
                        docker tag $IMAGE_NAME:$IMAGE_TAG $ARTIFACT_KEEPER_URL/$ARTIFACT_KEEPER_REPO/$IMAGE_NAME:$IMAGE_TAG
                        docker tag $IMAGE_NAME:$IMAGE_TAG $ARTIFACT_KEEPER_URL/$ARTIFACT_KEEPER_REPO/$IMAGE_NAME:latest
                        docker push $ARTIFACT_KEEPER_URL/$ARTIFACT_KEEPER_REPO/$IMAGE_NAME:$IMAGE_TAG
                        docker push $ARTIFACT_KEEPER_URL/$ARTIFACT_KEEPER_REPO/$IMAGE_NAME:latest
                    '''
                }
            }
        }
    }

    post {
        always {
            sh 'docker logout $ARTIFACT_KEEPER_URL || true'
        }
    }
}`;

  const getRelevantJenkinsfile = () => {
    switch (repoFormat) {
      case 'npm':
        return { code: npmJenkinsfile, name: 'npm' };
      case 'maven':
        return { code: mavenJenkinsfile, name: 'Maven' };
      case 'docker':
        return { code: dockerJenkinsfile, name: 'Docker' };
      default:
        return { code: jenkinsfileExample, name: 'generic' };
    }
  };

  const relevantPipeline = getRelevantJenkinsfile();

  const collapseItems = [
    {
      key: 'npm',
      label: 'npm Pipeline',
      children: <CodeBlock code={npmJenkinsfile} filename="Jenkinsfile" />,
    },
    {
      key: 'maven',
      label: 'Maven Pipeline',
      children: <CodeBlock code={mavenJenkinsfile} filename="Jenkinsfile" />,
    },
    {
      key: 'docker',
      label: 'Docker Pipeline',
      children: <CodeBlock code={dockerJenkinsfile} filename="Jenkinsfile" />,
    },
    {
      key: 'generic',
      label: 'Generic Pipeline',
      children: <CodeBlock code={jenkinsfileExample} filename="Jenkinsfile" />,
    },
  ];

  return (
    <div>
      <Space orientation="vertical" size="large" style={{ width: '100%' }}>
        <div>
          <Title level={5}>
            <KeyOutlined style={{ marginRight: spacing.xs }} />
            Step 1: Configure Credentials
          </Title>
          <Paragraph type="secondary">
            Create Jenkins credentials to securely store your Artifact Keeper authentication.
          </Paragraph>

          <Alert
            type="info"
            showIcon
            message="Credentials Setup"
            description={
              <ol style={{ margin: 0, paddingLeft: spacing.lg }}>
                <li>Navigate to <Text code>Manage Jenkins &gt; Manage Credentials</Text></li>
                <li>Select the appropriate domain (or Global)</li>
                <li>Click <Text code>Add Credentials</Text></li>
                <li>Choose <Text code>Username with password</Text></li>
                <li>Enter your Artifact Keeper username and API key</li>
                <li>Set ID to <Text code>artifact-keeper-credentials</Text></li>
                <li>Click <Text code>OK</Text> to save</li>
              </ol>
            }
            style={{ marginBottom: spacing.md }}
          />
        </div>

        <Divider style={{ margin: `${spacing.sm}px 0` }} />

        <div>
          <Title level={5}>
            <FileTextOutlined style={{ marginRight: spacing.xs }} />
            Step 2: Create Jenkinsfile
          </Title>
          <Paragraph type="secondary">
            Add a Jenkinsfile to your repository root. Below is an example
            {repository && ` configured for your ${relevantPipeline.name} repository`}.
          </Paragraph>

          <CodeBlock code={relevantPipeline.code} filename="Jenkinsfile" />

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
            Step 3: Configure Jenkins Pipeline
          </Title>
          <Paragraph type="secondary">
            Set up a new Pipeline job in Jenkins:
          </Paragraph>

          <ol style={{ paddingLeft: spacing.lg }}>
            <li>Navigate to <Text code>New Item</Text> in Jenkins</li>
            <li>Enter a name and select <Text code>Pipeline</Text></li>
            <li>Under Pipeline section, choose <Text code>Pipeline script from SCM</Text></li>
            <li>Configure your source code repository</li>
            <li>Set the Script Path to <Text code>Jenkinsfile</Text></li>
            <li>Save and run the pipeline</li>
          </ol>
        </div>

        <Divider style={{ margin: `${spacing.sm}px 0` }} />

        <div>
          <Title level={5}>Environment Variables</Title>
          <Paragraph type="secondary">
            The following environment variables are available in your pipeline:
          </Paragraph>

          <CodeBlock
            code={`ARTIFACT_KEEPER_URL=${baseUrl}
ARTIFACT_KEEPER_REPO=${repoKey}
AK_USERNAME=<your-username>
AK_PASSWORD=<your-api-key>`}
            language="bash"
            filename="Environment Variables"
          />
        </div>
      </Space>
    </div>
  );
};

export default JenkinsSetup;
