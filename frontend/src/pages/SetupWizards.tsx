import { useState } from 'react'
import { Card, Row, Col, Typography, Button, Space, Tabs } from 'antd'
import {
  CodeOutlined,
  RocketOutlined,
  ToolOutlined,
  GithubOutlined,
  GitlabOutlined,
} from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { repositoriesApi } from '../api'
import { useDocumentTitle } from '../hooks'
import { PackageManagerWizard, CICDPlatformWizard } from '../components/setup'
import type { Repository } from '../types'
import { colors, spacing } from '../styles/tokens'

const { Title, Text, Paragraph } = Typography

interface SetupCardProps {
  title: string
  description: string
  icon: React.ReactNode
  onClick: () => void
}

const SetupCard = ({ title, description, icon, onClick }: SetupCardProps) => (
  <Card
    hoverable
    onClick={onClick}
    style={{ height: '100%' }}
    styles={{ body: { display: 'flex', flexDirection: 'column', height: '100%' } }}
  >
    <div style={{ textAlign: 'center', marginBottom: spacing.md }}>
      <div style={{ fontSize: 48, color: colors.primary, marginBottom: spacing.sm }}>
        {icon}
      </div>
      <Title level={4} style={{ margin: 0 }}>{title}</Title>
    </div>
    <Paragraph type="secondary" style={{ flex: 1, textAlign: 'center' }}>
      {description}
    </Paragraph>
    <Button type="primary" block>
      Get Started
    </Button>
  </Card>
)

const SetupWizards = () => {
  useDocumentTitle('Set Me Up')

  const [packageManagerOpen, setPackageManagerOpen] = useState(false)
  const [cicdPlatformOpen, setCicdPlatformOpen] = useState(false)
  const [selectedRepository, setSelectedRepository] = useState<Repository | undefined>()

  const { data: repositoriesData } = useQuery({
    queryKey: ['repositories'],
    queryFn: () => repositoriesApi.list({ per_page: 100 }),
  })

  const repositories = repositoriesData?.items ?? []

  const handlePackageManagerClick = (repo?: Repository) => {
    setSelectedRepository(repo)
    setPackageManagerOpen(true)
  }

  const handleCICDClick = (repo?: Repository) => {
    setSelectedRepository(repo)
    setCicdPlatformOpen(true)
  }

  const packageManagerFormats = [
    { key: 'maven', name: 'Maven', icon: <CodeOutlined />, description: 'Java/JVM artifacts' },
    { key: 'npm', name: 'npm', icon: <CodeOutlined />, description: 'Node.js packages' },
    { key: 'docker', name: 'Docker', icon: <CodeOutlined />, description: 'Container images' },
    { key: 'pypi', name: 'PyPI', icon: <CodeOutlined />, description: 'Python packages' },
    { key: 'helm', name: 'Helm', icon: <CodeOutlined />, description: 'Kubernetes charts' },
    { key: 'nuget', name: 'NuGet', icon: <CodeOutlined />, description: '.NET packages' },
    { key: 'cargo', name: 'Cargo', icon: <CodeOutlined />, description: 'Rust crates' },
    { key: 'go', name: 'Go', icon: <CodeOutlined />, description: 'Go modules' },
  ]

  const cicdPlatforms = [
    { key: 'github', name: 'GitHub Actions', icon: <GithubOutlined />, description: 'GitHub CI/CD workflows' },
    { key: 'gitlab', name: 'GitLab CI', icon: <GitlabOutlined />, description: 'GitLab pipelines' },
    { key: 'jenkins', name: 'Jenkins', icon: <ToolOutlined />, description: 'Jenkins pipelines' },
    { key: 'azure', name: 'Azure DevOps', icon: <RocketOutlined />, description: 'Azure Pipelines' },
  ]

  return (
    <div>
      <div style={{ marginBottom: spacing.lg }}>
        <Title level={2} style={{ margin: 0, marginBottom: spacing.sm }}>Set Me Up</Title>
        <Text type="secondary">
          Configure your build tools and CI/CD pipelines to work with Artifact Keeper
        </Text>
      </div>

      <Tabs
        defaultActiveKey="package-managers"
        items={[
          {
            key: 'package-managers',
            label: (
              <Space>
                <CodeOutlined />
                Package Managers
              </Space>
            ),
            children: (
              <div>
                <Row gutter={[spacing.md, spacing.md]} style={{ marginBottom: spacing.lg }}>
                  <Col span={24}>
                    <Card>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div>
                          <Title level={4} style={{ margin: 0 }}>Quick Setup</Title>
                          <Text type="secondary">
                            Get started with your preferred package manager
                          </Text>
                        </div>
                        <Button
                          type="primary"
                          icon={<RocketOutlined />}
                          onClick={() => handlePackageManagerClick()}
                        >
                          Open Setup Wizard
                        </Button>
                      </div>
                    </Card>
                  </Col>
                </Row>

                <Title level={4}>Available Package Formats</Title>
                <Row gutter={[spacing.md, spacing.md]}>
                  {packageManagerFormats.map((format) => {
                    const matchingRepo = repositories.find(r => r.format === format.key)
                    return (
                      <Col xs={24} sm={12} md={8} lg={6} key={format.key}>
                        <Card
                          hoverable
                          onClick={() => handlePackageManagerClick(matchingRepo)}
                          size="small"
                        >
                          <div style={{ textAlign: 'center' }}>
                            <div style={{ fontSize: 32, color: colors.primary, marginBottom: spacing.xs }}>
                              {format.icon}
                            </div>
                            <Text strong>{format.name}</Text>
                            <br />
                            <Text type="secondary" style={{ fontSize: 12 }}>
                              {format.description}
                            </Text>
                          </div>
                        </Card>
                      </Col>
                    )
                  })}
                </Row>
              </div>
            ),
          },
          {
            key: 'cicd-platforms',
            label: (
              <Space>
                <RocketOutlined />
                CI/CD Platforms
              </Space>
            ),
            children: (
              <div>
                <Row gutter={[spacing.md, spacing.md]} style={{ marginBottom: spacing.lg }}>
                  <Col span={24}>
                    <Card>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div>
                          <Title level={4} style={{ margin: 0 }}>CI/CD Integration</Title>
                          <Text type="secondary">
                            Configure your CI/CD pipelines to publish and consume artifacts
                          </Text>
                        </div>
                        <Button
                          type="primary"
                          icon={<RocketOutlined />}
                          onClick={() => handleCICDClick()}
                        >
                          Open CI/CD Wizard
                        </Button>
                      </div>
                    </Card>
                  </Col>
                </Row>

                <Title level={4}>Supported Platforms</Title>
                <Row gutter={[spacing.md, spacing.md]}>
                  {cicdPlatforms.map((platform) => (
                    <Col xs={24} sm={12} md={6} key={platform.key}>
                      <SetupCard
                        title={platform.name}
                        description={platform.description}
                        icon={platform.icon}
                        onClick={() => handleCICDClick()}
                      />
                    </Col>
                  ))}
                </Row>
              </div>
            ),
          },
          {
            key: 'repositories',
            label: (
              <Space>
                <ToolOutlined />
                By Repository
              </Space>
            ),
            children: (
              <div>
                <Title level={4}>Configure by Repository</Title>
                <Text type="secondary" style={{ display: 'block', marginBottom: spacing.md }}>
                  Select a repository to get specific configuration instructions
                </Text>
                <Row gutter={[spacing.md, spacing.md]}>
                  {repositories.map((repo) => (
                    <Col xs={24} sm={12} md={8} key={repo.id}>
                      <Card
                        hoverable
                        onClick={() => handlePackageManagerClick(repo)}
                        size="small"
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>
                          <div style={{ fontSize: 24, color: colors.primary }}>
                            <CodeOutlined />
                          </div>
                          <div style={{ flex: 1 }}>
                            <Text strong>{repo.name}</Text>
                            <br />
                            <Text type="secondary" style={{ fontSize: 12 }}>
                              {repo.format.toUpperCase()} • {repo.repo_type}
                            </Text>
                          </div>
                        </div>
                      </Card>
                    </Col>
                  ))}
                  {repositories.length === 0 && (
                    <Col span={24}>
                      <Card>
                        <Text type="secondary">
                          No repositories available. Create a repository first to get configuration instructions.
                        </Text>
                      </Card>
                    </Col>
                  )}
                </Row>
              </div>
            ),
          },
        ]}
      />

      {packageManagerOpen && (
        <PackageManagerWizard
          repository={selectedRepository}
          onClose={() => {
            setPackageManagerOpen(false)
            setSelectedRepository(undefined)
          }}
        />
      )}

      {cicdPlatformOpen && (
        <CICDPlatformWizard
          visible={cicdPlatformOpen}
          repository={selectedRepository}
          onClose={() => {
            setCicdPlatformOpen(false)
            setSelectedRepository(undefined)
          }}
        />
      )}
    </div>
  )
}

export default SetupWizards
