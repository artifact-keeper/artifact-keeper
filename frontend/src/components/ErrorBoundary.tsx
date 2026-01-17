import { Component, ErrorInfo, ReactNode } from 'react'
import { Result, Button, Space, Typography, Collapse } from 'antd'
import {
  HomeOutlined,
  ReloadOutlined,
  BugOutlined,
  MailOutlined,
} from '@ant-design/icons'

const { Text, Paragraph } = Typography
const { Panel } = Collapse

interface Props {
  children: ReactNode
  fallback?: ReactNode
  onError?: (error: Error, errorInfo: ErrorInfo) => void
  showErrorDetails?: boolean
  supportEmail?: string
}

interface State {
  hasError: boolean
  error?: Error
  errorInfo?: ErrorInfo
}

class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    this.setState({ errorInfo })

    console.error('ErrorBoundary caught an error:')
    console.error('Error:', error)
    console.error('Error Info:', errorInfo)
    console.error('Component Stack:', errorInfo.componentStack)

    if (this.props.onError) {
      this.props.onError(error, errorInfo)
    }
  }

  handleGoHome = () => {
    this.setState({ hasError: false, error: undefined, errorInfo: undefined })
    window.location.href = '/'
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: undefined, errorInfo: undefined })
  }

  handleReload = () => {
    window.location.reload()
  }

  getErrorDetails = (): string => {
    const { error, errorInfo } = this.state
    const details = []

    if (error) {
      details.push(`Error: ${error.name}`)
      details.push(`Message: ${error.message}`)
      if (error.stack) {
        details.push(`\nStack Trace:\n${error.stack}`)
      }
    }

    if (errorInfo?.componentStack) {
      details.push(`\nComponent Stack:${errorInfo.componentStack}`)
    }

    return details.join('\n')
  }

  render() {
    const {
      children,
      fallback,
      showErrorDetails = process.env.NODE_ENV === 'development',
      supportEmail = 'support@example.com',
    } = this.props
    const { hasError, error } = this.state

    if (hasError) {
      if (fallback) {
        return fallback
      }

      return (
        <div
          style={{
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            minHeight: '100vh',
            background: '#f0f2f5',
            padding: 24,
          }}
        >
          <Result
            status="error"
            title="Something Went Wrong"
            subTitle="An unexpected error occurred while rendering this page."
            extra={
              <Space orientation="vertical" size="large" align="center">
                <Space size="middle">
                  <Button
                    type="primary"
                    icon={<ReloadOutlined />}
                    onClick={this.handleRetry}
                  >
                    Try Again
                  </Button>
                  <Button
                    icon={<HomeOutlined />}
                    onClick={this.handleGoHome}
                  >
                    Go Home
                  </Button>
                  <Button
                    icon={<ReloadOutlined />}
                    onClick={this.handleReload}
                  >
                    Reload Page
                  </Button>
                </Space>

                <Text type="secondary">
                  If the problem persists,{' '}
                  <a
                    href={`mailto:${supportEmail}?subject=Application Error Report&body=${encodeURIComponent(this.getErrorDetails())}`}
                  >
                    <MailOutlined /> report this issue
                  </a>
                </Text>

                {showErrorDetails && error && (
                  <Collapse
                    ghost
                    style={{
                      width: '100%',
                      maxWidth: 600,
                      textAlign: 'left',
                    }}
                  >
                    <Panel
                      header={
                        <span>
                          <BugOutlined /> Error Details
                        </span>
                      }
                      key="details"
                    >
                      <Paragraph
                        copyable
                        style={{
                          background: '#f5f5f5',
                          padding: 12,
                          borderRadius: 4,
                          fontSize: 12,
                          fontFamily: 'monospace',
                          maxHeight: 300,
                          overflow: 'auto',
                          whiteSpace: 'pre-wrap',
                          wordBreak: 'break-word',
                        }}
                      >
                        {this.getErrorDetails()}
                      </Paragraph>
                    </Panel>
                  </Collapse>
                )}
              </Space>
            }
          />
        </div>
      )
    }

    return children
  }
}

export default ErrorBoundary
