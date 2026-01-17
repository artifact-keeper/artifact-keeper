import { Button, Result, Space, Typography, theme } from 'antd'
import { useNavigate } from 'react-router-dom'
import { HomeOutlined, ReloadOutlined, MailOutlined } from '@ant-design/icons'

const { Text, Link } = Typography

interface ServerErrorProps {
  onRetry?: () => void
  showReportLink?: boolean
  supportEmail?: string
}

const ServerError = ({
  onRetry,
  showReportLink = true,
  supportEmail = 'support@example.com',
}: ServerErrorProps) => {
  const navigate = useNavigate()
  const { token } = theme.useToken()

  const handleGoHome = () => {
    navigate('/')
  }

  const handleRetry = () => {
    if (onRetry) {
      onRetry()
    } else {
      window.location.reload()
    }
  }

  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        minHeight: '60vh',
        padding: token.paddingLG,
      }}
    >
      <Result
        status="500"
        title="Server Error"
        subTitle="Sorry, something went wrong on our end. Please try again later."
        extra={
          <Space orientation="vertical" size="middle" align="center">
            <Space size="middle">
              <Button
                type="primary"
                icon={<ReloadOutlined />}
                onClick={handleRetry}
              >
                Retry
              </Button>
              <Button
                icon={<HomeOutlined />}
                onClick={handleGoHome}
              >
                Go Home
              </Button>
            </Space>
            {showReportLink && (
              <Text type="secondary">
                If the problem persists,{' '}
                <Link
                  href={`mailto:${supportEmail}?subject=Server Error Report`}
                >
                  <MailOutlined /> report this issue
                </Link>
              </Text>
            )}
          </Space>
        }
      />
    </div>
  )
}

export default ServerError
