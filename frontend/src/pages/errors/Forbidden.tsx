import { Button, Result, Space, Typography, theme } from 'antd'
import { useNavigate } from 'react-router-dom'
import { ArrowLeftOutlined, MailOutlined, LockOutlined } from '@ant-design/icons'

const { Text, Link } = Typography

interface ForbiddenProps {
  onRequestAccess?: () => void
  adminEmail?: string
  showContactAdmin?: boolean
}

const Forbidden = ({
  onRequestAccess,
  adminEmail = 'admin@example.com',
  showContactAdmin = true,
}: ForbiddenProps) => {
  const navigate = useNavigate()
  const { token } = theme.useToken()

  const handleGoBack = () => {
    navigate(-1)
  }

  const handleRequestAccess = () => {
    if (onRequestAccess) {
      onRequestAccess()
    } else {
      window.location.href = `mailto:${adminEmail}?subject=Access Request`
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
        status="403"
        title="Access Denied"
        subTitle="You do not have permission to access this resource."
        extra={
          <Space orientation="vertical" size="middle" align="center">
            <Space size="middle">
              <Button
                type="primary"
                icon={<LockOutlined />}
                onClick={handleRequestAccess}
              >
                Request Access
              </Button>
              <Button
                icon={<ArrowLeftOutlined />}
                onClick={handleGoBack}
              >
                Go Back
              </Button>
            </Space>
            {showContactAdmin && (
              <Text type="secondary">
                Need access? Contact your administrator at{' '}
                <Link href={`mailto:${adminEmail}`}>
                  <MailOutlined /> {adminEmail}
                </Link>
              </Text>
            )}
          </Space>
        }
      />
    </div>
  )
}

export default Forbidden
