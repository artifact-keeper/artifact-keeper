import { Card, Form, Input, Tabs, Alert } from 'antd'
import { useAuth } from '../contexts'
import { useDocumentTitle } from '../hooks'

const Settings = () => {
  useDocumentTitle('Settings')
  const { user } = useAuth()

  if (!user?.is_admin) {
    return (
      <div>
        <h1>Settings</h1>
        <Alert
          message="Access Denied"
          description="You must be an administrator to view settings."
          type="error"
          showIcon
        />
      </div>
    )
  }

  return (
    <div>
      <h1>Settings</h1>
      <Alert
        message="Settings Configuration"
        description="Server settings are configured via environment variables. The settings shown below are read-only."
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
      />
      <Tabs
        defaultActiveKey="general"
        items={[
          {
            key: 'general',
            label: 'General',
            children: (
              <Card>
                <Form layout="vertical">
                  <Form.Item label="API URL">
                    <Input disabled value={import.meta.env.VITE_API_URL || window.location.origin} />
                  </Form.Item>
                  <Form.Item label="Version">
                    <Input disabled value="1.0.0" />
                  </Form.Item>
                </Form>
              </Card>
            ),
          },
          {
            key: 'storage',
            label: 'Storage',
            children: (
              <Card>
                <Form layout="vertical">
                  <Form.Item label="Storage Backend">
                    <Input disabled value="Local Filesystem" />
                  </Form.Item>
                  <Form.Item label="Storage Path">
                    <Input disabled value="/data/artifacts" />
                  </Form.Item>
                </Form>
              </Card>
            ),
          },
          {
            key: 'auth',
            label: 'Authentication',
            children: (
              <Card>
                <Form layout="vertical">
                  <Form.Item label="Authentication Method">
                    <Input disabled value="JWT (JSON Web Token)" />
                  </Form.Item>
                  <Form.Item label="Token Expiry">
                    <Input disabled value="1 hour" />
                  </Form.Item>
                </Form>
              </Card>
            ),
          },
        ]}
      />
    </div>
  )
}

export default Settings
