import { Card, Form, Input, Button, Tabs, Switch, message } from 'antd'

const Settings = () => {
  const [form] = Form.useForm()

  const onFinish = (values: unknown) => {
    console.log('Settings:', values)
    message.success('Settings saved')
  }

  return (
    <div>
      <h1>Settings</h1>
      <Tabs
        defaultActiveKey="general"
        items={[
          {
            key: 'general',
            label: 'General',
            children: (
              <Card>
                <Form
                  form={form}
                  layout="vertical"
                  onFinish={onFinish}
                >
                  <Form.Item label="Server URL" name="serverUrl">
                    <Input placeholder="https://artifacts.example.com" />
                  </Form.Item>
                  <Form.Item label="Allow Anonymous Access" name="allowAnonymous" valuePropName="checked">
                    <Switch />
                  </Form.Item>
                  <Form.Item>
                    <Button type="primary" htmlType="submit">
                      Save Settings
                    </Button>
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
                  <Form.Item label="Storage Backend" name="storageBackend">
                    <Input disabled value="S3" />
                  </Form.Item>
                  <Form.Item label="S3 Bucket" name="s3Bucket">
                    <Input placeholder="my-artifacts-bucket" />
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
                  <Form.Item label="OIDC Issuer" name="oidcIssuer">
                    <Input placeholder="https://auth.example.com" />
                  </Form.Item>
                  <Form.Item label="OIDC Client ID" name="oidcClientId">
                    <Input />
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
