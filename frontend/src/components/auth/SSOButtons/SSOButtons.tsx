import React from 'react';
import { Button, Space, Typography } from 'antd';
import { GoogleOutlined, GithubOutlined, SafetyOutlined, TeamOutlined } from '@ant-design/icons';
import { colors } from '../../../styles/tokens';

const { Text } = Typography;

export type SSOProvider = 'google' | 'github' | 'saml' | 'ldap';

export interface SSOProviderConfig {
  id: SSOProvider;
  name: string;
  enabled: boolean;
}

export interface SSOButtonsProps {
  onSelect: (provider: SSOProvider) => void;
  availableProviders: SSOProviderConfig[];
  loading?: boolean;
  loadingProvider?: SSOProvider;
  disabled?: boolean;
}

const providerIcons: Record<SSOProvider, React.ReactNode> = {
  google: <GoogleOutlined />,
  github: <GithubOutlined />,
  saml: <SafetyOutlined />,
  ldap: <TeamOutlined />,
};

const providerColors: Record<SSOProvider, { background: string; border: string; text: string }> = {
  google: {
    background: '#ffffff',
    border: colors.border,
    text: colors.textPrimary,
  },
  github: {
    background: '#24292e',
    border: '#24292e',
    text: '#ffffff',
  },
  saml: {
    background: colors.primary,
    border: colors.primary,
    text: '#ffffff',
  },
  ldap: {
    background: colors.info,
    border: colors.info,
    text: '#ffffff',
  },
};

export const SSOButtons: React.FC<SSOButtonsProps> = ({
  onSelect,
  availableProviders,
  loading = false,
  loadingProvider,
  disabled = false,
}) => {
  const enabledProviders = availableProviders.filter((p) => p.enabled);

  if (enabledProviders.length === 0) {
    return null;
  }

  return (
    <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
      <Text type="secondary" style={{ textAlign: 'center', display: 'block' }}>
        Or continue with
      </Text>
      <Space orientation="vertical" size="small" style={{ width: '100%' }}>
        {enabledProviders.map((provider) => {
          const colorConfig = providerColors[provider.id];
          const isLoading = loading && loadingProvider === provider.id;
          const isDisabled = disabled || (loading && loadingProvider !== provider.id);

          return (
            <Button
              key={provider.id}
              icon={providerIcons[provider.id]}
              onClick={() => onSelect(provider.id)}
              loading={isLoading}
              disabled={isDisabled}
              block
              size="large"
              style={{
                backgroundColor: colorConfig.background,
                borderColor: colorConfig.border,
                color: colorConfig.text,
                height: 44,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: 8,
              }}
            >
              Continue with {provider.name}
            </Button>
          );
        })}
      </Space>
    </Space>
  );
};

export default SSOButtons;
