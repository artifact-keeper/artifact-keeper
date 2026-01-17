import React from 'react';
import { Avatar, Space, Typography, Tag } from 'antd';
import { UserOutlined, CrownOutlined } from '@ant-design/icons';
import type { User } from '../../../types';
import { colors } from '../../../styles/tokens';

const { Title, Text } = Typography;

export interface ProfileHeaderProps {
  user: User;
}

/**
 * Generates user initials from display name or username
 */
const getInitials = (user: User): string => {
  const name = user.display_name || user.username;
  const parts = name.trim().split(/\s+/);
  if (parts.length >= 2) {
    return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  }
  return name.slice(0, 2).toUpperCase();
};

/**
 * Generates a consistent color based on the user's name
 */
const getAvatarColor = (user: User): string => {
  const name = user.display_name || user.username;
  const avatarColors = [
    colors.primary,
    colors.info,
    '#722ED1', // Purple
    '#EB2F96', // Magenta
    '#13C2C2', // Cyan
    '#FA541C', // Volcano
    '#FA8C16', // Orange
  ];

  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = name.charCodeAt(i) + ((hash << 5) - hash);
  }

  return avatarColors[Math.abs(hash) % avatarColors.length];
};

export const ProfileHeader: React.FC<ProfileHeaderProps> = ({ user }) => {
  const initials = getInitials(user);
  const avatarColor = getAvatarColor(user);

  return (
    <Space size="large" align="center">
      <Avatar
        size={80}
        icon={<UserOutlined />}
        style={{
          backgroundColor: avatarColor,
          fontSize: 28,
          fontWeight: 600,
        }}
      >
        {initials}
      </Avatar>
      <Space orientation="vertical" size={4}>
        <Space align="center" size="middle">
          <Title level={3} style={{ margin: 0 }}>
            {user.display_name || user.username}
          </Title>
          {user.is_admin && (
            <Tag
              icon={<CrownOutlined />}
              color="gold"
              style={{ marginLeft: 0 }}
            >
              Administrator
            </Tag>
          )}
        </Space>
        <Text type="secondary">{user.email}</Text>
        <Text type="secondary" style={{ fontSize: 12 }}>
          @{user.username}
        </Text>
      </Space>
    </Space>
  );
};

export default ProfileHeader;
