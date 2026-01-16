import apiClient from './client';
import type { LoginResponse, User } from '../types';

export interface LoginCredentials {
  username: string;
  password: string;
}

export const authApi = {
  login: async (credentials: LoginCredentials): Promise<LoginResponse> => {
    const response = await apiClient.post<LoginResponse>('/api/v1/auth/login', credentials);
    return response.data;
  },

  logout: async (): Promise<void> => {
    await apiClient.post('/api/v1/auth/logout');
  },

  refreshToken: async (refreshToken: string): Promise<LoginResponse> => {
    const response = await apiClient.post<LoginResponse>('/api/v1/auth/refresh', {
      refresh_token: refreshToken,
    });
    return response.data;
  },

  getCurrentUser: async (): Promise<User> => {
    const response = await apiClient.get<User>('/api/v1/auth/me');
    return response.data;
  },
};

export default authApi;
