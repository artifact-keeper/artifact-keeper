import apiClient from './client';
import type { AdminStats, User, HealthResponse } from '../types';

export const adminApi = {
  getStats: async (): Promise<AdminStats> => {
    const response = await apiClient.get<AdminStats>('/api/v1/admin/stats');
    return response.data;
  },

  listUsers: async (): Promise<User[]> => {
    const response = await apiClient.get<{ items: User[] }>('/api/v1/users');
    return response.data.items;
  },

  getHealth: async (): Promise<HealthResponse> => {
    const response = await apiClient.get<HealthResponse>('/health');
    return response.data;
  },
};

export default adminApi;
