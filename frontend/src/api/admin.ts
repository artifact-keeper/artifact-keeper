import apiClient from './client';
import type { AdminStats, User, HealthResponse } from '../types';

export const adminApi = {
  getStats: async (): Promise<AdminStats> => {
    const response = await apiClient.get<AdminStats>('/api/v1/admin/stats');
    return response.data;
  },

  listUsers: async (): Promise<User[]> => {
    const response = await apiClient.get<User[]>('/api/v1/admin/users');
    return response.data;
  },

  getHealth: async (): Promise<HealthResponse> => {
    const response = await apiClient.get<HealthResponse>('/api/v1/health');
    return response.data;
  },
};

export default adminApi;
