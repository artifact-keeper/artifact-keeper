import apiClient from './client';
import type { Repository, CreateRepositoryRequest, PaginatedResponse } from '../types';

export interface ListRepositoriesParams {
  page?: number;
  per_page?: number;
  format?: string;
  repo_type?: string;
}

export const repositoriesApi = {
  list: async (params: ListRepositoriesParams = {}): Promise<PaginatedResponse<Repository>> => {
    const response = await apiClient.get<PaginatedResponse<Repository>>('/api/v1/repositories', {
      params,
    });
    return response.data;
  },

  get: async (key: string): Promise<Repository> => {
    const response = await apiClient.get<Repository>(`/api/v1/repositories/${key}`);
    return response.data;
  },

  create: async (data: CreateRepositoryRequest): Promise<Repository> => {
    const response = await apiClient.post<Repository>('/api/v1/repositories', data);
    return response.data;
  },

  update: async (key: string, data: Partial<CreateRepositoryRequest>): Promise<Repository> => {
    const response = await apiClient.put<Repository>(`/api/v1/repositories/${key}`, data);
    return response.data;
  },

  delete: async (key: string): Promise<void> => {
    await apiClient.delete(`/api/v1/repositories/${key}`);
  },
};

export default repositoriesApi;
