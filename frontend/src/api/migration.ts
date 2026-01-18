import apiClient from './client';
import type {
  SourceConnection,
  CreateConnectionRequest,
  ConnectionTestResult,
  SourceRepository,
  MigrationJob,
  CreateMigrationRequest,
  MigrationItem,
  MigrationReport,
  AssessmentResult,
  PaginatedResponse,
} from '../types';

interface ListResponse<T> {
  items: T[];
  pagination?: {
    page: number;
    per_page: number;
    total: number;
    total_pages: number;
  };
}

export const migrationApi = {
  // Source Connections
  listConnections: async (): Promise<SourceConnection[]> => {
    const response = await apiClient.get<ListResponse<SourceConnection>>(
      '/api/v1/migrations/connections'
    );
    return response.data.items;
  },

  createConnection: async (
    data: CreateConnectionRequest
  ): Promise<SourceConnection> => {
    const response = await apiClient.post<SourceConnection>(
      '/api/v1/migrations/connections',
      data
    );
    return response.data;
  },

  getConnection: async (id: string): Promise<SourceConnection> => {
    const response = await apiClient.get<SourceConnection>(
      `/api/v1/migrations/connections/${id}`
    );
    return response.data;
  },

  deleteConnection: async (id: string): Promise<void> => {
    await apiClient.delete(`/api/v1/migrations/connections/${id}`);
  },

  testConnection: async (id: string): Promise<ConnectionTestResult> => {
    const response = await apiClient.post<ConnectionTestResult>(
      `/api/v1/migrations/connections/${id}/test`
    );
    return response.data;
  },

  listSourceRepositories: async (
    connectionId: string
  ): Promise<SourceRepository[]> => {
    const response = await apiClient.get<ListResponse<SourceRepository>>(
      `/api/v1/migrations/connections/${connectionId}/repositories`
    );
    return response.data.items;
  },

  // Migration Jobs
  listMigrations: async (params?: {
    status?: string;
    page?: number;
    per_page?: number;
  }): Promise<PaginatedResponse<MigrationJob>> => {
    const response = await apiClient.get<PaginatedResponse<MigrationJob>>(
      '/api/v1/migrations',
      { params }
    );
    return response.data;
  },

  createMigration: async (
    data: CreateMigrationRequest
  ): Promise<MigrationJob> => {
    const response = await apiClient.post<MigrationJob>(
      '/api/v1/migrations',
      data
    );
    return response.data;
  },

  getMigration: async (id: string): Promise<MigrationJob> => {
    const response = await apiClient.get<MigrationJob>(
      `/api/v1/migrations/${id}`
    );
    return response.data;
  },

  deleteMigration: async (id: string): Promise<void> => {
    await apiClient.delete(`/api/v1/migrations/${id}`);
  },

  startMigration: async (id: string): Promise<MigrationJob> => {
    const response = await apiClient.post<MigrationJob>(
      `/api/v1/migrations/${id}/start`
    );
    return response.data;
  },

  pauseMigration: async (id: string): Promise<MigrationJob> => {
    const response = await apiClient.post<MigrationJob>(
      `/api/v1/migrations/${id}/pause`
    );
    return response.data;
  },

  resumeMigration: async (id: string): Promise<MigrationJob> => {
    const response = await apiClient.post<MigrationJob>(
      `/api/v1/migrations/${id}/resume`
    );
    return response.data;
  },

  cancelMigration: async (id: string): Promise<MigrationJob> => {
    const response = await apiClient.post<MigrationJob>(
      `/api/v1/migrations/${id}/cancel`
    );
    return response.data;
  },

  listMigrationItems: async (
    jobId: string,
    params?: {
      status?: string;
      item_type?: string;
      page?: number;
      per_page?: number;
    }
  ): Promise<PaginatedResponse<MigrationItem>> => {
    const response = await apiClient.get<PaginatedResponse<MigrationItem>>(
      `/api/v1/migrations/${jobId}/items`,
      { params }
    );
    return response.data;
  },

  getMigrationReport: async (
    jobId: string,
    format: 'json' | 'html' = 'json'
  ): Promise<MigrationReport | string> => {
    if (format === 'html') {
      const response = await apiClient.get<string>(
        `/api/v1/migrations/${jobId}/report`,
        {
          params: { format },
          responseType: 'text',
        }
      );
      return response.data;
    }
    const response = await apiClient.get<MigrationReport>(
      `/api/v1/migrations/${jobId}/report`,
      { params: { format } }
    );
    return response.data;
  },

  // Assessment
  runAssessment: async (jobId: string): Promise<MigrationJob> => {
    const response = await apiClient.post<MigrationJob>(
      `/api/v1/migrations/${jobId}/assess`
    );
    return response.data;
  },

  getAssessment: async (jobId: string): Promise<AssessmentResult> => {
    const response = await apiClient.get<AssessmentResult>(
      `/api/v1/migrations/${jobId}/assessment`
    );
    return response.data;
  },

  // SSE Stream for progress
  createProgressStream: (jobId: string): EventSource => {
    const token = localStorage.getItem('token');
    const url = new URL(`/api/v1/migrations/${jobId}/stream`, window.location.origin);
    if (token) {
      url.searchParams.set('token', token);
    }
    return new EventSource(url.toString());
  },
};

export default migrationApi;
