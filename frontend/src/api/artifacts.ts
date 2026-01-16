import apiClient from './client';
import type { Artifact, PaginatedResponse } from '../types';

export interface ListArtifactsParams {
  page?: number;
  per_page?: number;
  path?: string;
  search?: string;
}

export const artifactsApi = {
  list: async (repoKey: string, params: ListArtifactsParams = {}): Promise<PaginatedResponse<Artifact>> => {
    const response = await apiClient.get<PaginatedResponse<Artifact>>(
      `/api/v1/repositories/${repoKey}/artifacts`,
      { params }
    );
    return response.data;
  },

  get: async (repoKey: string, artifactPath: string): Promise<Artifact> => {
    const response = await apiClient.get<Artifact>(
      `/api/v1/repositories/${repoKey}/artifacts/${encodeURIComponent(artifactPath)}`
    );
    return response.data;
  },

  delete: async (repoKey: string, artifactPath: string): Promise<void> => {
    await apiClient.delete(
      `/api/v1/repositories/${repoKey}/artifacts/${encodeURIComponent(artifactPath)}`
    );
  },

  getDownloadUrl: (repoKey: string, artifactPath: string): string => {
    const baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:9080';
    return `${baseUrl}/api/v1/repositories/${repoKey}/artifacts/${encodeURIComponent(artifactPath)}/download`;
  },

  upload: async (
    repoKey: string,
    file: File,
    path?: string,
    onProgress?: (percent: number) => void
  ): Promise<Artifact> => {
    const formData = new FormData();
    formData.append('file', file);
    if (path) {
      formData.append('path', path);
    }

    const response = await apiClient.post<Artifact>(
      `/api/v1/repositories/${repoKey}/artifacts`,
      formData,
      {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
        onUploadProgress: (progressEvent) => {
          if (progressEvent.total && onProgress) {
            const percent = Math.round((progressEvent.loaded * 100) / progressEvent.total);
            onProgress(percent);
          }
        },
      }
    );
    return response.data;
  },
};

export default artifactsApi;
