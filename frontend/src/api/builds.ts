import apiClient from './client';
import type { PaginatedResponse } from '../types';

// Re-export types from the canonical types/ module
export type { BuildStatus, Build, BuildModule, BuildDiff, BuildDetail, BuildModuleArtifact, ArtifactChange } from '../types/builds';
// Re-export for backward compat
export type { BuildModuleArtifact as BuildArtifact, ArtifactChange as BuildArtifactDiff } from '../types/builds';
import type { Build, BuildDetail, BuildStatus, BuildDiff } from '../types/builds';

export interface ListBuildsParams {
  page?: number;
  per_page?: number;
  status?: BuildStatus;
  search?: string;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
}

export const buildsApi = {
  list: async (params: ListBuildsParams = {}): Promise<PaginatedResponse<Build>> => {
    const response = await apiClient.get<PaginatedResponse<Build>>('/api/v1/builds', {
      params,
    });
    return response.data;
  },

  get: async (buildId: string): Promise<BuildDetail> => {
    const response = await apiClient.get<BuildDetail>(`/api/v1/builds/${buildId}`);
    return response.data;
  },

  diff: async (buildIdA: string, buildIdB: string): Promise<BuildDiff> => {
    const response = await apiClient.get<BuildDiff>('/api/v1/builds/diff', {
      params: {
        build_a: buildIdA,
        build_b: buildIdB,
      },
    });
    return response.data;
  },
};

export default buildsApi;
