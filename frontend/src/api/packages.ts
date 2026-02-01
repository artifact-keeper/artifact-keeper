import apiClient from './client';
import type { PaginatedResponse } from '../types';

// Re-export types from the canonical types/ module
export type { Package, PackageVersion } from '../types/packages';
import type { Package, PackageVersion } from '../types/packages';

export interface ListPackagesParams {
  page?: number;
  per_page?: number;
  repository_key?: string;
  format?: string;
  search?: string;
}

export const packagesApi = {
  list: async (params: ListPackagesParams = {}): Promise<PaginatedResponse<Package>> => {
    const response = await apiClient.get<PaginatedResponse<Package>>('/api/v1/packages', {
      params,
    });
    return response.data;
  },

  get: async (packageId: string): Promise<Package> => {
    const response = await apiClient.get<Package>(`/api/v1/packages/${packageId}`);
    return response.data;
  },

  getVersions: async (packageId: string): Promise<PackageVersion[]> => {
    const response = await apiClient.get<{ versions: PackageVersion[] }>(
      `/api/v1/packages/${packageId}/versions`
    );
    return response.data.versions;
  },
};

export default packagesApi;
