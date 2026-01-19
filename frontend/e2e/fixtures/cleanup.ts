import { APIRequestContext } from '@playwright/test';
import { TEST_CREDENTIALS, TEST_PATTERNS } from './test-data';

/**
 * Resource types that can be cleaned up
 */
type ResourceType = 'repository' | 'user' | 'group' | 'migration';

/**
 * Resource record for cleanup tracking
 */
interface CleanupResource {
  type: ResourceType;
  id: string;
}

/**
 * Cleanup utility for managing test resources.
 * Tracks resources created during tests and cleans them up afterward.
 */
export class CleanupUtility {
  private resources: CleanupResource[] = [];
  private request: APIRequestContext;
  private baseUrl: string;

  constructor(request: APIRequestContext, baseUrl: string = 'http://localhost:8080') {
    this.request = request;
    this.baseUrl = baseUrl;
  }

  /**
   * Register a resource for cleanup
   */
  registerForCleanup(type: ResourceType, id: string): void {
    this.resources.push({ type, id });
  }

  /**
   * Clean up all registered resources
   */
  async cleanup(): Promise<void> {
    // Clean up in reverse order (LIFO) to handle dependencies
    const resourcesToClean = [...this.resources].reverse();

    for (const resource of resourcesToClean) {
      try {
        await this.deleteResource(resource);
      } catch (error) {
        console.warn(`Failed to clean up ${resource.type} ${resource.id}:`, error);
      }
    }

    // Clear the list
    this.resources = [];
  }

  /**
   * Delete a single resource
   */
  private async deleteResource(resource: CleanupResource): Promise<void> {
    const endpoints: Record<ResourceType, string> = {
      repository: `/api/v1/repositories/${resource.id}`,
      user: `/api/v1/users/${resource.id}`,
      group: `/api/v1/groups/${resource.id}`,
      migration: `/api/v1/migrations/${resource.id}`,
    };

    const endpoint = endpoints[resource.type];
    if (!endpoint) {
      console.warn(`Unknown resource type: ${resource.type}`);
      return;
    }

    const response = await this.request.delete(`${this.baseUrl}${endpoint}`, {
      headers: {
        Authorization: `Basic ${Buffer.from(
          `${TEST_CREDENTIALS.admin.username}:${TEST_CREDENTIALS.admin.password}`
        ).toString('base64')}`,
      },
    });

    if (!response.ok() && response.status() !== 404) {
      console.warn(
        `Failed to delete ${resource.type} ${resource.id}: ${response.status()}`
      );
    }
  }

  /**
   * Clean up all repositories matching the E2E test pattern
   */
  async cleanupRepos(pattern: string = TEST_PATTERNS.repoKeyPrefix): Promise<void> {
    try {
      const response = await this.request.get(
        `${this.baseUrl}/api/v1/repositories`,
        {
          headers: {
            Authorization: `Basic ${Buffer.from(
              `${TEST_CREDENTIALS.admin.username}:${TEST_CREDENTIALS.admin.password}`
            ).toString('base64')}`,
          },
        }
      );

      if (response.ok()) {
        const data = await response.json();
        const repos = data.items || data || [];

        for (const repo of repos) {
          if (repo.key?.startsWith(pattern)) {
            await this.deleteResource({ type: 'repository', id: repo.key });
          }
        }
      }
    } catch (error) {
      console.warn('Failed to clean up repositories:', error);
    }
  }

  /**
   * Clean up all users matching the E2E test pattern
   */
  async cleanupUsers(pattern: string = TEST_PATTERNS.userPrefix): Promise<void> {
    try {
      const response = await this.request.get(`${this.baseUrl}/api/v1/users`, {
        headers: {
          Authorization: `Basic ${Buffer.from(
            `${TEST_CREDENTIALS.admin.username}:${TEST_CREDENTIALS.admin.password}`
          ).toString('base64')}`,
        },
      });

      if (response.ok()) {
        const data = await response.json();
        const users = data.items || data || [];

        for (const user of users) {
          if (user.username?.startsWith(pattern)) {
            await this.deleteResource({ type: 'user', id: user.username });
          }
        }
      }
    } catch (error) {
      console.warn('Failed to clean up users:', error);
    }
  }

  /**
   * Clean up all groups matching the E2E test pattern
   */
  async cleanupGroups(pattern: string = TEST_PATTERNS.groupPrefix): Promise<void> {
    try {
      const response = await this.request.get(`${this.baseUrl}/api/v1/groups`, {
        headers: {
          Authorization: `Basic ${Buffer.from(
            `${TEST_CREDENTIALS.admin.username}:${TEST_CREDENTIALS.admin.password}`
          ).toString('base64')}`,
        },
      });

      if (response.ok()) {
        const data = await response.json();
        const groups = data.items || data || [];

        for (const group of groups) {
          if (group.name?.startsWith(pattern)) {
            await this.deleteResource({ type: 'group', id: group.name });
          }
        }
      }
    } catch (error) {
      console.warn('Failed to clean up groups:', error);
    }
  }

  /**
   * Clean up all E2E test data (repos, users, groups)
   */
  async cleanupAll(): Promise<void> {
    await this.cleanupRepos();
    await this.cleanupUsers();
    await this.cleanupGroups();
    await this.cleanup();
  }
}

export default CleanupUtility;
