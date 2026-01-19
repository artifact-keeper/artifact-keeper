import { type Page, type Locator, expect } from '@playwright/test';
import { BasePage } from './BasePage';

/**
 * Page Object for Admin Groups page
 * Path: /admin/groups
 *
 * Features:
 * - Group list table with CRUD operations
 * - Create group modal
 * - Edit group modal
 * - Manage group members
 */
export class AdminGroupsPage extends BasePage {
  // Page heading
  readonly heading: Locator;

  // Groups table
  readonly groupsTable: Locator;
  readonly searchInput: Locator;
  readonly createGroupButton: Locator;
  readonly refreshButton: Locator;

  // Create group modal
  readonly createGroupModal: Locator;
  readonly groupNameInput: Locator;
  readonly groupDescriptionInput: Locator;
  readonly submitCreateButton: Locator;
  readonly cancelButton: Locator;

  // Edit group modal
  readonly editGroupModal: Locator;
  readonly submitEditButton: Locator;

  // Members modal
  readonly membersModal: Locator;
  readonly memberSearch: Locator;
  readonly addMemberButton: Locator;
  readonly removeMemberButton: Locator;
  readonly membersList: Locator;

  // Group row actions
  readonly editButton: Locator;
  readonly membersButton: Locator;
  readonly deleteButton: Locator;

  constructor(page: Page) {
    super(page);

    // Page heading
    this.heading = page.getByRole('heading', { name: 'Groups' });

    // Groups table
    this.groupsTable = page.locator('.ant-table');
    this.searchInput = page.getByPlaceholder(/search/i);
    this.createGroupButton = page.getByRole('button', { name: /create group/i });
    this.refreshButton = page.getByRole('button', { name: /refresh/i });

    // Create group modal
    this.createGroupModal = page.locator('.ant-modal').filter({ hasText: 'Create Group' });
    this.groupNameInput = page.getByLabel('Name');
    this.groupDescriptionInput = page.getByLabel('Description');
    this.submitCreateButton = page.getByRole('button', { name: /^create$/i });
    this.cancelButton = page.getByRole('button', { name: 'Cancel' });

    // Edit group modal
    this.editGroupModal = page.locator('.ant-modal').filter({ hasText: /Edit Group/i });
    this.submitEditButton = page.getByRole('button', { name: /save|update/i });

    // Members modal
    this.membersModal = page.locator('.ant-modal').filter({ hasText: /Members|Manage/i });
    this.memberSearch = this.membersModal.getByPlaceholder(/search|add/i);
    this.addMemberButton = this.membersModal.getByRole('button', { name: /add/i });
    this.removeMemberButton = this.membersModal.getByRole('button', { name: /remove/i });
    this.membersList = this.membersModal.locator('.ant-list, .ant-table');

    // Group row actions
    this.editButton = page.getByRole('button', { name: 'Edit' });
    this.membersButton = page.getByRole('button', { name: /members/i });
    this.deleteButton = page.getByRole('button', { name: /delete/i });
  }

  /**
   * Navigate to Groups page
   */
  async goto(): Promise<void> {
    await this.page.goto('/admin/groups');
    await this.waitForPageReady();
  }

  /**
   * Wait for page to be fully loaded
   */
  async waitForPageReady(): Promise<void> {
    await this.heading.waitFor({ state: 'visible' });
    await this.groupsTable.waitFor({ state: 'visible' }).catch(() => {
      // Table may not be visible if no groups exist
    });
  }

  /**
   * Assert page is loaded
   */
  async expectPageLoaded(): Promise<void> {
    await expect(this.heading).toBeVisible();
  }

  // === Group CRUD Operations ===

  /**
   * Open create group modal
   */
  async openCreateGroupModal(): Promise<void> {
    await this.createGroupButton.click();
    await this.createGroupModal.waitFor({ state: 'visible' });
  }

  /**
   * Create a new group
   */
  async createGroup(group: {
    name: string;
    description?: string;
  }): Promise<void> {
    await this.openCreateGroupModal();

    await this.groupNameInput.fill(group.name);
    if (group.description) {
      await this.groupDescriptionInput.fill(group.description);
    }

    await this.submitCreateButton.click();
    await this.createGroupModal.waitFor({ state: 'hidden', timeout: 10000 });
  }

  /**
   * Close create group modal
   */
  async closeCreateGroupModal(): Promise<void> {
    await this.cancelButton.click();
    await this.createGroupModal.waitFor({ state: 'hidden' });
  }

  /**
   * Edit a group
   */
  async editGroup(groupName: string, updates: {
    name?: string;
    description?: string;
  }): Promise<void> {
    const groupRow = this.groupsTable.locator('tr').filter({ hasText: groupName });
    await groupRow.getByRole('button', { name: 'Edit' }).click();

    await this.editGroupModal.waitFor({ state: 'visible' });

    if (updates.name) {
      await this.groupNameInput.clear();
      await this.groupNameInput.fill(updates.name);
    }
    if (updates.description) {
      await this.groupDescriptionInput.clear();
      await this.groupDescriptionInput.fill(updates.description);
    }

    await this.submitEditButton.click();
    await this.editGroupModal.waitFor({ state: 'hidden' });
  }

  /**
   * Delete a group
   */
  async deleteGroup(groupName: string): Promise<void> {
    const groupRow = this.groupsTable.locator('tr').filter({ hasText: groupName });
    await groupRow.getByRole('button', { name: /delete/i }).click();

    // Confirm deletion
    const confirmButton = this.page.getByRole('button', { name: /confirm|yes|delete/i });
    if (await confirmButton.isVisible()) {
      await confirmButton.click();
    }
  }

  // === Member Management ===

  /**
   * Open members modal for a group
   */
  async openMembersModal(groupName: string): Promise<void> {
    const groupRow = this.groupsTable.locator('tr').filter({ hasText: groupName });
    await groupRow.getByRole('button', { name: /members/i }).click();
    await this.membersModal.waitFor({ state: 'visible' });
  }

  /**
   * Add a member to a group
   */
  async addMemberToGroup(groupName: string, username: string): Promise<void> {
    await this.openMembersModal(groupName);

    await this.memberSearch.fill(username);
    await this.page.waitForTimeout(500);

    // Click on the user in search results
    await this.page.getByText(username).click();

    // Add member
    await this.addMemberButton.click();

    await this.expectSuccessToast(/added|success/i);
  }

  /**
   * Remove a member from a group
   */
  async removeMemberFromGroup(groupName: string, username: string): Promise<void> {
    await this.openMembersModal(groupName);

    const memberRow = this.membersList.locator('tr, .ant-list-item').filter({ hasText: username });
    await memberRow.getByRole('button', { name: /remove/i }).click();

    // Confirm removal
    const confirmButton = this.page.getByRole('button', { name: /confirm|yes|remove/i });
    if (await confirmButton.isVisible()) {
      await confirmButton.click();
    }

    await this.expectSuccessToast(/removed|success/i);
  }

  /**
   * Close members modal
   */
  async closeMembersModal(): Promise<void> {
    const closeButton = this.membersModal.locator('.ant-modal-close');
    await closeButton.click();
    await this.membersModal.waitFor({ state: 'hidden' });
  }

  /**
   * Get member count for a group
   */
  async getMemberCount(groupName: string): Promise<number> {
    await this.openMembersModal(groupName);
    const rows = await this.membersList.locator('tr, .ant-list-item').all();
    await this.closeMembersModal();
    return rows.length;
  }

  /**
   * Search for groups
   */
  async searchGroups(query: string): Promise<void> {
    await this.searchInput.fill(query);
    await this.page.waitForTimeout(500); // Debounce
  }

  /**
   * Get group count
   */
  async getGroupCount(): Promise<number> {
    const rows = await this.groupsTable.locator('tbody tr').all();
    return rows.length;
  }

  // === Assertions ===

  /**
   * Expect group to be visible in table
   */
  async expectGroupVisible(groupName: string): Promise<void> {
    await expect(this.groupsTable.getByText(groupName)).toBeVisible();
  }

  /**
   * Expect group creation success
   */
  async expectGroupCreated(): Promise<void> {
    await this.expectSuccessToast(/created|success/i);
  }
}
