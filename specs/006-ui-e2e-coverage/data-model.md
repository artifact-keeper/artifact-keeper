# Data Model: UI E2E Test Coverage

**Feature**: 006-ui-e2e-coverage
**Date**: 2026-01-18

## Overview

This feature does not introduce database entities. Instead, it defines test infrastructure entities: Page Objects, Test Fixtures, and Test Data Factories.

## Test Infrastructure Entities

### Page Objects

Page Objects encapsulate UI page interactions and selectors.

#### BasePage

Base class for all page objects.

| Property/Method | Type | Description |
|-----------------|------|-------------|
| page | Page | Playwright Page instance |
| waitForPageLoad() | async | Wait for network idle |
| expectToast(message) | async | Assert toast notification |
| expectUrl(pattern) | async | Assert current URL |

#### LoginPage

| Property/Method | Type | Description |
|-----------------|------|-------------|
| usernameInput | Locator | Username field |
| passwordInput | Locator | Password field |
| loginButton | Locator | Submit button |
| errorMessage | Locator | Error alert |
| login(username, password) | async | Complete login flow |

#### DashboardPage

| Property/Method | Type | Description |
|-----------------|------|-------------|
| welcomeWidget | Locator | Welcome/onboarding widget |
| artifactCountWidget | Locator | Artifact stats widget |
| storageWidget | Locator | Storage usage widget |
| recentActivityWidget | Locator | Recent activity widget |
| completeOnboarding() | async | Complete onboarding wizard |

#### RepositoriesPage

| Property/Method | Type | Description |
|-----------------|------|-------------|
| createButton | Locator | Create Repository button |
| table | Locator | Repository table |
| searchInput | Locator | Filter/search input |
| openCreateWizard() | async | Click create, wait for modal |
| findRepo(key) | async | Find row by repo key |
| deleteRepo(key) | async | Delete with confirmation |

#### RepoWizardPage

| Property/Method | Type | Description |
|-----------------|------|-------------|
| modal | Locator | Wizard modal container |
| steps | Locator | Steps indicator |
| nextButton | Locator | Next step button |
| previousButton | Locator | Previous step button |
| cancelButton | Locator | Cancel button |
| createButton | Locator | Final create button |
| **Step 1** | | |
| selectRepoType(type) | async | Select local/remote/virtual |
| **Step 2** | | |
| selectPackageFormat(format) | async | Select npm/maven/docker/etc |
| **Step 3** | | |
| keyInput | Locator | Repository key input |
| nameInput | Locator | Repository name input |
| descriptionInput | Locator | Description textarea |
| fillBasicConfig(data) | async | Fill all basic fields |
| **Step 4 (conditional)** | | |
| upstreamUrlInput | Locator | Remote URL (remote only) |
| repoSelector | Locator | Repo selection (virtual only) |
| **Step 5** | | |
| quotaInput | Locator | Quota bytes input |
| completeWizard(config) | async | Full wizard completion |

#### MigrationPage

| Property/Method | Type | Description |
|-----------------|------|-------------|
| createJobButton | Locator | Start new migration button |
| jobsTable | Locator | Migration jobs table |
| getJobRow(id) | async | Find job by ID |
| getJobStatus(id) | async | Get job status text |

#### MigrationWizardPage

| Property/Method | Type | Description |
|-----------------|------|-------------|
| **Step 1: Source** | | |
| sourceUrlInput | Locator | Artifactory URL |
| usernameInput | Locator | Source username |
| passwordInput | Locator | Source password |
| testConnectionButton | Locator | Test connection |
| connectionStatus | Locator | Connection result |
| fillSourceConfig(config) | async | Fill source fields |
| testConnection() | async | Click test, wait for result |
| **Step 2: Repositories** | | |
| repoCheckboxes | Locator | Repository checkboxes |
| selectAllButton | Locator | Select all checkbox |
| selectRepos(repos) | async | Select specific repos |
| **Step 3: Options** | | |
| skipExistingCheckbox | Locator | Skip existing option |
| deleteSourceCheckbox | Locator | Delete after migrate |
| **Progress** | | |
| progressBar | Locator | Progress indicator |
| progressPercent | Locator | Percent complete |
| completedCount | Locator | Items completed |
| failedCount | Locator | Items failed |

#### SetupPage

| Property/Method | Type | Description |
|-----------------|------|-------------|
| cicdTab | Locator | CI/CD platforms tab |
| packageManagerTab | Locator | Package managers tab |
| repoSelector | Locator | Repository dropdown |
| codeBlocks | Locator | All code blocks |
| copyButtons | Locator | All copy buttons |
| selectRepo(key) | async | Select repository |
| selectCICD(platform) | async | Select CI/CD platform |
| selectPackageManager(type) | async | Select package manager |
| copyCodeBlock(index) | async | Click copy on nth block |

#### ProfilePage

| Property/Method | Type | Description |
|-----------------|------|-------------|
| displayNameInput | Locator | Display name field |
| emailInput | Locator | Email field |
| generateApiKeyButton | Locator | Generate API key button |
| apiKeysList | Locator | API keys table |
| accessTokensList | Locator | Access tokens table |
| generateApiKey() | async | Generate and return key |
| revokeApiKey(id) | async | Revoke with confirmation |
| createAccessToken(scope, expiry) | async | Create scoped token |

#### AdminUsersPage

| Property/Method | Type | Description |
|-----------------|------|-------------|
| createUserButton | Locator | Create user button |
| usersTable | Locator | Users table |
| createUser(data) | async | Complete user creation |
| findUser(username) | async | Find user row |
| deleteUser(username) | async | Delete with confirmation |

#### AdminGroupsPage

| Property/Method | Type | Description |
|-----------------|------|-------------|
| createGroupButton | Locator | Create group button |
| groupsTable | Locator | Groups table |
| createGroup(name, members) | async | Create with members |
| addMember(group, user) | async | Add user to group |

#### SearchPage

| Property/Method | Type | Description |
|-----------------|------|-------------|
| quickSearchInput | Locator | Top bar search |
| quickSearchResults | Locator | Dropdown results |
| advancedSearchLink | Locator | Advanced search link |
| searchTypeSelect | Locator | Search type dropdown |
| searchButton | Locator | Execute search |
| results | Locator | Results container |
| quickSearch(query) | async | Type and wait for dropdown |
| advancedSearch(type, params) | async | Full advanced search |

## Test Fixtures

### AuthFixture

Provides authenticated page context.

| Property | Type | Description |
|----------|------|-------------|
| adminPage | Page | Page logged in as admin |
| userPage | Page | Page logged in as regular user |
| login(role) | async | Login with specified role |
| logout() | async | Logout current session |

### TestDataFactory

Generates unique test data.

| Method | Returns | Description |
|--------|---------|-------------|
| uniqueId(prefix) | string | Unique identifier |
| testRepo(overrides?) | RepoConfig | Repository test data |
| testUser(overrides?) | UserConfig | User test data |
| testGroup(overrides?) | GroupConfig | Group test data |
| testMigration(overrides?) | MigrationConfig | Migration test data |

### CleanupUtility

Cleans up test data after tests.

| Method | Description |
|--------|-------------|
| registerForCleanup(type, id) | Queue resource for cleanup |
| cleanup() | Delete all registered resources |
| cleanupRepos(pattern) | Delete repos matching pattern |
| cleanupUsers(pattern) | Delete users matching pattern |

## Test Data Types

```typescript
interface RepoConfig {
  key: string;
  name: string;
  description?: string;
  format: 'npm' | 'maven' | 'docker' | 'pypi' | 'generic';
  repoType: 'local' | 'remote' | 'virtual';
  upstreamUrl?: string;  // for remote
  includedRepos?: string[];  // for virtual
}

interface UserConfig {
  username: string;
  email: string;
  password: string;
  isAdmin?: boolean;
  groups?: string[];
}

interface GroupConfig {
  name: string;
  description?: string;
  members?: string[];
}

interface MigrationConfig {
  sourceUrl: string;
  username: string;
  password: string;
  repositories: string[];
  skipExisting?: boolean;
}
```

## Relationships

```
AuthFixture
  └── provides authenticated Page to all Page Objects

TestDataFactory
  └── generates unique data for all test scenarios

CleanupUtility
  └── tracks and cleans resources created by tests

Page Objects (composition):
  BasePage
    ├── LoginPage
    ├── DashboardPage
    ├── RepositoriesPage
    │   └── uses RepoWizardPage
    ├── MigrationPage
    │   └── uses MigrationWizardPage
    ├── SetupPage
    ├── ProfilePage
    ├── AdminUsersPage
    ├── AdminGroupsPage
    └── SearchPage
```
