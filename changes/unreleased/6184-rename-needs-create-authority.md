---
section: Security
issues: [#6184]
---
- **Renaming a repository needs the authority to create one** (#6184). A rename claims a new key, so the repository `admin` grant alone let a Maintainer squat any unused key, including one an operator meant to create next. Changing the key now needs the same authority as creating a repository with it: a global admin, a system repository admin, or the project admin of the repository's project. Every other setting still follows the `admin` grant. Not covered: deleting a repository still needs only the `admin` grant and frees its key.
