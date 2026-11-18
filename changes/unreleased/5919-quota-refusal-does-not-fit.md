---
section: Fixed
issues: [#5919]
---
- **A storage-quota refusal now says when the upload does not fit in the space left, instead of claiming the quota is reached** (#5919). While usage is still below the instance, repository or project quota, the 403 names the upload's size, the space used and free, and says smaller uploads still fit; the body also carries the declared `content_length`. Repository and project messages still begin with "Repository storage quota exceeded" or "Project storage quota exceeded", so clients matching on that text keep working. The status, `code` and other fields are unchanged.
