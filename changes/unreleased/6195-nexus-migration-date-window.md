---
section: Fixed
issues: [#6195]
---
- **A migration from Nexus 3 now honours `date_from` and `date_to`** (#6195). The Nexus source client accepted the date window and then listed the whole repository, while the job log said it was filtered, so an incremental catch-up run walked and duplicate-checked every historical artifact. The client now reads each asset's `lastModified` and keeps only the assets inside the window (strictly after `date_from`, strictly before `date_to`, as for Artifactory), applied while the pages are fetched so a page of older components cannot end the walk early. An asset Nexus reports without `lastModified` is still migrated.
