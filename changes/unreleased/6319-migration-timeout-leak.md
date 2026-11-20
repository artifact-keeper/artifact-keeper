---
section: Fixed
issues: [#6319]
---
- **Startup migrations no longer leave a 30-minute statement timeout and a 5-minute lock timeout on an application database connection** (#6319). The migration connection is now closed afterwards instead of being returned to the pool (and keeps its pool slot until then), so normal queries keep the operator-configured defaults.
