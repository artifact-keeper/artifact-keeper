---
section: Fixed
issues: [#3899]
---
- **A failed remote NuGet resolution now logs which step failed, the upstream and the status** (#3899). The reported failure (a paginated registration page such as `registration/serilog/page/0.1.6/1.2.47.json` answering 404, which `dotnet` surfaces as "Object reference not set to an instance of an object") was fixed in 1.9.0 by #3871, which added the registration page route. A remote NuGet failure still reached the log only as the request's final status; service-index discovery, registration index and page fetches, and flat-container version-list and package fetches now each record the step, the redacted upstream and fetch URLs, and the status (INFO for an upstream 404, WARN otherwise).
