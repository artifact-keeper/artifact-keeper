---
section: Fixed
issues: [#3977]
---
- **The promotion endpoints document `400` for a validation refusal, which is the status they have always returned** (#3977). Every `#[utoipa::path]` on the promotion handlers listed `422 Unprocessable Entity` for repository-shape, package-format, release-link and not-a-staging-repository refusals, while `AppError::Validation` maps to `400 Bad Request` throughout the API. The OpenAPI document is the input to the SDKs that `artifact-keeper-web` and `artifact-keeper-cli` consume, so a client branching on the documented code never matched the response it actually got. The five annotations are corrected to `400`; **runtime behaviour is unchanged** and no request that works today changes its status. A downstream consumer that coded against the published `422` for these five operations should re-generate its SDK and expect `400`.
