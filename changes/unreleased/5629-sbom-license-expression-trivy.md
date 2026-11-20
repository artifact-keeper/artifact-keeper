---
section: Fixed
issues: [#5629]
---
- **SBOM license expressions survive when the Trivy filesystem scanner also catalogued the package** (#5629). With the Trivy filesystem scanner enabled, as in a standard Helm install, a component licensed `MIT AND PSF-2.0` or `Public Domain` came out of the CycloneDX SBOM (and the Dependency-Track submission) as `LicenseRef-MIT-AND-PSF-2.0` / `LicenseRef-Public-Domain` instead of an `expression` / the license text. Trivy stores a license it cannot read as one SPDX id in that wrapped form, Grype stores the text, and the merge kept whichever row came first. A `LicenseRef-` license that is exactly the wrapped form of the other scanner's text now gives way to that text; licenses that differ are never swapped.
