---
section: Fixed
issues: [#5626]
---
- **A non-admin's delete of a hosted Go release answers 409** ([#5626]). #5780 taught the delete gate the stored layouts of hosted npm and cargo releases, hosted Go stores `<module>/<ver>/<ver>.zip` and `<module>/<ver>/go.mod`, which the classifier (it knows `/@v/`) called mutable, so a repository owner could delete a published module version. Those paths now map to their `@v/` download path before classifying, an administrator can still retract.
