---
section: Fixed
issues: [#6495]
---
- **A browser download through a presigned redirect keeps the artifact's file name** (#6495). The redirect pointed at the storage key, a digest, and the object store sent no `Content-Disposition`, so a browser saved `example.tar.gz` under the digest. The repository download route now signs the file name into the URL (`response-content-disposition` on S3 and GCS, `rscd` on Azure), and the store answers with it. A CloudFront distribution decides itself which query parameters reach the bucket, so CloudFront URLs are unchanged
