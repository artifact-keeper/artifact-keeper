---
section: Added
issues: [#6288]
---
- **`S3_VIRTUAL_HOSTED_STYLE=true` addresses the bucket in the hostname, so presigned download redirects can be allow-listed by host** (#6288). The S3 client always used path-style URLs (`https://s3.<region>.amazonaws.com/<bucket>/<key>`), so a redirect shared its hostname with every other bucket in the region and a proxy that matches on hostname, such as a TLS-inspecting corporate proxy's bypass list, could not single out the artifact bucket. The new opt-in setting turns on `object_store`'s virtual-hosted-style requests (`https://<bucket>.s3.<region>.amazonaws.com/<key>`) for the backend's own requests and presigned URLs alike. Default stays path-style.
