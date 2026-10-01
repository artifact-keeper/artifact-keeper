---
section: Fixed
issues: [#3737]
---
- **Proxy-cache publishes work on Google Cloud Storage's S3-compatible API** (#3737). GCS answers a PUT without `Content-Length` with `411 Length Required`, including the empty-bodied CopyObject that moves a staged proxy-cache object to its live key, so on `STORAGE_BACKEND=s3` pointed at `storage.googleapis.com` every publish failed and the cache never filled. A copy rejected with 411 is now retried as a signed CopyObject carrying `Content-Length: 0`, and the backend uses that form for every later copy; the multipart `UploadPartCopy` path sends the header too.
