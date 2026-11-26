---
section: Changed
issues: [#6358]
---
- **The generic download of a Docker manifest path streams the stored object and answers a `HEAD` without reading it** (#6358). `GET` and `HEAD /api/v1/repositories/<docker-repo>/download/v2/<name>/manifests/<ref>` learned the stored object's real length (the row's `size_bytes` is the image size, #5594) by reading the whole object into memory first, on a `HEAD` too. Nothing caps what is stored at a manifest path: the manifest `PUT` takes up to `max_upload_size_bytes`. The length now comes from the storage backend's object metadata (filesystem, S3, Azure and GCS all report it), a `GET` streams the body, and a `HEAD` runs the same download gate without opening the object and still counts no download. Responses are unchanged.
