---
section: Fixed
issues: [#5322]
---
- **A `HEAD` on a Remote no longer downloads the whole file from upstream and throws it away, so a new file is fetched once instead of twice** (#5322). `hf_hub_download` sends `HEAD` and then `GET` for every file it resolves. On a cache miss the `HEAD` ran the download path: it opened an upstream `GET` of the whole file and dropped the body unread, which cached nothing, so the `GET` that followed downloaded the file again. For multi-GB model weights that doubled egress and time. A cold `HEAD` is now answered from an upstream `HEAD` (same upstream filter, origin policy and Package Age Policy hold as a `GET`; a cached file is still answered from the cache), with the `ETag`, `Content-Length` and `X-Repo-Commit` `huggingface_hub` needs. An upstream that refuses `HEAD` gets the `GET` path as before. This covers every format served through the shared Remote download path (Hugging Face, RPM, RubyGems, Puppet, Hex, CRAN, Ansible, Bazel) and the Remote members of Virtual repositories of those formats.

  `ak_proxy_cache_lookups_total` now counts the streaming proxy path too, `HEAD` and `GET` alike, with the `result` values `hit`, `miss` and `negative_hit`. It used to count only buffered metadata fetches, so file and `HEAD` hits were missing from the hit ratio. See [proxy cache metrics](docs/operations/proxy-cache-metrics.md).
