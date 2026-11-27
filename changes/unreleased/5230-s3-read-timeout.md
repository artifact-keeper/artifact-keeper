---
section: Fixed
issues: [#5230]
---
- **An S3 read no longer stalls for 30 to 50 seconds on a dropped connection** (#5230). Object reads (cache hits included) ran on a client with no read timeout, so a pooled connection that the store or a load balancer had dropped without a reset waited out the operating system's own timeout before anything happened. Reads now use their own client with a read-inactivity timeout, `S3_READ_TIMEOUT_SECS` (default 10, `0` disables it): a request that receives nothing for that long is retried on a new connection. The timeout restarts on every byte, so long downloads are not cut. Writes and server-side copies keep the bulk client, where some stores send nothing until a long copy is done
