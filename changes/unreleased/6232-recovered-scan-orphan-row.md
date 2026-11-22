---
section: Fixed
issues: [#6232]
---
- **A scan whose worker died mid-scan no longer shows as in progress for 30 minutes after the durable scan queue recovers it** (#6232). When a replica died holding a scan job, the surviving replica re-ran the job into a new `scan_results` row, and the dead worker's row stayed `running` until the stuck-scan janitor failed it after 1800 s, so the UI, the API and anything waiting for "no running scans" saw a phantom scan. Each row a queued job creates now records the job's claim (migration 410 adds the nullable `scan_results.queue_claim_token` column), and the sweep that recovers a lapsed claim fails that claim's `running` rows in the same statement, with a reason naming the recovery. A row another worker's live claim is writing, or one an in-process scan created, is not touched. A worker that was only slow, not dead, finds its claim gone when it finishes and leaves the rows as recovery recorded them instead of overwriting them.
