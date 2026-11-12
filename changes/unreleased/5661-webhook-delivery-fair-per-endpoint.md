---
section: Fixed
issues: [#5661]
---
- **One unreachable or failing webhook receiver no longer delays every other webhook's deliveries** ([#5661]). The delivery worker claimed the 50 oldest due deliveries across all webhooks and sent them one at a time with a 30-second timeout, so a receiver with a backlog of retries (a decommissioned endpoint, a URL that always answers an error) filled every batch and a healthy webhook's new delivery could wait minutes. Each pass now fills its batch round-robin across webhooks (every webhook's oldest due delivery before any webhook's second, first attempts ahead of retries at the same rank), sends up to 8 webhooks' deliveries concurrently while keeping each webhook's own deliveries in order and one at a time, and after a failed send to an endpoint leaves that endpoint's other due deliveries for the next pass without counting an attempt. Retry backoff, `max_attempts`, dead-lettering and auto-disable are unchanged.
