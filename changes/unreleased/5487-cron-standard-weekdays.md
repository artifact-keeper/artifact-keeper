---
section: Fixed
issues: [#5487]
---
- **5-field cron schedules run on the weekday they name** (#5487). Backup schedules and lifecycle policies take standard 5-field cron, but the weekday field went to the `cron` crate unchanged, and it numbers weekdays 1-7 from Sunday where standard cron numbers them 0-7 with 0 and 7 both Sunday. So `0 3 * * 1` ran on Sunday instead of Monday, every numeric weekday ran one day early, and `0 3 * * 0` was refused as invalid. Numeric weekdays, ranges, lists and steps in a 5-field expression are now translated to day names before parsing. Day names were already read correctly, and 6- and 7-field expressions keep the crate's own numbering. Upgrading: a schedule written with numeric weekdays moves to the day it names, one day later than it has been running.
