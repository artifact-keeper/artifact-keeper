---
section: Fixed
issues: [#5168, #4989]
---
- **Storage scrub repair now checks `max_bytes` between donor copies** (#5168, #4989). The repair loop read up to five donor copies without looking at the budget, so a run of corrupt donors could overshoot it by several object sizes. It now stops between donors once the budget is spent. The first donor is always tried, so an object as large as the budget can still be repaired, and a copy that verified is always written. A repair stopped this way records that it hit the byte budget, not "no verified good copy available", since the copies it did not read may be good; a later run retries it.
