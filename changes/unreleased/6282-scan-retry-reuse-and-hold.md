---
section: Fixed
issues: [#6282]
---
- **A retried scan that reuses an identical scan now completes, and a recorded scan failure keeps blocking while its retry runs** (#6282). In 1.12.3's retry of a queued scan whose scanner hit the job deadline (#5942), two gaps remained. If a byte-identical artifact's scan completed during the backoff, the retry reused it but left the artifact's row `failed`, with the first attempt's partial findings and its `block_on_fail` hold. And when the retry started, the row read `running`, so `block_on_fail` stopped refusing downloads, and another scanner's verdict could release the hold before the retry finished. The retry now reopens the row before the reuse check, so a reuse completes it with the source's findings. While the retry runs, the row keeps counting as the recorded failure (its error reads "retrying after a failed attempt: ..."), and the attempt's findings stay until the retry replaces them in one transaction.
