---
section: Fixed
issues: [#5973]
---
- **A burst of RubyGems Remote `/versions` requests can no longer stall every format's metadata** (#5973). Each Compact Index, specs index or quick gemspec fetch on a RubyGems Remote reserved the full 128 MiB cap from the shared 1 GiB buffered-metadata budget and waited for it without a bound, so eight concurrent cold or slow `/versions` fetches held the whole budget and npm, Maven, PyPI and every other format's metadata requests queued behind them. RubyGems Remote documents now draw on a sub-budget of their own, a quarter of the shared budget by default (`AK_RUBYGEMS_REMOTE_METADATA_BUDGET_BYTES` overrides it), and a request that cannot get its share within 10 seconds answers 503 with `Retry-After`. A fresh cached document reserves its own size rather than the cap. A single request is served as before, and no configuration change is needed.
