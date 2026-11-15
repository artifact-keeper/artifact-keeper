---
section: Fixed
issues: [#5686]
---
- **Bundler can resolve gems through a Remote RubyGems repository on `/gems/{repo}`** (#5686). A Remote repo proxied `specs.4.8.gz` and the `.gem` files, but every endpoint Bundler resolves with answered from local rows only: the Compact Index (`/versions`, `/names`, `/info/{name}`) was not routed, the quick gemspec (`/quick/Marshal.4.8/{name}-{version}.gemspec.rz`) returned 404 for any gem not cached yet, and the Dependency API returned `[]`, so `bundle lock` and `bundle install` failed. A Remote repo now passes the upstream Compact Index and quick gemspecs through byte for byte, re-declaring any upstream `Content-Encoding` (the specs indexes now keep it too), and its Dependency API answers 404 like rubygems.org, which has retired it. Hosted and Virtual repositories keep answering 404 on the Compact Index, so Bundler still falls back to the Marshal indexes there. Contributed by @kycheng.
