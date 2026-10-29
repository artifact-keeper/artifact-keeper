---
section: Changed
issues: [#4958]
---
- **The scan-on-proxy guide now says how the repository `artifacts` routes behave for a scanning Remote** (#4958). `docs/security/scan-on-proxy.md` gains a section covering the formats gated in 1.12.0 (Go, RubyGems, Composer, Pub, Conan, CocoaPods, Swift), which behave as the earlier formats do: the `artifacts` listing and the `artifacts/*path` metadata route serve no bytes and run no gate, the generic download route refuses proxied files with `scan_on_proxy_route_required`, the format route gates them, and an `artifacts` row a Remote holds is served from storage without a scan on both download routes. Documentation only; no behaviour change.
