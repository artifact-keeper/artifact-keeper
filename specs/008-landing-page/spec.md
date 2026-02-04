# Landing Page Specification: artifactkeeper.com

**Created**: 2026-01-30
**Status**: Draft
**Owner**: Brandon Geraci

## Core Positioning

**Tagline**: "Enterprise artifact management. Actually free."

**Key differentiators to emphasize:**
1. No feature gates - security, scanning, all formats included free
2. Self-host and own your data
3. One-click migration from Artifactory
4. Open source (MIT license)

---

## Page Structure

### Section 1: Hero

**Headline**:
> "The Open-Source Artifactory Alternative"

**Subheadline**:
> "Full-featured artifact management with no feature gates, no vendor lock-in, and no surprise bills. Security scanning, all 40+ package formats, and enterprise features—included free."

**Primary CTAs** (side by side):
- **[Try Live Demo]** → Interactive sandbox with sample data
- **[Deploy in 5 Minutes]** → Quickstart docs (Docker Compose)

**Trust badges below CTAs**:
- "40+ Package Formats"
- "Security Scanning Included"
- "MIT Licensed"
- "Artifactory Migration Built-in"

---

### Section 2: The Problem (Empathy)

**Headline**: "Tired of paying enterprise prices for basic features?"

**Pain points to address**:
- "Artifactory charges extra for security scanning"
- "Feature-gated tiers that force upgrades"
- "Vendor lock-in with no easy migration path"
- "Per-user pricing that punishes growth"

**Transition**: "We built Artifact Keeper because DevOps tooling shouldn't have a paywall."

---

### Section 3: Feature Comparison (Differentiator)

**Headline**: "Everything included. No upgrade required."

| Feature | Artifact Keeper | Artifactory Pro | Artifactory Enterprise |
|---------|-----------------|-----------------|------------------------|
| All package formats | ✓ Free | ✓ | ✓ |
| Security scanning | ✓ Free | ✗ (Xray add-on) | ✗ (Xray add-on) |
| High availability | ✓ Free | ✗ | ✓ |
| Replication | ✓ Free | ✗ | ✓ |
| LDAP/SAML/OIDC | ✓ Free | ✓ | ✓ |
| REST API | ✓ Free | ✓ | ✓ |
| Migration tooling | ✓ Built-in | N/A | N/A |
| Self-hosted option | ✓ Always | ✓ | ✓ |
| Price | **$0** | ~$400/month | ~$1,400/month+ |

**Callout box**:
> "Security isn't a premium feature. It's a baseline requirement. That's why vulnerability scanning is included in every Artifact Keeper deployment—free."

---

### Section 4: Package Format Support

**Headline**: "Every package format. One registry."

**Visual**: Grid/mosaic of format logos with hover states

**Formats to display** (grouped):
- **Languages**: Maven, npm, PyPI, NuGet, Cargo, Go, RubyGems, Composer, Hex, Pub, CRAN
- **Containers & Cloud**: Docker/OCI, Helm, Terraform, Vagrant
- **ML/AI**: HuggingFace, MLModel, Conda
- **System**: Debian, RPM, Alpine, Conan
- **Other**: Generic, GitLFS, VS Code Extensions, JetBrains Plugins

**Note**: "Don't see your format? Our WASM plugin system lets you add custom formats without waiting for us."

---

### Section 5: Migration (Key Differentiator)

**Headline**: "Migrate from Artifactory in an afternoon"

**Subheadline**: "Our built-in migration tool handles everything—repositories, artifacts, metadata, users, and permissions."

**Visual**: GIF or video showing migration wizard flow

**Steps displayed**:
1. Connect to your Artifactory instance
2. Select what to migrate
3. Click start—we handle the rest
4. Verify with built-in integrity checks

**Proof point**:
> "Migrate 50,000+ artifacts with full metadata preservation. Resume interrupted migrations automatically. Zero data loss guaranteed."

**CTA**: **[See Migration Docs]** | **[Book a Migration Consultation]**

---

### Section 6: Security (Trust Builder)

**Headline**: "Security built in, not bolted on"

**Features to highlight**:
- **Vulnerability scanning**: Integrated CVE database, automatic alerts
- **Access control**: Fine-grained permissions, RBAC
- **Audit logging**: Full audit trail of all actions
- **Encryption**: At-rest and in-transit encryption standard
- **SSO**: LDAP, SAML, OIDC out of the box

**Callout**:
> "Other registries charge $30,000+/year for security scanning. We include it because securing your supply chain shouldn't be a luxury."

---

### Section 7: Deployment Options

**Headline**: "Your infrastructure. Your rules."

**Option cards**:

**Self-Hosted (Docker)**
- Spin up in 5 minutes
- Single command deployment
- Full control over your data
- **[Get Started →]**

**Self-Hosted (Kubernetes)**
- Helm chart included
- Horizontal autoscaling
- Production-ready
- **[View Helm Chart →]**

**Managed (Coming Soon)**
- We run it, you use it
- Storage-based pricing only
- No feature restrictions
- **[Join Waitlist →]**

---

### Section 8: Open Source Commitment

**Headline**: "Open source. For real."

**Content**:
> "Artifact Keeper is MIT licensed. No open-core bait-and-switch. No 'community edition' with crippled features. The code you deploy is the same code everyone gets."
>
> "View the source, audit the security, contribute improvements. That's how open source should work."

**CTA**: **[View on GitHub]**

---

### Section 9: Social Proof / Testimonials

**Headline**: "Teams shipping with Artifact Keeper"

*(Placeholder for future testimonials/logos)*

**Alternative for early stage**:
- GitHub stars count
- "Join X developers who've deployed Artifact Keeper"
- Link to community Discord/forum

---

### Section 10: Call to Action (Footer)

**Headline**: "Ready to take control of your artifacts?"

**Two-track CTA**:

**For self-starters**:
> "Deploy Artifact Keeper in 5 minutes with Docker Compose"
> **[Read the Quickstart →]**

**For migration help**:
> "Need help migrating from Artifactory? We'll walk you through it."
> **[Book a Free Consultation →]**

---

## Interactive Demo Specification

### Purpose
Let potential users explore the full UI without deploying anything. Reduce friction to "aha moment."

### Demo Environment Requirements

**Pre-populated data**:
- 4-5 repositories (maven-releases, npm-internal, docker-images, pypi-packages, helm-charts)
- ~100 sample artifacts per repo with realistic metadata
- 3 sample users with different permission levels
- Some artifacts flagged with sample vulnerabilities (to show scanning)
- Sample audit log entries

**Accessible features**:
- Full repository browsing
- Artifact detail views with metadata
- Search functionality
- Security scan results view
- Migration wizard (in read-only/preview mode)
- User/permission management (view only)
- Settings panels

**Restricted in demo**:
- Actual uploads/downloads (show toast: "Uploads disabled in demo")
- User creation/deletion
- Destructive actions

**Reset behavior**:
- Demo resets to clean state every 24 hours
- Or: each visitor gets isolated session that expires after 1 hour

### Technical Implementation

**Option A**: Static demo deployment
- Dedicated instance with read-only database
- Minimal cost, simple to maintain
- Same codebase, just restricted write permissions

**Option B**: Per-session sandboxes
- Spin up ephemeral containers per visitor
- More impressive but operationally complex
- Consider for v2

**Recommendation**: Start with Option A (static demo instance)

---

## Messaging Guidelines

### Voice & Tone
- **Direct**: No marketing fluff. DevOps people smell BS instantly.
- **Technical**: Use correct terminology. Don't dumb it down.
- **Honest**: If something isn't ready, say "coming soon" not "available."
- **Confident**: You built something good. Don't undersell it.

### Words to use:
- "Included" (not "free tier")
- "Self-host" (not "on-premise")
- "Open source" (not "community edition")
- "No feature gates"
- "Your data"

### Words to avoid:
- "Enterprise-grade" (overused, meaningless)
- "Best-in-class" (prove it instead)
- "Synergy" (obviously)
- "Free tier" (implies paid tiers have more features)

---

## Conversion Funnel

```
Landing Page
    ├── Try Demo → Explore UI → [Deploy Now] or [Book Consultation]
    ├── Deploy Now → Quickstart Docs → Success → [Join Community]
    └── Book Consultation → Calendly → Migration Discussion → Paid Engagement
```

**Key metrics to track**:
- Demo engagement (time spent, pages visited)
- Quickstart doc completion rate
- GitHub stars/forks from landing page traffic
- Consultation bookings

---

## Implementation Priority

1. **P0**: Hero section + Deploy CTA + Basic feature list
2. **P1**: Interactive demo environment
3. **P1**: Migration section with video/GIF
4. **P2**: Comparison table
5. **P2**: Security section
6. **P3**: Testimonials (need users first)
7. **P3**: Managed waitlist

---

## Open Questions

- [ ] What's the GitHub repo URL to link to?
- [ ] Do we have a Discord/community forum set up?
- [ ] Calendly or other booking tool for consultations?
- [ ] Analytics platform preference? (Plausible for privacy-respecting option)
- [ ] Domain ready? SSL configured?
