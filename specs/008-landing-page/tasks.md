# Landing Page Implementation Tasks

## Phase 1: Foundation (P0)

### TASK-001: Set up landing page project structure
**Estimate**: 2 hours
**Dependencies**: None

- [ ] Decide framework (Next.js recommended for SEO, or simple static HTML)
- [ ] Initialize project in `/landing` or separate repo
- [ ] Configure deployment (Vercel, Netlify, or self-hosted)
- [ ] Set up domain and SSL for artifactkeeper.com

### TASK-002: Implement hero section
**Estimate**: 4 hours
**Dependencies**: TASK-001

- [ ] Headline: "The Open-Source Artifactory Alternative"
- [ ] Subheadline with key differentiators
- [ ] Two CTA buttons: "Try Live Demo" + "Deploy in 5 Minutes"
- [ ] Trust badges row (40+ formats, security included, MIT, migration)
- [ ] Responsive design for mobile

### TASK-003: Create basic feature grid
**Estimate**: 3 hours
**Dependencies**: TASK-001

- [ ] "Everything included" section
- [ ] Comparison table vs Artifactory tiers
- [ ] Highlight $0 price with full features
- [ ] Security callout box

### TASK-004: Build deployment options section
**Estimate**: 2 hours
**Dependencies**: TASK-001

- [ ] Docker self-hosted card → links to quickstart
- [ ] Kubernetes card → links to Helm chart (once ready)
- [ ] Managed "Coming Soon" card with waitlist signup

### TASK-005: Footer with dual CTA
**Estimate**: 1 hour
**Dependencies**: TASK-001

- [ ] "Deploy now" path for self-starters
- [ ] "Book consultation" path for migration help
- [ ] Links: GitHub, Docs, Community

---

## Phase 2: Interactive Demo (P1)

### TASK-006: Provision demo environment
**Estimate**: 4 hours
**Dependencies**: Working Artifact Keeper deployment

- [ ] Deploy dedicated demo instance
- [ ] Configure read-only mode / restricted writes
- [ ] Set up demo.artifactkeeper.com subdomain
- [ ] SSL and basic rate limiting

### TASK-007: Populate demo with sample data
**Estimate**: 3 hours
**Dependencies**: TASK-006

- [ ] Create sample repositories (maven, npm, docker, pypi, helm)
- [ ] Generate realistic artifacts with metadata (~100 per repo)
- [ ] Create sample users with different roles
- [ ] Add sample security scan results (some vulnerabilities)
- [ ] Populate audit log with realistic entries

### TASK-008: Demo UI restrictions
**Estimate**: 2 hours
**Dependencies**: TASK-006

- [ ] Disable upload/delete operations with friendly toast messages
- [ ] Migration wizard in preview/read-only mode
- [ ] Hide sensitive admin functions
- [ ] Add "This is a demo" banner with link to deploy

### TASK-009: Demo reset automation
**Estimate**: 2 hours
**Dependencies**: TASK-007

- [ ] Script to reset demo to clean state
- [ ] Schedule daily reset (cron or K8s CronJob)
- [ ] Or: implement session-based isolation (more complex)

---

## Phase 3: Migration Showcase (P1)

### TASK-010: Create migration demo video/GIF
**Estimate**: 3 hours
**Dependencies**: Working migration tool

- [ ] Screen record migration wizard flow
- [ ] Edit to ~30-60 seconds
- [ ] Add captions/annotations
- [ ] Compress for web (GIF or WebM)

### TASK-011: Migration section on landing page
**Estimate**: 2 hours
**Dependencies**: TASK-001, TASK-010

- [ ] "Migrate from Artifactory" section
- [ ] Embed video/GIF
- [ ] Step-by-step visual
- [ ] CTAs: docs + consultation booking

---

## Phase 4: Package Format Grid (P2)

### TASK-012: Design format logo grid
**Estimate**: 3 hours
**Dependencies**: TASK-001

- [ ] Gather/create logos for all 40+ formats
- [ ] Design responsive grid layout
- [ ] Group by category (languages, containers, ML, system)
- [ ] Hover states with format names

### TASK-013: Implement format grid component
**Estimate**: 2 hours
**Dependencies**: TASK-012

- [ ] Build responsive grid
- [ ] Add "WASM plugin" callout for custom formats
- [ ] Link to format-specific docs where available

---

## Phase 5: Security Deep-Dive (P2)

### TASK-014: Security features section
**Estimate**: 2 hours
**Dependencies**: TASK-001

- [ ] Vulnerability scanning explanation
- [ ] Access control / RBAC
- [ ] Audit logging
- [ ] Encryption details
- [ ] SSO options (LDAP, SAML, OIDC)
- [ ] Callout: "Free, not an add-on"

---

## Phase 6: Infrastructure & Analytics (P2)

### TASK-015: Set up analytics
**Estimate**: 2 hours
**Dependencies**: TASK-001

- [ ] Choose platform (Plausible recommended for privacy)
- [ ] Install tracking
- [ ] Set up conversion goals (demo clicks, deploy clicks, consultation bookings)

### TASK-016: Set up consultation booking
**Estimate**: 1 hour
**Dependencies**: None

- [ ] Create Calendly (or Cal.com for open-source option)
- [ ] Configure availability
- [ ] Set up intake questions (current setup, migration scope, timeline)
- [ ] Embed/link from landing page

### TASK-017: Set up waitlist for managed offering
**Estimate**: 1 hour
**Dependencies**: TASK-001

- [ ] Simple email collection form
- [ ] Store in database or use Buttondown/Mailchimp
- [ ] Confirmation email

---

## Phase 7: Community & Social Proof (P3)

### TASK-018: Set up community platform
**Estimate**: 2 hours
**Dependencies**: None

- [ ] Create Discord server or GitHub Discussions
- [ ] Set up channels (general, support, feature-requests, showcase)
- [ ] Link from landing page

### TASK-019: GitHub presence polish
**Estimate**: 2 hours
**Dependencies**: None

- [ ] Ensure README is landing-page quality
- [ ] Add badges (build status, license, stars)
- [ ] Contributing guide
- [ ] Issue templates

### TASK-020: Testimonial collection system
**Estimate**: Future
**Dependencies**: Actual users

- [ ] Reach out to early adopters for quotes
- [ ] Create testimonial section once available
- [ ] Consider case study format for larger migrations

---

## Total Estimates

| Phase | Hours |
|-------|-------|
| Phase 1: Foundation | ~12 hours |
| Phase 2: Interactive Demo | ~11 hours |
| Phase 3: Migration Showcase | ~5 hours |
| Phase 4: Format Grid | ~5 hours |
| Phase 5: Security Section | ~2 hours |
| Phase 6: Infrastructure | ~4 hours |
| Phase 7: Community | ~4+ hours |

**Total MVP (Phases 1-3)**: ~28 hours
**Full Landing Page**: ~43+ hours
