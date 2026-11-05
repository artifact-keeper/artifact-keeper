---
section: Fixed
issues: [#5293]
---
- **A peer subscription or sync policy can no longer be created with the `pull` replication mode, which was accepted, was the default, and never replicated anything** (#5293). Only `push` and `mirror` subscriptions ever got sync tasks, so a subscription made with `pull`, or with no mode at all, silently never moved a byte. `POST /api/v1/peers/{id}/repositories` and the sync-policy create and update routes now refuse `pull` with 400 and a message that names `push` and `mirror`; an omitted mode is `push` on both entry points, and the column default is `push` too (migration 330). Sync policies also reject an unknown mode at write time instead of failing later at evaluation. Existing `pull` subscriptions and policies are left unchanged, logged once at startup, and subscriptions report a new `effective` field (`active` or `inactive`), so a row that never replicates says so.

  The new [air-gapped deployment guide](docs/air-gapped.md) collects what a disconnected install needs: topologies, images, the Remote settings, the scanners' databases, the background jobs that reach out and how to turn each off, format notes, and a verification checklist. A unit test checks that every Artifact Keeper env var and API route the guide names exists in the tree.
