//! Repository-state metadata epoch for reproducible repository metadata.
//!
//! Signed repository metadata must be a **pure function of repository state**.
//! The bytes a client verifies and the bytes the server signs are produced by
//! two *independent* renders, in two *separate* requests:
//!
//! | format | served document        | detached signature over it |
//! |--------|------------------------|----------------------------|
//! | RPM    | `repodata/repomd.xml`  | `repodata/repomd.xml.asc`  |
//! | Debian | `dists/{d}/Release`    | `dists/{d}/Release.gpg`    |
//!
//! If any part of a render reads a wall clock, the two renders disagree
//! whenever the two requests land in different seconds — and the client
//! reports a **BAD signature on a repository nobody tampered with**. The
//! failure probability is `min(1, gap / 1s)` where `gap` is the time between
//! the two renders, so it grows with repo size, host load, and client latency
//! rather than with anything the operator can see or control. Caching the
//! render does not fix it either: a `repomd.xml` held in a client's metadata
//! cache from an earlier run can never match a freshly stamped signature.
//!
//! Deriving the metadata timestamp from repository *state* instead of `now()`
//! removes the clock from the render entirely: unchanged state renders
//! byte-identical bytes, forever, on every replica. That is also closer to
//! what `createrepo`/`apt-ftparchive` produce, and it makes the metadata
//! cacheable and reproducible.
//!
//! See #2636 (RPM `repomd.xml.asc`) and #2652 (Debian `Release.gpg`) — one
//! root cause, two formats.

use chrono::{DateTime, Utc};

/// The metadata epoch for a rendered document: the most recent `updated_at`
/// among the artifacts that document describes.
///
/// This is the timestamp to stamp into `<revision>`/`<timestamp>` (RPM) or
/// `Date:` (Debian) instead of `now()`. It is derived from exactly the rows
/// being rendered, so it changes if and only if the rendered content can
/// change, and two renders of unchanged state agree by construction — no
/// second query, and no coordination between the two handlers.
///
/// An empty repository has no state to derive from and yields the Unix epoch:
/// a repository with no packages has no meaningful metadata age, and a fixed
/// value keeps the render deterministic (`unwrap_or(now())` would reintroduce
/// exactly the bug this exists to prevent).
pub fn metadata_epoch<I>(updated_ats: I) -> DateTime<Utc>
where
    I: IntoIterator<Item = DateTime<Utc>>,
{
    updated_ats
        .into_iter()
        .max()
        .unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    #[test]
    fn test_metadata_epoch_is_the_most_recent_update() {
        assert_eq!(
            metadata_epoch(vec![at(100), at(300), at(200)]),
            at(300),
            "the epoch must track the most recently updated artifact",
        );
    }

    #[test]
    fn test_metadata_epoch_is_order_independent() {
        // The epoch must not depend on the order rows come back in, so a
        // query-plan change cannot move it.
        assert_eq!(
            metadata_epoch(vec![at(300), at(100), at(200)]),
            metadata_epoch(vec![at(100), at(200), at(300)]),
        );
    }

    #[test]
    fn test_metadata_epoch_of_empty_repo_is_the_unix_epoch() {
        // Deterministic, and — decisively — not `now()`.
        assert_eq!(metadata_epoch(vec![]), DateTime::<Utc>::UNIX_EPOCH);
        assert_eq!(metadata_epoch(vec![]).timestamp(), 0);
    }

    /// The property the signature chain depends on: the same state always
    /// yields the same epoch, no matter how much wall-clock time passes
    /// between the two renders.
    #[test]
    fn test_metadata_epoch_is_stable_across_calls() {
        let state = vec![at(1_700_000_000), at(1_600_000_000)];
        let first = metadata_epoch(state.clone());
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let second = metadata_epoch(state);
        assert_eq!(
            first, second,
            "unchanged state must yield the same epoch across a second boundary",
        );
    }
}
