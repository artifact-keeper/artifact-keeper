-- #5278: repodata listed an uploaded source RPM under its header's ARCH
-- (the build host's, e.g. x86_64) instead of `src`, so dnf let it satisfy
-- dependencies on the subpackages it provides. The render now lists a
-- source package as `src`, re-deriving the repodata block of every stored
-- package that may be one, but a precomputed root (#4544) is only rebuilt
-- when it changes. Mark every root holding a source package dirty so its
-- next build heals and re-renders it.
SELECT ak_rpm_repodata_mark_dirty(a.repository_id, a.path)
FROM artifacts a
WHERE a.is_deleted = false AND a.path LIKE '%.src.rpm';
