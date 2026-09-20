-- Issue #4033 / #4045 / #4056: record what is actually *inside* a package.
--
-- WHY THIS IS NOT scan_packages
-- `scan_packages` (085) is the inventory a *scanner engine* reported: one row
-- per package Grype or Trivy cataloged, keyed on scan_result_id. It answers
-- "what did the engine see on this run".
--
-- These tables answer a different question: "what did we learn by reading the
-- artifact's own bytes at ingest". For conda that is the vendored native
-- libraries declared in `info/recipe/` and the install-time scripts in the
-- payload -- neither of which any scanner engine reports, because conda
-- metadata never names them. A conda package that vendors libwebp is reported
-- by every engine as clean; the recipe is the only place the truth is written
-- down.
--
-- They are therefore ingest-scoped, not scan-scoped: computed once when the
-- artifact is stored, valid until the bytes change, and readable without a
-- scan having run. Folding them into scan_packages would tie facts about the
-- artifact to the lifecycle of a scan row and lose them on rescan.
--
-- SCOPE
-- Hosted artifacts only. Proxy content deliberately has no `artifacts` row
-- (#1278/#1280), so the FK below excludes it by construction -- the same
-- constraint that blocked proxy SBOMs from `sbom_documents`. Extending this to
-- proxied content is deliberately out of scope here; see the proxy-SBOM design
-- (docs/plans/2026-08-14-proxy-sbom-design.md) for the pattern that works
-- there, which is to persist the inventory and generate the document on demand.

-- One row per analyzed artifact: did we manage to read it, and how much.
--
-- `status` is the honest-reporting primitive for #4047. The distinction that
-- matters is 'complete' (we read the payload and found what we found) versus
-- 'not_read' (we never opened it). Rendering the second as clean is the
-- failure mode this whole epic exists to remove, so the column is NOT NULL
-- with no default -- a writer must state which case it is.
CREATE TABLE IF NOT EXISTS package_analysis (
    artifact_id UUID PRIMARY KEY REFERENCES artifacts(id) ON DELETE CASCADE,
    format TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (status IN ('complete', 'partial', 'not_read', 'unsupported')),
    -- Human-readable explanation, required whenever the payload was not fully
    -- read. Surfaced verbatim in the UI tooltip, so it must be a sentence a
    -- user can act on ("archive exceeded the 2 GiB extraction ceiling"), not
    -- an error code.
    reason TEXT,
    files_total INTEGER,
    files_read INTEGER,
    analyzed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT package_analysis_reason_present_when_incomplete
        CHECK (status = 'complete' OR reason IS NOT NULL)
);

-- Native libraries compiled into the package, as declared by its recipe.
--
-- `confidence` records how we know. 'declared' means the recipe named this
-- source explicitly; 'inferred' means we derived the name from a source URL;
-- 'unresolved' means a template expression could not be evaluated and the
-- version is unknown. An unresolved row is still worth storing -- it tells a
-- reader that a source exists and we could not pin it, which is materially
-- different from the package having no vendored code.
CREATE TABLE IF NOT EXISTS package_vendored_components (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id UUID NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    version TEXT,
    purl TEXT,
    source_url TEXT,
    git_url TEXT,
    git_rev TEXT,
    sha256 TEXT,
    -- Applied patches, as a JSON array of {name, description?, source_url?}.
    -- A backported fix showing up as the unpatched upstream version is a false
    -- positive we specifically must avoid, so the patch list travels with the
    -- component rather than being dropped.
    applied_patches JSONB NOT NULL DEFAULT '[]'::jsonb,
    confidence TEXT NOT NULL
        CHECK (confidence IN ('declared', 'inferred', 'unresolved')),
    detection_method TEXT,
    -- The library's own linker name, where the packaging tool preserved it
    -- (`libwebp.so.7.1.3`). For a wheel this is the most useful single string
    -- to show a reviewer, because the file on disk has been renamed.
    soname TEXT,
    -- The ELF/libtool ABI version, kept DELIBERATELY SEPARATE from `version`.
    --
    -- These are different numbering schemes and conflating them is actively
    -- dangerous: `libwebp.so.7` ships in libwebp 1.2.4, and
    -- `libjpeg.so.62.3.0` ships in libjpeg-turbo 2.1.4. Writing 7 or 62.3.0
    -- into `version` would hand a CVE matcher a number from the wrong scheme
    -- that matches confidently and wrongly -- worse than no version at all.
    --
    -- So `version` stays NULL unless a real upstream release number was
    -- recovered, and the ABI tail lives here where nothing will match on it.
    abi_version TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Install-time scripts (post-link / pre-link / pre-unlink) and their static
-- analysis findings. These execute as the installing user, which makes their
-- mere presence a fact worth surfacing even before any rule fires.
CREATE TABLE IF NOT EXISTS package_install_scripts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id UUID NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    kind TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    sha256 TEXT NOT NULL,
    -- NULL when the script was detected but its bytes could not be read (a
    -- capped extraction, a non-UTF8 body). Distinct from an empty string,
    -- which means a genuinely empty script.
    body TEXT,
    -- Findings as a JSON array of
    -- {rule_id, severity, title, description?, line?, snippet?}.
    -- Stored denormalized: findings are only ever read alongside their script,
    -- are rewritten wholesale when rules change, and are never aggregated
    -- across artifacts -- so a child table would buy nothing.
    --
    -- NULL is NOT the same as '[]'. An empty array means "we ran the rules and
    -- nothing matched"; NULL means "we did not run the rules at all", which
    -- happens when a script declares an interpreter the engine does not read
    -- (an RPM scriptlet with PREINPROG = /usr/bin/lua, a Perl maintainer
    -- script). Running shell regexes over Lua is wrong in both directions --
    -- it misses real behaviour and invents matches -- so the honest outcome is
    -- to record that the script exists, note that it runs, and decline to
    -- judge it.
    --
    -- This is the same distinction `package_analysis.status` draws for the
    -- package as a whole, applied per script: "clean" and "unexamined" must
    -- never render alike.
    findings JSONB,
    -- Required whenever `findings` is NULL, for the same reason
    -- `package_analysis.reason` is required whenever status is not 'complete':
    -- an unexamined artifact must carry the explanation with it, not leave a
    -- reader to guess.
    analysis_skipped_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT package_install_scripts_skip_reason_present
        CHECK (findings IS NOT NULL OR analysis_skipped_reason IS NOT NULL)
);

-- The read paths: both panels load everything for one artifact, in one query.
CREATE INDEX IF NOT EXISTS package_vendored_components_artifact_id_idx
    ON package_vendored_components (artifact_id);
CREATE INDEX IF NOT EXISTS package_install_scripts_artifact_id_idx
    ON package_install_scripts (artifact_id);

-- Re-analysis must be idempotent: analyzing the same artifact twice may not
-- double the component list. Name+version is the identity because the same
-- library can legitimately appear twice at different versions in a
-- multi-output recipe. NULLs are coalesced so a version-less row still
-- deduplicates rather than inserting unbounded copies.
CREATE UNIQUE INDEX IF NOT EXISTS package_vendored_components_unique_idx
    ON package_vendored_components (artifact_id, name, COALESCE(version, ''));
CREATE UNIQUE INDEX IF NOT EXISTS package_install_scripts_unique_idx
    ON package_install_scripts (artifact_id, path);
