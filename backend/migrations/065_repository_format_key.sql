-- Add format_key column to repositories for WASM plugin format handler linkage.
-- For core formats, format_key is derived from the format enum (e.g. "maven", "rpm").
-- For WASM plugins, format_key stores the custom key (e.g. "rpm-custom", "pypi-custom").
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS format_key TEXT;
