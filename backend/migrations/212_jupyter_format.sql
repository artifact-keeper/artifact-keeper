-- Add JupyterLab Extensions as a PyPI-served alias format (#3784)
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'jupyter';
