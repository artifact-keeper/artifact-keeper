-- Add Incus/LXC container image format support
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'incus';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'lxc';
