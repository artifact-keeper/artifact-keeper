-- GitHub release mirrors share the generic handler but have their own cache policy.
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'github';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'mise';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'aqua';
