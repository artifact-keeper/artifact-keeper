-- Initialize additional databases for services
-- This script runs once when the PostgreSQL container is first created

-- Create Dependency-Track database
CREATE DATABASE dependency_track;
GRANT ALL PRIVILEGES ON DATABASE dependency_track TO registry;
