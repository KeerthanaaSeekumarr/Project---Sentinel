-- Migration: 002_add_indexes
-- Description: Add indexes for common query patterns
-- Index for timestamp-based queries (sorting, filtering by time)
CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets (timestamp);

-- Index for severity filtering (dashboard filters)
CREATE INDEX IF NOT EXISTS idx_packets_severity ON packets (severity);

-- Index for type filtering (attack type analysis)
CREATE INDEX IF NOT EXISTS idx_packets_type ON packets (type);

-- Index for source IP filtering (IP range queries)
CREATE INDEX IF NOT EXISTS idx_packets_source ON packets (source);

-- Index for successful attacks (breach analysis)
CREATE INDEX IF NOT EXISTS idx_packets_is_successful ON packets (is_successful);

-- Composite index for common dashboard queries
CREATE INDEX IF NOT EXISTS idx_packets_severity_type ON packets (severity, type);