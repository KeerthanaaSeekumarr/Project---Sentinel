-- Migration: 001_create_packets_table
-- Description: Create the packets table to store traffic data
CREATE TABLE
    IF NOT EXISTS packets (
        id SERIAL PRIMARY KEY,
        timestamp VARCHAR(20) NOT NULL,
        source VARCHAR(45) NOT NULL,
        destination VARCHAR(45) NOT NULL,
        protocol VARCHAR(10) NOT NULL,
        port INTEGER NOT NULL,
        length INTEGER NOT NULL,
        severity VARCHAR(20) NOT NULL,
        type VARCHAR(50) NOT NULL,
        is_successful BOOLEAN DEFAULT FALSE,
        rule_hit BOOLEAN DEFAULT FALSE,
        ml_score FLOAT DEFAULT 0.0,
        info TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

-- Add comment to table
COMMENT ON TABLE packets IS 'Stores network traffic packets captured by TrafficEngine';