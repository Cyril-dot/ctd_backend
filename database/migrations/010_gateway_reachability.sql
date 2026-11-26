-- Migration 010: remote exit-node routing.
-- Every gateway heartbeat reports how remote customers can reach it, so the
-- backend (the coordination server) can send a customer anywhere to a gateway
-- that is online, reachable and has capacity. Safe to re-run.
ALTER TABLE gateways
    ADD COLUMN IF NOT EXISTS direct_endpoint varchar(255),
    ADD COLUMN IF NOT EXISTS relay_endpoint varchar(255),
    ADD COLUMN IF NOT EXISTS relay_connected boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS reachability varchar(16) NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS active_clients integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS gateway_version varchar(64),
    ADD COLUMN IF NOT EXISTS reachability_reported_at timestamptz;
