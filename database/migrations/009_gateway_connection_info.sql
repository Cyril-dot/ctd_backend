-- Migration 009: gateway WireGuard connection info + tunnel IP uniqueness
-- Safe to re-run: every statement is guarded.
--
-- A customer app that connects itself needs the gateway's WireGuard public
-- key and the host:port customers dial. wg_dns is a comma-separated list
-- (the API falls back to "8.8.8.8, 1.1.1.1" when NULL).
ALTER TABLE gateways
    ADD COLUMN IF NOT EXISTS wg_public_key text,
    ADD COLUMN IF NOT EXISTS wg_endpoint varchar(255),
    ADD COLUMN IF NOT EXISTS wg_dns varchar(255);

-- Tunnel IP allocation is SELECT-then-INSERT; this index makes a lost race
-- fail with 23505 (which the API retries) instead of handing out one IP twice.
CREATE UNIQUE INDEX IF NOT EXISTS gateway_peers_gateway_tunnel_ip_uniq
    ON gateway_peers (gateway_id, tunnel_ip);
