-- Migration 012: endpoints discovered automatically (no hand-typed addresses).
-- lan_endpoint: the gateway's address on its own local network (from the
-- gateway); public_ip: the address its heartbeats arrive from (seen by the
-- backend); port_forwarded: the operator says UDP listen_port is forwarded.
ALTER TABLE gateways
    ADD COLUMN IF NOT EXISTS lan_endpoint varchar(255),
    ADD COLUMN IF NOT EXISTS public_ip varchar(64),
    ADD COLUMN IF NOT EXISTS listen_port integer,
    ADD COLUMN IF NOT EXISTS port_forwarded boolean NOT NULL DEFAULT false;
