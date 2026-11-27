-- Migration 011: customer notifications (news, maintenance, outages).
-- Live gateway up/down status is NOT stored here: GET /notifications derives
-- it from heartbeats on every request, so it can never go stale.
CREATE TABLE IF NOT EXISTS notifications (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    title varchar(120) NOT NULL,
    body text NOT NULL,
    kind varchar(16) NOT NULL DEFAULT 'info',   -- info | maintenance | outage | resolved | offer
    gateway_id uuid REFERENCES gateways(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    expires_at timestamptz
);
CREATE INDEX IF NOT EXISTS notifications_created_idx ON notifications (created_at DESC);
