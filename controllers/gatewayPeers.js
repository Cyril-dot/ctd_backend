import { pool } from "../config/db.js";
import { enqueueCommand } from "./gatewayCommands.js";

// Tunnel IP pool for WireGuard peers (V1): 10.8.0.2 - 10.8.0.254,
// allocated sequentially per gateway.
const TUNNEL_BASE = "10.8.0";

async function allocateTunnelIp(gatewayId) {
    const r = await pool.query(
        `SELECT tunnel_ip FROM gateway_peers WHERE gateway_id = $1`,
        [gatewayId]
    );
    const used = new Set();
    for (const row of r.rows) {
        const m = /^10\.8\.0\.(\d+)$/.exec(row.tunnel_ip ?? "");
        if (m) used.add(Number(m[1]));
    }
    for (let i = 2; i <= 254; i++) {
        if (!used.has(i)) return `${TUNNEL_BASE}.${i}`;
    }
    return null;
}

async function requireOperator(req, res) {
    if (!req.authUser) {
        res.status(401).json({ message: "Unauthorized" });
        return false;
    }
    return true;
}

// GET /gateways/:id/peers — list peers on a gateway
const listPeers = async (req, res) => {
    try {
        if (!(await requireOperator(req, res))) return;

        const result = await pool.query(
            `SELECT gp.*, d.device_identifier
             FROM gateway_peers gp
             LEFT JOIN devices d ON d.id = gp.device_id
             WHERE gp.gateway_id = $1
             ORDER BY gp.tunnel_ip ASC`,
            [req.params.id]
        );

        return res.status(200).json({ peers: result.rows });
    } catch (error) {
        console.error("listPeers error:", error);
        return res.status(500).json({ message: "Server error" });
    }
};

// hasActiveEntitlement reports whether a user currently holds a trial or
// subscription that is active, inside its time window, and not used up.
const hasActiveEntitlement = async (userId) => {
    if (!userId) return false;
    const result = await pool.query(
        `SELECT 1 FROM trials
          WHERE user_id = $1 AND status = 'active'
            AND starts_at <= NOW() AND expires_at > NOW()
            AND used_bytes < quota_bytes
         UNION ALL
         SELECT 1 FROM subscriptions
          WHERE user_id = $1 AND status = 'active'
            AND starts_at <= NOW() AND expires_at > NOW()
            AND used_bytes < quota_bytes
         LIMIT 1`,
        [userId]
    );
    return result.rows.length > 0;
};

// authorizeDevice — shared core of the admin route and the customer connect
// endpoint. Returns { status, body } (an HTTP code and JSON body) and never
// touches req/res. Throws only on unexpected errors.
const MAX_IP_ATTEMPTS = 5;

const authorizeDevice = async (gatewayId, deviceId) => {
    const gw = await pool.query(
        `SELECT id FROM gateways WHERE id = $1`,
        [gatewayId]
    );
    if (gw.rows.length === 0) {
        return { status: 404, body: { message: "Gateway not found" } };
    }

    const dev = await pool.query(
        `SELECT id, user_id, public_key FROM devices WHERE id = $1`,
        [deviceId]
    );
    if (dev.rows.length === 0) {
        return { status: 404, body: { message: "Device not found" } };
    }

    // Entitlement gate: a device may only be peered while its owner holds
    // a live trial or subscription. Without this, an operator could hand
    // free internet to any registered device. "Live" uses the same rules
    // usage ingestion relies on (status 'active', quota not used up) plus
    // the time window, so a lapsed trial or package is refused too.
    if (!(await hasActiveEntitlement(dev.rows[0].user_id))) {
        return {
            status: 403,
            body: {
                code: "no_active_entitlement",
                message:
                    "The device owner has no active trial or package (expired, used up, or never claimed). " +
                    "Claim a trial or activate a package first."
            }
        };
    }

    const dup = await pool.query(
        `SELECT id FROM gateway_peers
         WHERE gateway_id = $1 AND device_id = $2
           AND status IN ('pending', 'active')`,
        [gatewayId, deviceId]
    );
    if (dup.rows.length > 0) {
        return {
            status: 409,
            body: { message: "Device is already peered on this gateway" }
        };
    }

    // unique_gateway_device blocks re-authorizing a device whose old
    // peer row lingers in a terminal state — clear those first.
    await pool.query(
        `DELETE FROM gateway_peers
         WHERE gateway_id = $1 AND device_id = $2
           AND status IN ('revoked', 'error', 'inactive')`,
        [gatewayId, deviceId]
    );

    // Allocation is SELECT-then-INSERT, so two concurrent callers can pick the
    // same IP; the unique index on (gateway_id, tunnel_ip) rejects the loser
    // with 23505 and we simply allocate again.
    let peer = null;
    let tunnel_ip = null;
    for (let attempt = 0; attempt < MAX_IP_ATTEMPTS; attempt++) {
        tunnel_ip = await allocateTunnelIp(gatewayId);
        if (!tunnel_ip) {
            return {
                status: 507,
                body: { message: "No free tunnel IPs left on this gateway" }
            };
        }
        try {
            peer = await pool.query(
                `INSERT INTO gateway_peers
                    (gateway_id, device_id, tunnel_ip, public_key, status)
                 VALUES ($1, $2, $3, $4, 'pending')
                 RETURNING *`,
                [gatewayId, deviceId, tunnel_ip, dev.rows[0].public_key]
            );
            break;
        } catch (err) {
            if (err.code !== "23505") throw err;
            if (err.constraint === "unique_gateway_device") {
                return {
                    status: 409,
                    body: { message: "Device is already peered on this gateway" }
                };
            }
            // tunnel_ip collision: retry with a fresh allocation
        }
    }
    if (!peer) {
        return {
            status: 503,
            body: { message: "Could not allocate a tunnel IP, please retry" }
        };
    }

    const command = await enqueueCommand(gatewayId, "AUTHORIZE_PEER", {
        peer_id: peer.rows[0].id,
        device_id: deviceId,
        public_key: dev.rows[0].public_key,
        tunnel_ip,
    });

    return {
        status: 201,
        body: {
            message: "Peer authorization queued — applies on next gateway heartbeat",
            peer: peer.rows[0],
            command_id: command.message_id,
        }
    };
};

// POST /gateways/:id/peers — authorize a device as a WireGuard peer.
// Body: { device_id }
// Creates the peer row (status 'pending'), queues AUTHORIZE_PEER; the peer
// flips to 'active' when the gateway acks the command.
// NOTE: any signed-in user for now; restrict to admins in task #11.
const authorizePeer = async (req, res) => {
    try {
        if (!(await requireOperator(req, res))) return;

        const { device_id } = req.body ?? {};
        // Keep the original check order: unknown gateway (404) before a
        // missing device_id (400).
        const gw = await pool.query(
            `SELECT id FROM gateways WHERE id = $1`,
            [req.params.id]
        );
        if (gw.rows.length === 0) {
            return res.status(404).json({ message: "Gateway not found" });
        }
        if (!device_id) {
            return res.status(400).json({ message: "device_id is required" });
        }

        const { status, body } = await authorizeDevice(req.params.id, device_id);
        return res.status(status).json(body);
    } catch (error) {
        console.error("authorizePeer error:", error);
        return res.status(500).json({ message: "Server error" });
    }
};

// DELETE /gateways/:id/peers/:peerId — revoke a peer.
// Marks 'revoking', queues REVOKE_PEER; flips to 'revoked' on gateway ack.
const revokePeer = async (req, res) => {
    try {
        if (!(await requireOperator(req, res))) return;

        const peer = await pool.query(
            `SELECT * FROM gateway_peers WHERE id = $1 AND gateway_id = $2`,
            [req.params.peerId, req.params.id]
        );
        if (peer.rows.length === 0) {
            return res.status(404).json({ message: "Peer not found" });
        }
        if (!["pending", "active"].includes(peer.rows[0].status)) {
            return res.status(409).json({
                message: `Peer is already ${peer.rows[0].status}`
            });
        }

        await pool.query(
            `UPDATE gateway_peers SET status = 'revoking' WHERE id = $1`,
            [peer.rows[0].id]
        );

        const command = await enqueueCommand(req.params.id, "REVOKE_PEER", {
            peer_id: peer.rows[0].id,
            device_id: peer.rows[0].device_id,
            public_key: peer.rows[0].public_key,
            tunnel_ip: peer.rows[0].tunnel_ip,
        });

        return res.status(200).json({
            message: "Peer revocation queued — applies on next gateway heartbeat",
            command_id: command.message_id,
        });
    } catch (error) {
        console.error("revokePeer error:", error);
        return res.status(500).json({ message: "Server error" });
    }
};

export { listPeers, authorizePeer, authorizeDevice, revokePeer, hasActiveEntitlement };
