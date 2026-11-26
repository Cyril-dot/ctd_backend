import { pool } from "../config/db.js";
import { enqueueCommand } from "./gatewayCommands.js";
import { authorizeDevice } from "./gatewayPeers.js";
import { pickGateway } from "../utils/gatewaySelect.js";

// WireGuard public keys are 32 bytes -> 44-char base64 ending with '='
const WIREGUARD_KEY_RE = /^[A-Za-z0-9+/]{43}=$/;

// req.authUser is set by the session middleware in index.js
// (verified Better Auth session, or null when signed out).

// Resolve the internal users.id from the Better Auth user id.
// Devices link to users.id, not to the auth id directly.
async function getInternalUserId(authUserId) {
    const r = await pool.query(
        `SELECT id FROM users WHERE auth_user_id = $1`,
        [authUserId]
    );
    return r.rows[0]?.id ?? null;
}

// POST /devices
// Body: { public_key, device_identifier? }
const registerDevice = async (req, res) => {
    try {
        const authUser = req.authUser;
        if (!authUser) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        const { public_key, device_identifier } = req.body ?? {};

        if (!public_key || !WIREGUARD_KEY_RE.test(public_key)) {
            return res.status(400).json({
                message: "A valid WireGuard public_key is required (44-char base64)"
            });
        }

        const internalId = await getInternalUserId(authUser.id);
        if (!internalId) {
            return res.status(404).json({
                message: "User not found. Call GET /auth/user/me first to sync your profile."
            });
        }

        // Idempotency: same key already registered by this user
        const dup = await pool.query(
            `SELECT id FROM devices WHERE user_id = $1 AND public_key = $2`,
            [internalId, public_key]
        );
        if (dup.rows.length > 0) {
            return res.status(409).json({
                message: "Device already registered",
                device_id: dup.rows[0].id
            });
        }

        const result = await pool.query(
            `INSERT INTO devices (user_id, public_key, device_identifier)
             VALUES ($1, $2, $3)
             RETURNING *`,
            [internalId, public_key, device_identifier ?? null]
        );

        return res.status(201).json({
            message: "Device registered",
            device: result.rows[0]
        });
    } catch (error) {
        console.error("registerDevice error:", error);
        if (error.code === "23505") {
            return res.status(409).json({ message: "Device already registered" });
        }
        return res.status(500).json({ message: "Server error" });
    }
};

// GET /devices
const listDevices = async (req, res) => {
    try {
        const authUser = req.authUser;
        if (!authUser) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        const internalId = await getInternalUserId(authUser.id);
        if (!internalId) {
            return res.status(404).json({
                message: "User not found. Call GET /auth/user/me first to sync your profile."
            });
        }

        const result = await pool.query(
            `SELECT * FROM devices WHERE user_id = $1`,
            [internalId]
        );

        return res.status(200).json({ devices: result.rows });
    } catch (error) {
        console.error("listDevices error:", error);
        return res.status(500).json({ message: "Server error" });
    }
};

// DELETE /devices/:id
const removeDevice = async (req, res) => {
    try {
        const authUser = req.authUser;
        if (!authUser) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        const internalId = await getInternalUserId(authUser.id);
        if (!internalId) {
            return res.status(404).json({ message: "User not found" });
        }

        // Tell each gateway to drop this device's live tunnels first.
        // (Peer/sessions rows cascade on device delete, but the gateway
        // only learns about it via REVOKE_PEER.)
        const peers = await pool.query(
            `SELECT gp.id, gp.gateway_id, gp.public_key, gp.tunnel_ip
             FROM gateway_peers gp
             JOIN devices d ON d.id = gp.device_id
             WHERE gp.device_id = $1 AND d.user_id = $2
               AND gp.status IN ('pending', 'active')`,
            [req.params.id, internalId]
        );
        for (const p of peers.rows) {
            await pool.query(
                `UPDATE gateway_peers SET status = 'revoking' WHERE id = $1`,
                [p.id]
            );
            await enqueueCommand(p.gateway_id, "REVOKE_PEER", {
                peer_id: p.id,
                device_id: req.params.id,
                public_key: p.public_key,
                tunnel_ip: p.tunnel_ip,
                reason: "device_removed",
            });
        }

        const result = await pool.query(
            `DELETE FROM devices WHERE id = $1 AND user_id = $2 RETURNING id`,
            [req.params.id, internalId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "Device not found" });
        }

        return res.status(200).json({ message: "Device removed" });
    } catch (error) {
        console.error("removeDevice error:", error);
        return res.status(500).json({ message: "Server error" });
    }
};


// ---------- Self-service connect ----------

const GATEWAY_ONLINE_WINDOW = "2 minutes";
const DEFAULT_DNS = "8.8.8.8, 1.1.1.1";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Live entitlement with the latest expiry (same liveness rules as
// hasActiveEntitlement), or null.
async function getLiveEntitlement(userId) {
    const r = await pool.query(
        `SELECT kind, quota_bytes, used_bytes, expires_at FROM (
            SELECT 'trial' AS kind, quota_bytes, used_bytes, expires_at
              FROM trials
             WHERE user_id = $1 AND status = 'active'
               AND starts_at <= NOW() AND expires_at > NOW()
               AND used_bytes < quota_bytes
            UNION ALL
            SELECT 'subscription', quota_bytes, used_bytes, expires_at
              FROM subscriptions
             WHERE user_id = $1 AND status = 'active'
               AND starts_at <= NOW() AND expires_at > NOW()
               AND used_bytes < quota_bytes
         ) e ORDER BY expires_at DESC LIMIT 1`,
        [userId]
    );
    const row = r.rows[0];
    if (!row) return null;
    return {
        kind: row.kind,
        quota_bytes: Number(row.quota_bytes),
        used_bytes: Number(row.used_bytes),
        expires_at: row.expires_at,
    };
}

// Resolve the caller and their device. Sends the error response and returns
// null when the caller is signed out or doesn't own the device (404 either
// way, so ownership isn't leaked).
async function loadOwnedDevice(req, res) {
    if (!req.authUser) {
        res.status(401).json({ message: "Unauthorized" });
        return null;
    }
    const internalId = await getInternalUserId(req.authUser.id);
    if (!internalId) {
        res.status(404).json({ message: "Device not found" });
        return null;
    }
    const dev = await pool.query(
        `SELECT id, user_id, status FROM devices WHERE id = $1 AND user_id = $2`,
        [req.params.id, internalId]
    );
    if (dev.rows.length === 0) {
        res.status(404).json({ message: "Device not found" });
        return null;
    }
    return dev.rows[0];
}

function buildConfig(gw, tunnelIp) {
    return {
        address: `${tunnelIp}/32`,
        dns: (gw.wg_dns || DEFAULT_DNS)
            .split(",").map((s) => s.trim()).filter(Boolean),
        mtu: 1280,
        peer: {
            public_key: gw.wg_public_key,
            endpoint: gw.wg_endpoint,
            allowed_ips: ["0.0.0.0/0"],
            persistent_keepalive: 25,
        },
    };
}

// POST /devices/:id/connect
// Body: { gateway_id? }
// The phone holds its own private key; we only ever see the public key it
// registered via POST /devices. Returns everything needed to build the
// WireGuard config (no private key anywhere).
const connectDevice = async (req, res) => {
    try {
        const device = await loadOwnedDevice(req, res);
        if (!device) return;

        if (device.status !== "active") {
            return res.status(409).json({
                message: `Device is ${device.status}, not active`
            });
        }

        const GW_COLS = `g.id, g.name, g.wg_public_key, g.wg_endpoint, g.wg_dns,
                g.direct_endpoint, g.relay_endpoint, g.relay_connected,
                g.reachability, g.capacity_users,
                (SELECT count(*)::int FROM gateway_peers p
                  WHERE p.gateway_id = g.id AND p.status IN ('pending', 'active')) AS peer_count`;
        const current = await pool.query(
            `SELECT gateway_id FROM gateway_peers
              WHERE device_id = $1 AND status IN ('pending', 'active')
              LIMIT 1`,
            [device.id]
        );
        const currentGatewayId = current.rows[0]?.gateway_id ?? null;

        const wanted = req.body?.gateway_id;
        let candidates;
        if (wanted !== undefined && wanted !== null) {
            if (typeof wanted !== "string" || !UUID_RE.test(wanted)) {
                return res.status(404).json({ message: "Gateway not found" });
            }
            const r = await pool.query(
                `SELECT ${GW_COLS} FROM gateways g WHERE g.id = $1`,
                [wanted]
            );
            if (r.rows.length === 0) {
                return res.status(404).json({ message: "Gateway not found" });
            }
            candidates = r.rows;
        } else {
            const r = await pool.query(
                `SELECT ${GW_COLS} FROM gateways g
                  WHERE g.last_heartbeat_at > NOW() - INTERVAL '${GATEWAY_ONLINE_WINDOW}'`
            );
            candidates = r.rows;
        }

        // Remote exit-node routing: an online gateway that is reachable from
        // the internet (direct or through its relay) and has room. Never a
        // "be near the gateway" fallback.
        const choice = pickGateway(candidates, { currentGatewayId });
        if (!choice) {
            return res.status(503).json({
                code: "no_gateway_reachable",
                message: "No CTD gateway can take a new connection right now. Please try again shortly."
            });
        }
        const gw = { ...choice.gateway, wg_endpoint: choice.endpoint };

        const entitlement = await getLiveEntitlement(device.user_id);
        if (!entitlement) {
            return res.status(403).json({
                code: "no_active_entitlement",
                message:
                    "No active trial or package (expired, used up, or never claimed). " +
                    "Claim a trial or activate a package first."
            });
        }

        // Idempotent: reuse a pending/active peer on this gateway.
        const existing = await pool.query(
            `SELECT id, status, tunnel_ip FROM gateway_peers
              WHERE gateway_id = $1 AND device_id = $2
                AND status IN ('pending', 'active')
              LIMIT 1`,
            [gw.id, device.id]
        );
        let peer = existing.rows[0];
        let httpStatus = 200;

        if (!peer) {
            const result = await authorizeDevice(gw.id, device.id);
            if (result.status !== 201) {
                return res.status(result.status).json(result.body);
            }
            peer = result.body.peer;
            httpStatus = 201;
        }

        return res.status(httpStatus).json({
            status: peer.status,
            peer_id: peer.id,
            gateway: { id: gw.id, name: gw.name, path: choice.path },
            config: buildConfig(gw, peer.tunnel_ip),
            entitlement,
        });
    } catch (error) {
        console.error("connectDevice error:", error);
        return res.status(500).json({ message: "Server error" });
    }
};

// GET /devices/:id/connection — poll target for the app dashboard.
const getConnection = async (req, res) => {
    try {
        const device = await loadOwnedDevice(req, res);
        if (!device) return;

        const peer = await pool.query(
            `SELECT id, status, tunnel_ip, gateway_id FROM gateway_peers
              WHERE device_id = $1
              ORDER BY (status IN ('pending', 'active')) DESC
              LIMIT 1`,
            [device.id]
        );
        const p = peer.rows[0];

        return res.status(200).json({
            status: p?.status ?? "none",
            peer_id: p?.id ?? null,
            tunnel_ip: p?.tunnel_ip ?? null,
            gateway_id: p?.gateway_id ?? null,
            entitlement: await getLiveEntitlement(device.user_id),
        });
    } catch (error) {
        console.error("getConnection error:", error);
        return res.status(500).json({ message: "Server error" });
    }
};

export { registerDevice, listDevices, removeDevice, connectDevice, getConnection };
