import crypto from "node:crypto";
import { pool } from "../config/db.js";
import { deliverPendingCommands } from "./gatewayCommands.js";
import { expireLapsedEntitlements } from "./entitlementExpiry.js";
import { parseReachability } from "../utils/gatewaySelect.js";

// Best-effort throttle for the expiry sweep. On serverless this is per
// instance only; correctness never depends on it (the sweep is idempotent).
const EXPIRY_SWEEP_INTERVAL_MS = 30_000;
let lastExpirySweep = 0;

// Seconds after the last heartbeat before a gateway reads as offline.
const HEARTBEAT_TIMEOUT_SECONDS = Number(
    process.env.GATEWAY_HEARTBEAT_TIMEOUT_SECONDS ?? 90
);

const UUID_RE =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function hashToken(token) {
    return crypto.createHash("sha256").update(token).digest("hex");
}

// Strip the token hash and add live online/offline state.
function decorate(gw) {
    const { api_token_hash, ...publicGw } = gw;
    const lastBeat = gw.last_heartbeat_at
        ? new Date(gw.last_heartbeat_at).getTime()
        : 0;
    return {
        ...publicGw,
        is_online:
            Date.now() - lastBeat <= HEARTBEAT_TIMEOUT_SECONDS * 1000,
    };
}

// POST /gateways/register — bootstrap a gateway.
// Auth: X-Provision-Token header must match GATEWAY_PROVISIONING_TOKEN.
// Returns a gateway API token ONCE — the gateway must store it and use it
// as `Authorization: Bearer <token>` from then on.
const registerGateway = async (req, res) => {
    try {
        const provisionToken = process.env.GATEWAY_PROVISIONING_TOKEN;
        if (!provisionToken) {
            return res.status(503).json({
                message: "Gateway provisioning is not configured"
            });
        }

        const presented = Buffer.from(req.header("X-Provision-Token") ?? "");
        const expected = Buffer.from(provisionToken);
        const ok =
            presented.length === expected.length &&
            crypto.timingSafeEqual(presented, expected);
        if (!ok) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        const { gateway_uuid, name, capacity_users } = req.body ?? {};

        if (!gateway_uuid || !UUID_RE.test(gateway_uuid)) {
            return res.status(400).json({
                message: "gateway_uuid must be a valid UUID"
            });
        }
        if (!name || typeof name !== "string") {
            return res.status(400).json({ message: "name is required" });
        }
        const capacity =
            capacity_users === undefined ? 0 : Number(capacity_users);
        if (!Number.isInteger(capacity) || capacity < 0) {
            return res.status(400).json({
                message: "capacity_users must be a non-negative integer"
            });
        }

        const existing = await pool.query(
            `SELECT id FROM gateways WHERE gateway_uuid = $1`,
            [gateway_uuid]
        );
        if (existing.rows.length > 0) {
            return res.status(409).json({
                message: "Gateway already registered"
            });
        }

        const token = "ctd_gw_" + crypto.randomBytes(32).toString("hex");

        const result = await pool.query(
            `INSERT INTO gateways
                (gateway_uuid, name, status, capacity_users, last_heartbeat_at, api_token_hash)
             VALUES ($1, $2, 'online', $3, NOW(), $4)
             RETURNING *`,
            [gateway_uuid, name.trim(), capacity, hashToken(token)]
        );

        return res.status(201).json({
            message: "Gateway registered",
            gateway: decorate(result.rows[0]),
            // Shown once — store it on the gateway, it is never returned again.
            api_token: token,
        });
    } catch (error) {
        console.error("registerGateway error:", error);
        return res.status(500).json({ message: "Server error" });
    }
};

// POST /gateways/heartbeat — gateway liveness ping (gatewayAuth).
// Updates last_heartbeat_at; the gateway initiates, so the backend
// needs no inbound management port (PDF section 11).
const heartbeat = async (req, res) => {
    try {
        // Enforce time-based expiry; a failure here must not fail the ping.
        if (Date.now() - lastExpirySweep >= EXPIRY_SWEEP_INTERVAL_MS) {
            lastExpirySweep = Date.now();
            try {
                await expireLapsedEntitlements();
            } catch (sweepError) {
                console.error("expireLapsedEntitlements error:", sweepError);
            }
        }

        await pool.query(
            `UPDATE gateways
             SET last_heartbeat_at = NOW(), status = 'online'
             WHERE id = $1`,
            [req.gateway.id]
        );

        // Remote exit-node routing: record how customers can reach this
        // gateway. Older gateways send no body and keep their admin-set
        // endpoint. A malformed report never fails the heartbeat.
        const reach = parseReachability(req.body);
        if (reach) {
            try {
                await pool.query(
                    `UPDATE gateways
                        SET direct_endpoint = $2, relay_endpoint = $3,
                            relay_connected = $4, reachability = $5,
                            active_clients = $6, gateway_version = $7,
                            wg_public_key = COALESCE($8, wg_public_key),
                            reachability_reported_at = NOW()
                      WHERE id = $1`,
                    [req.gateway.id, reach.direct_endpoint, reach.relay_endpoint,
                     reach.relay_connected, reach.reachability, reach.active_clients,
                     reach.version, reach.wg_public_key]
                );
            } catch (reachError) {
                console.error("heartbeat reachability error:", reachError);
            }
        }

        // Deliver any queued control-plane commands with this heartbeat
        const commands = await deliverPendingCommands(req.gateway.id);

        return res.status(200).json({
            message: "ok",
            gateway_id: req.gateway.id,
            commands,
        });
    } catch (error) {
        console.error("heartbeat error:", error);
        return res.status(500).json({ message: "Server error" });
    }
};

// GET /gateways — list gateways with live online state.
// NOTE: any signed-in user for now; restrict to admins in task #11.
const listGateways = async (req, res) => {
    try {
        if (!req.authUser) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        const result = await pool.query(
            `SELECT * FROM gateways ORDER BY name ASC`
        );

        return res.status(200).json({
            gateways: result.rows.map(decorate),
        });
    } catch (error) {
        console.error("listGateways error:", error);
        return res.status(500).json({ message: "Server error" });
    }
};

// GET /gateways/:id — single gateway with live online state
const getGateway = async (req, res) => {
    try {
        if (!req.authUser) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        const result = await pool.query(
            `SELECT * FROM gateways WHERE id = $1`,
            [req.params.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "Gateway not found" });
        }

        return res.status(200).json({ gateway: decorate(result.rows[0]) });
    } catch (error) {
        console.error("getGateway error:", error);
        return res.status(500).json({ message: "Server error" });
    }
};

export {
    registerGateway,
    heartbeat,
    listGateways,
    getGateway,
    decorate as decorateGateway,
};
