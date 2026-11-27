import { pool } from "../config/db.js";

const KINDS = new Set(["info", "maintenance", "outage", "resolved", "offer"]);
const ONLINE_SECONDS = Number(process.env.GATEWAY_HEARTBEAT_TIMEOUT_SECONDS ?? 90);

async function internalUserId(authUserId) {
    const r = await pool.query(`SELECT id FROM users WHERE auth_user_id = $1`, [authUserId]);
    return r.rows[0]?.id ?? null;
}

// GET /notifications — news for the signed-in customer, newest first:
// live status of the gateway(s) their devices use (derived from heartbeats,
// so an outage shows within about 90 seconds) plus posted announcements.
const listNotifications = async (req, res) => {
    try {
        if (!req.authUser) return res.status(401).json({ message: "Unauthorized" });
        const userId = await internalUserId(req.authUser.id);

        // Gateways this customer is on; if none yet, every gateway.
        const mine = await pool.query(
            `SELECT DISTINCT g.id, g.name, g.last_heartbeat_at
               FROM gateways g
               JOIN gateway_peers p ON p.gateway_id = g.id
               JOIN devices d ON d.id = p.device_id
              WHERE d.user_id = $1 AND p.status IN ('pending', 'active')`,
            [userId]
        );
        const gws = mine.rows.length
            ? mine.rows
            : (await pool.query(`SELECT id, name, last_heartbeat_at FROM gateways`)).rows;

        const now = Date.now();
        const status = gws.map((g) => {
            const last = g.last_heartbeat_at ? new Date(g.last_heartbeat_at).getTime() : 0;
            const online = last > 0 && now - last <= ONLINE_SECONDS * 1000;
            return {
                id: `status-${g.id}`,
                kind: online ? "status_online" : "status_offline",
                title: online ? `${g.name} is online` : `${g.name} is down`,
                body: online
                    ? "Everything is working normally."
                    : "We are working on it. You will be able to connect again as soon as it is back.",
                gateway_id: g.id,
                created_at: online ? new Date(now).toISOString() : (g.last_heartbeat_at ?? new Date(now).toISOString()),
                live: true,
            };
        });

        const news = await pool.query(
            `SELECT id, title, body, kind, gateway_id, created_at
               FROM notifications
              WHERE (expires_at IS NULL OR expires_at > NOW())
              ORDER BY created_at DESC
              LIMIT 50`
        );
        return res.status(200).json({ status, notifications: news.rows });
    } catch (error) {
        console.error("listNotifications error:", error);
        return res.status(500).json({ message: "Server error" });
    }
};

// POST /admin/notifications — post news, maintenance notices or offers.
// Body: { title, body, kind?, gateway_id?, expires_at? }
const createNotification = async (req, res) => {
    try {
        const { title, body, kind = "info", gateway_id = null, expires_at = null } = req.body ?? {};
        if (typeof title !== "string" || !title.trim() || title.length > 120) {
            return res.status(400).json({ message: "title is required (max 120 characters)" });
        }
        if (typeof body !== "string" || !body.trim() || body.length > 2000) {
            return res.status(400).json({ message: "body is required (max 2000 characters)" });
        }
        if (!KINDS.has(kind)) {
            return res.status(400).json({ message: `kind must be one of ${[...KINDS].join(", ")}` });
        }
        const r = await pool.query(
            `INSERT INTO notifications (title, body, kind, gateway_id, expires_at)
             VALUES ($1, $2, $3, $4, $5) RETURNING *`,
            [title.trim(), body.trim(), kind, gateway_id, expires_at]
        );
        return res.status(201).json({ notification: r.rows[0] });
    } catch (error) {
        if (error.code === "22P02" || error.code === "23503") {
            return res.status(400).json({ message: "gateway_id or expires_at is invalid" });
        }
        console.error("createNotification error:", error);
        return res.status(500).json({ message: "Server error" });
    }
};

// DELETE /admin/notifications/:id
const deleteNotification = async (req, res) => {
    try {
        const r = await pool.query(`DELETE FROM notifications WHERE id = $1`, [req.params.id]);
        return r.rowCount ? res.status(204).end() : res.status(404).json({ message: "Not found" });
    } catch (error) {
        console.error("deleteNotification error:", error);
        return res.status(500).json({ message: "Server error" });
    }
};

export { listNotifications, createNotification, deleteNotification };
