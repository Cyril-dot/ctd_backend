import { pool } from "../config/db.js";
import { enqueueCommand } from "./gatewayCommands.js";
import { hasActiveEntitlement } from "./gatewayPeers.js";

// Time-based expiry. Access ends at whichever comes first, quota or time;
// quota is enforced in usage.js, this module enforces the clock.
//
// Each UPDATE ... RETURNING claims its rows atomically, so concurrent
// sweeps never process the same entitlement twice; the peer UPDATE does the
// same for peers, so a REVOKE_PEER is queued at most once per peer.
const expireLapsedEntitlements = async () => {
    const lapsed = await pool.query(
        `WITH t AS (
             UPDATE trials SET status = 'expired'
              WHERE status = 'active' AND expires_at <= NOW()
              RETURNING user_id
         ), s AS (
             UPDATE subscriptions SET status = 'expired'
              WHERE status = 'active' AND expires_at <= NOW()
              RETURNING user_id
         )
         SELECT user_id FROM t UNION SELECT user_id FROM s`
    );

    let revoked = 0;
    for (const { user_id } of lapsed.rows) {
        // Another live trial/package keeps the user's peers authorised.
        if (await hasActiveEntitlement(user_id)) continue;

        const peers = await pool.query(
            `UPDATE gateway_peers p SET status = 'revoking'
               FROM devices d
              WHERE d.id = p.device_id AND d.user_id = $1
                AND p.status IN ('pending', 'active')
              RETURNING p.id, p.gateway_id, p.device_id, p.public_key, p.tunnel_ip`,
            [user_id]
        );
        for (const p of peers.rows) {
            await enqueueCommand(p.gateway_id, "REVOKE_PEER", {
                peer_id: p.id,
                device_id: p.device_id,
                public_key: p.public_key,
                tunnel_ip: p.tunnel_ip,
                reason: "entitlement_expired",
            });
            revoked++;
        }
    }
    return { expired_users: lapsed.rows.length, revoked_peers: revoked };
};

export { expireLapsedEntitlements };
