// Gateway routing for remote customers (the coordination-server role).
// Pure functions: no database access, so they are unit-tested directly.

const WG_KEY_RE = /^[A-Za-z0-9+/]{43}=$/;
const HOST_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const MODES = new Set(["direct", "relay", "unreachable"]);

export function validEndpoint(v) {
    if (typeof v !== "string" || v.length > 255) return false;
    const i = v.lastIndexOf(":");
    if (i <= 0) return false;
    const host = v.slice(0, i);
    const portStr = v.slice(i + 1);
    if (!/^\d{1,5}$/.test(portStr)) return false;
    const port = Number(portStr);
    if (port < 1 || port > 65535) return false;
    if (IPV4_RE.test(host)) return host.split(".").every((o) => Number(o) <= 255);
    if (/^\[[0-9A-Fa-f:.]+\]$/.test(host)) return true;
    return HOST_RE.test(host);
}

// Sanitize the reachability block a gateway sends with its heartbeat.
// Returns null when absent or not an object; invalid fields become null.
export function parseReachability(body) {
    const r = body?.reachability;
    if (!r || typeof r !== "object" || Array.isArray(r)) return null;
    const ep = (v) => (validEndpoint(v) ? v : null);
    const n = Number(r.active_clients);
    return {
        wg_public_key: typeof r.wg_public_key === "string" && WG_KEY_RE.test(r.wg_public_key) ? r.wg_public_key : null,
        direct_endpoint: ep(r.direct_endpoint),
        relay_endpoint: ep(r.relay_endpoint),
        relay_connected: r.relay_connected === true,
        reachability: MODES.has(r.reachability) ? r.reachability : "unreachable",
        active_clients: Number.isInteger(n) && n >= 0 && n < 1e6 ? n : 0,
        version: typeof r.version === "string" ? r.version.slice(0, 64) : null,
    };
}

// The address a customer should dial for this gateway, and which path it is.
// Gateways that never reported reachability (older versions) fall back to the
// admin-set wg_endpoint.
export function effectiveEndpoint(g) {
    if (g.reachability === "direct" && g.direct_endpoint) return { endpoint: g.direct_endpoint, path: "direct" };
    if (g.reachability === "relay" && g.relay_connected && g.relay_endpoint) return { endpoint: g.relay_endpoint, path: "relay" };
    if (g.reachability === "unknown" && g.wg_endpoint) return { endpoint: g.wg_endpoint, path: "configured" };
    return null;
}

function hasRoom(g, deviceAlreadyHere) {
    if (deviceAlreadyHere) return true;
    const cap = Number(g.capacity_users) || 0; // 0 = unlimited
    return cap === 0 || Number(g.peer_count || 0) < cap;
}

// Choose a gateway for a customer from ONLINE candidate rows. Prefers the
// gateway the device is already peered on, then direct paths over relayed
// ones, then the least loaded. Returns { gateway, endpoint, path } or null
// when no online gateway is reachable with room. A customer is never told to
// be near a gateway.
export function pickGateway(rows, { currentGatewayId = null } = {}) {
    const rank = { direct: 0, relay: 1, configured: 2 };
    const usable = [];
    for (const g of rows || []) {
        if (!g.wg_public_key) continue;
        const ep = effectiveEndpoint(g);
        if (!ep) continue;
        const here = currentGatewayId != null && g.id === currentGatewayId;
        if (!hasRoom(g, here)) continue;
        const cap = Number(g.capacity_users) || 0;
        const load = cap ? Number(g.peer_count || 0) / cap : Number(g.peer_count || 0) / 1e6;
        usable.push({ g, ep, here, load });
    }
    usable.sort((a, b) =>
        (b.here - a.here) ||
        (rank[a.ep.path] - rank[b.ep.path]) ||
        (a.load - b.load) ||
        String(a.g.name).localeCompare(String(b.g.name)));
    const best = usable[0];
    return best ? { gateway: best.g, endpoint: best.ep.endpoint, path: best.ep.path } : null;
}
