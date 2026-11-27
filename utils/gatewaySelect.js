// Gateway routing for remote customers (the coordination-server role).
// Pure functions: no database access, so they are unit-tested directly.

const WG_KEY_RE = /^[A-Za-z0-9+/]{43}=$/;
const HOST_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const MODES = new Set(["direct", "relay", "lan", "unreachable"]);

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
    const port = Number(r.listen_port);
    return {
        lan_endpoint: ep(r.lan_endpoint),
        listen_port: Number.isInteger(port) && port >= 1 && port <= 65535 ? port : null,
        port_forwarded: r.port_forwarded === true,
        wg_public_key: typeof r.wg_public_key === "string" && WG_KEY_RE.test(r.wg_public_key) ? r.wg_public_key : null,
        direct_endpoint: ep(r.direct_endpoint),
        relay_endpoint: ep(r.relay_endpoint),
        relay_connected: r.relay_connected === true,
        reachability: MODES.has(r.reachability) ? r.reachability : "unreachable",
        active_clients: Number.isInteger(n) && n >= 0 && n < 1e6 ? n : 0,
        version: typeof r.version === "string" ? r.version.slice(0, 64) : null,
    };
}

// The client's public IP as seen by the backend (Vercel sets these headers).
export function clientIp(req) {
    const xff = req?.headers?.["x-forwarded-for"];
    const first = typeof xff === "string" ? xff.split(",")[0].trim() : "";
    const ip = first || req?.headers?.["x-real-ip"] || req?.socket?.remoteAddress || "";
    return String(ip).replace(/^::ffff:/, "") || null;
}

// Every way a customer can reach this gateway, best first. A phone on the
// gateway's own network (same public IP) gets the local address first; a
// remote phone gets the port-forwarded public address and/or the relay.
// Older gateways that report nothing fall back to the admin-set endpoint.
export function endpointsFor(g, { clientIp: cip = null } = {}) {
    const out = [];
    const add = (endpoint, path) => {
        if (endpoint && !out.some((e) => e.endpoint === endpoint)) out.push({ endpoint, path });
    };
    const sameNetwork = Boolean(cip && g.public_ip && cip === g.public_ip);
    if (sameNetwork) add(g.lan_endpoint, "lan");
    if (g.direct_endpoint) add(g.direct_endpoint, "direct");
    else if (g.port_forwarded && g.public_ip && g.listen_port) {
        add(g.public_ip.includes(":") ? `[${g.public_ip}]:${g.listen_port}` : `${g.public_ip}:${g.listen_port}`, "direct");
    }
    if (g.relay_connected && g.relay_endpoint) add(g.relay_endpoint, "relay");
    if (out.length === 0 && (g.reachability ?? "unknown") === "unknown" && g.wg_endpoint) add(g.wg_endpoint, "configured");
    // A remote phone never gets ONLY a local address; but when another path
    // exists, the local one is a harmless last try (hairpin/odd NAT cases).
    if (out.length > 0 && !sameNetwork) add(g.lan_endpoint, "lan");
    return out;
}

// Back-compat helper: the first (best) endpoint, or null.
export function effectiveEndpoint(g, opts) {
    return endpointsFor(g, opts)[0] ?? null;
}

function hasRoom(g, deviceAlreadyHere) {
    if (deviceAlreadyHere) return true;
    const cap = Number(g.capacity_users) || 0; // 0 = unlimited
    return cap === 0 || Number(g.peer_count || 0) < cap;
}

// Choose a gateway for a customer from ONLINE candidate rows. Prefers the
// gateway the device is already on, then the best path (same network,
// direct, relay), then the least loaded. Returns { gateway, endpoints,
// endpoint, path } or null when no online gateway can take the customer.
// A customer is never told to be near a gateway.
export function pickGateway(rows, { currentGatewayId = null, clientIp: cip = null } = {}) {
    const rank = { lan: 0, direct: 1, relay: 2, configured: 3 };
    const usable = [];
    for (const g of rows || []) {
        if (!g.wg_public_key) continue;
        const eps = endpointsFor(g, { clientIp: cip });
        if (eps.length === 0) continue;
        const here = currentGatewayId != null && g.id === currentGatewayId;
        if (!hasRoom(g, here)) continue;
        const cap = Number(g.capacity_users) || 0;
        const load = cap ? Number(g.peer_count || 0) / cap : Number(g.peer_count || 0) / 1e6;
        usable.push({ g, eps, here, load });
    }
    usable.sort((a, b) =>
        (b.here - a.here) ||
        (rank[a.eps[0].path] - rank[b.eps[0].path]) ||
        (a.load - b.load) ||
        String(a.g.name).localeCompare(String(b.g.name)));
    const best = usable[0];
    return best ? { gateway: best.g, endpoints: best.eps, endpoint: best.eps[0].endpoint, path: best.eps[0].path } : null;
}
