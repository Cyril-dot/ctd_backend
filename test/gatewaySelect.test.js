import { test } from "node:test";
import assert from "node:assert/strict";
import { pickGateway, parseReachability, effectiveEndpoint } from "../utils/gatewaySelect.js";

const KEY = "A".repeat(43) + "=";
const gw = (o) => ({ id: o.id, name: o.id, wg_public_key: KEY, capacity_users: 0, peer_count: 0, reachability: "unknown", relay_connected: false, ...o });

test("direct path wins over relay", () => {
    const r = pickGateway([
        gw({ id: "relayed", reachability: "relay", relay_connected: true, relay_endpoint: "203.0.113.9:51820" }),
        gw({ id: "direct", reachability: "direct", direct_endpoint: "197.251.157.7:51820" }),
    ]);
    assert.equal(r.gateway.id, "direct");
    assert.equal(r.endpoint, "197.251.157.7:51820");
    assert.equal(r.path, "direct");
});

test("relay is used when it is the only path", () => {
    const r = pickGateway([gw({ id: "a", reachability: "relay", relay_connected: true, relay_endpoint: "203.0.113.9:51820" })]);
    assert.equal(r.path, "relay");
    assert.equal(r.endpoint, "203.0.113.9:51820");
});

test("a relay that is not connected is not a path", () => {
    assert.equal(pickGateway([gw({ id: "a", reachability: "relay", relay_connected: false, relay_endpoint: "203.0.113.9:51820" })]), null);
});

test("unreachable gateways are never offered", () => {
    assert.equal(pickGateway([gw({ id: "a", reachability: "unreachable", wg_endpoint: "192.168.100.229:51820" })]), null);
});

test("full gateways are skipped, except for a device already on them", () => {
    const full = gw({ id: "full", reachability: "direct", direct_endpoint: "198.51.100.1:51820", capacity_users: 2, peer_count: 2 });
    const free = gw({ id: "free", reachability: "relay", relay_connected: true, relay_endpoint: "203.0.113.9:51820", capacity_users: 2, peer_count: 1 });
    assert.equal(pickGateway([full, free]).gateway.id, "free");
    assert.equal(pickGateway([full, free], { currentGatewayId: "full" }).gateway.id, "full");
});

test("least loaded wins among equal paths", () => {
    const busy = gw({ id: "busy", reachability: "direct", direct_endpoint: "198.51.100.1:51820", capacity_users: 10, peer_count: 8 });
    const calm = gw({ id: "calm", reachability: "direct", direct_endpoint: "198.51.100.2:51820", capacity_users: 10, peer_count: 1 });
    assert.equal(pickGateway([busy, calm]).gateway.id, "calm");
});

test("older gateways without reachability use the admin-set endpoint", () => {
    assert.deepEqual(effectiveEndpoint(gw({ id: "old", wg_endpoint: "198.51.100.3:51820" })), { endpoint: "198.51.100.3:51820", path: "configured" });
});

test("no gateways means no answer, not a nearby-Wi-Fi fallback", () => {
    assert.equal(pickGateway([]), null);
});

test("parseReachability sanitizes input", () => {
    const r = parseReachability({ reachability: { wg_public_key: KEY, direct_endpoint: "197.251.157.7:51820", relay_endpoint: "not an endpoint", relay_connected: "yes", reachability: "teleport", active_clients: -5 } });
    assert.equal(r.wg_public_key, KEY);
    assert.equal(r.direct_endpoint, "197.251.157.7:51820");
    assert.equal(r.relay_endpoint, null);
    assert.equal(r.relay_connected, false);
    assert.equal(r.reachability, "unreachable");
    assert.equal(r.active_clients, 0);
    assert.equal(parseReachability({}), null);
});
