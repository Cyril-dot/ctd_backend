import { test } from "node:test";
import assert from "node:assert/strict";
import { pickGateway, parseReachability, effectiveEndpoint, endpointsFor, clientIp } from "../utils/gatewaySelect.js";

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

test("a phone on the gateway's own network gets the local address first", () => {
    const g = gw({ id: "home", reachability: "lan", lan_endpoint: "10.112.214.226:51820", public_ip: "41.66.1.2" });
    const r = pickGateway([g], { clientIp: "41.66.1.2" });
    assert.equal(r.endpoint, "10.112.214.226:51820");
    assert.equal(r.path, "lan");
});

test("a remote phone is never offered a local-only gateway", () => {
    const g = gw({ id: "home", reachability: "lan", lan_endpoint: "10.112.214.226:51820", public_ip: "41.66.1.2" });
    assert.equal(pickGateway([g], { clientIp: "154.160.0.9" }), null);
});

test("port forwarding publishes <public ip>:port automatically", () => {
    const g = gw({ id: "home", reachability: "direct", port_forwarded: true, public_ip: "197.251.157.7", listen_port: 51820, lan_endpoint: "192.168.100.229:51820" });
    assert.deepEqual(endpointsFor(g, { clientIp: "154.160.0.9" }).map((e) => e.endpoint), ["197.251.157.7:51820", "192.168.100.229:51820"]);
    assert.deepEqual(endpointsFor(g, { clientIp: "197.251.157.7" }).map((e) => e.path), ["lan", "direct"]);
});

test("fallback order for a remote phone: direct, then relay", () => {
    const g = gw({ id: "x", reachability: "direct", direct_endpoint: "197.251.157.7:51820", relay_connected: true, relay_endpoint: "203.0.113.9:51820" });
    assert.deepEqual(endpointsFor(g).map((e) => e.path), ["direct", "relay"]);
});

test("clientIp reads the first forwarded address", () => {
    assert.equal(clientIp({ headers: { "x-forwarded-for": "41.66.1.2, 76.76.21.21" } }), "41.66.1.2");
    assert.equal(clientIp({ headers: { "x-real-ip": "41.66.1.3" } }), "41.66.1.3");
});
