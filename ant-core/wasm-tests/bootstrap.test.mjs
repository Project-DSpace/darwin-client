import assert from "node:assert/strict";
import test from "node:test";
import { BrowserNetworkClient, encryptPublicFile, parseWebRtcDirectMultiaddr, test_bootstrap_eviction } from "./pkg/ant_core.js";
import { mockWebRtc, closesSettled, paymentNetwork } from "./mock-webrtc.mjs";

const content = new TextEncoder().encode("Pooled bootstrap and progressive discovery.".repeat(100));
const map = encryptPublicFile(content).records.at(-1);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

// A read asks a connected seed as soon as it is offered, nearest to the
// record first. Of the first two mock nodes, the second is the nearer to `map`.
for (const slowSeedIsNearer of [false, true]) {
  test(`network connect returns a fast seed and retains its authenticated association (slow seed ${slowSeedIsNearer ? "nearer to" : "farther from"} the record)`, async () => {
    const [slow, holder] = slowSeedIsNearer ? [1, 0] : [0, 1];
    const nodes = [];
    nodes[slow] = { connectDelay: 800 };
    nodes[holder] = { chunk: map.content };
    const rtc = mockWebRtc(nodes);
    const distance = i => BigInt(`0x${parseWebRtcDirectMultiaddr(rtc.endpoints[i]).peerId}`) ^ BigInt(`0x${map.address}`);
    assert.ok(distance(1) < distance(0));
    const client = new BrowserNetworkClient(rtc.endpoints);
    let reader;
    try {
      const started = performance.now();
      const hello = await client.connect(paymentNetwork);
      assert.equal(hello.peer_id, parseWebRtcDirectMultiaddr(rtc.endpoints[holder]).peerId);
      reader = await client.openPublicFile(map.address);
      assert.equal(reader.size, content.length);
      assert.ok(performance.now() - started < 600, "a slow seed must not delay authentication or the read");
      assert.equal(rtc.connections.filter(c => c.remoteSeed === holder + 1).length, 1, "the read must reuse the authenticated bootstrap association");
    } finally { reader?.close(); reader?.free(); client.close(); client.free(); }
    await closesSettled();
    assert.ok(rtc.connections.every(c => c.closed));
  });
}

test("cold discovery reaches a non-seed holder before the slow seed authenticates", async () => {
  const rtc = mockWebRtc([{ view: [0, 2] }, { connectDelay: 800 }, { chunk: map.content, view: [0, 2] }]);
  const client = new BrowserNetworkClient(rtc.endpoints.slice(0, 2));
  let reader;
  try {
    const started = performance.now();
    reader = await client.openPublicFile(map.address);
    assert.equal(reader.size, content.length);
    assert.ok(performance.now() - started < 600, "discovery must start before all seeds authenticate");
    assert.ok(rtc.requests.some(r => r.node === 2 && r.method === "get_chunk"));
  } finally { reader?.close(); reader?.free(); client.close(); client.free(); }
});

test("an exhausted fast seed still falls back through a later seed", async () => {
  const rtc = mockWebRtc([{ view: [0] }, { connectDelay: 150, view: [1, 2] }, { view: [1, 2], chunk: map.content }]);
  const client = new BrowserNetworkClient(rtc.endpoints.slice(0, 2));
  let reader;
  try {
    reader = await client.openPublicFile(map.address);
    assert.equal(reader.size, content.length);
    assert.ok(rtc.requests.some(r => r.node === 1 && r.method === "find_node"));
    assert.ok(rtc.requests.some(r => r.node === 2 && r.method === "get_chunk"));
  } finally { reader?.close(); reader?.free(); client.close(); client.free(); }
});

test("bootstrap dials three seeds and close cancels them", async () => {
  const rtc = mockWebRtc(Array.from({ length: 9 }, () => ({ connectDelay: 500 })));
  const client = new BrowserNetworkClient(rtc.endpoints);
  const connecting = client.connect();
  const rejected = assert.rejects(connecting, /closed/);
  await sleep(50);
  assert.equal(rtc.connections.length, 3);
  client.close();
  await rejected;
  client.free();
  await closesSettled();
  assert.ok(rtc.connections.every(c => c.closed));
  await sleep(550);
  assert.equal(rtc.connections.length, 3, "closing must stop queued seeds from dialing");
});

test("a browser keeps sessions with three of its seeds, chosen at random", async () => {
  const rtc = mockWebRtc(Array.from({ length: 9 }, () => ({})));
  const dialled = new Set();
  for (let round = 0; round < 12; round++) {
    const from = rtc.connections.length;
    const client = new BrowserNetworkClient(rtc.endpoints);
    try {
      await client.connect(paymentNetwork);
      await sleep(50);
      const seeds = rtc.connections.slice(from).map(c => c.remoteSeed);
      assert.equal(seeds.length, 3, "three seeds, not all nine");
      assert.equal(new Set(seeds).size, 3);
      for (const seed of seeds) dialled.add(seed);
    } finally { client.close(); client.free(); }
  }
  await closesSettled();
  // Twelve browsers in a fixed order would all dial the same three.
  assert.ok(dialled.size > 3, `dialled only seeds ${[...dialled]}`);
});

test("a seed that declines a session is replaced by the next, and held off", async () => {
  // Two of five seeds refuse every session, as full nodes do. Three sessions
  // are wanted, so the three others are all needed: each refusing seed the
  // random order reaches first is replaced by the next.
  const rtc = mockWebRtc([{ refuseDials: Infinity }, { refuseDials: Infinity }, {}, {}, {}]);
  const client = new BrowserNetworkClient(rtc.endpoints);
  try {
    const hello = await client.connect(paymentNetwork);
    const refusing = [0, 1].map(i => parseWebRtcDirectMultiaddr(rtc.endpoints[i]).peerId);
    assert.ok(!refusing.includes(hello.peer_id), "a refusing seed is never the one connected");
    await sleep(200);
    const dialsTo = seed => rtc.connections.filter(c => c.remoteSeed === seed).length;
    assert.deepEqual([3, 4, 5].map(dialsTo), [1, 1, 1], "every seed that takes a session, once");
    const refused = [1, 2].map(dialsTo);
    assert.ok(refused.every(dials => dials <= 1), `refusing seeds dialled ${refused}`);
    // Within their 15 s hold-off the refusing seeds are not dialled again.
    await client.connect(paymentNetwork);
    await sleep(100);
    assert.deepEqual([1, 2].map(dialsTo), refused);
  } finally { client.close(); client.free(); await closesSettled(); }
});

test("declining seeds are replaced until the seeds run out", async () => {
  // Three of four seeds refuse: however the random order runs, each refusal is
  // replaced by the next seed until all four are dialled, once each, and the
  // one that takes a session is the one connected.
  const rtc = mockWebRtc([{ refuseDials: Infinity }, { refuseDials: Infinity }, { refuseDials: Infinity }, {}]);
  const client = new BrowserNetworkClient(rtc.endpoints);
  try {
    const hello = await client.connect(paymentNetwork);
    assert.equal(hello.peer_id, parseWebRtcDirectMultiaddr(rtc.endpoints[3]).peerId);
    await sleep(200);
    const dialsTo = seed => rtc.connections.filter(c => c.remoteSeed === seed).length;
    assert.deepEqual([1, 2, 3, 4].map(dialsTo), [1, 1, 1, 1]);
  } finally { client.close(); client.free(); await closesSettled(); }
});

test("when every seed is held off for a refusal, connect says they are busy", async () => {
  const rtc = mockWebRtc([{ refuseDials: Infinity }, { refuseDials: Infinity }]);
  const client = new BrowserNetworkClient(rtc.endpoints);
  try {
    await assert.rejects(client.connect(paymentNetwork));
    await assert.rejects(client.connect(paymentNetwork), /busy/);
    assert.equal(rtc.connections.length, 2, "held off, not dialled again");
  } finally { client.close(); client.free(); await closesSettled(); }
});

test("bootstrap rejects the wrong network and cannot change trust policy after startup", async () => {
  const rtc = mockWebRtc([{}, {}]);
  const client = new BrowserNetworkClient(rtc.endpoints);
  try {
    await assert.rejects(client.connect({ ...paymentNetwork, chain_id: 1 }), /NETWORK_MISMATCH/);
    await assert.rejects(client.connect(paymentNetwork), /policy cannot change/);
    await assert.rejects(client.openPublicFile(map.address));
    assert.equal(rtc.requests.filter(r => r.method === "get_chunk").length, 0);
    assert.equal(rtc.connections.length, 2);
  } finally { client.close(); client.free(); }
});

test("a fast wrong-network seed cannot win the race or re-enter through discovery", async () => {
  const rtc = mockWebRtc([{ payment: { ...paymentNetwork, chain_id: 1 } }, { connectDelay: 50, chunk: map.content }]);
  const client = new BrowserNetworkClient(rtc.endpoints);
  let reader;
  try {
    const hello = await client.connect(paymentNetwork);
    assert.equal(hello.peer_id, parseWebRtcDirectMultiaddr(rtc.endpoints[1]).peerId);
    reader = await client.openPublicFile(map.address);
    assert.equal(reader.size, content.length);
    assert.equal(rtc.requests.filter(r => r.node === 0 && !["handshake", "hello"].includes(r.method)).length, 0);
  } finally { reader?.close(); reader?.free(); client.close(); client.free(); }
});

test("a later lookup retries transient bootstrap failure once and coalesces concurrent callers", async () => {
  let failHello = true;
  const rtc = mockWebRtc([{ respond(channel, method) {
    if (failHello && method === "hello") { channel.close(); return false; }
  } }]);
  const client = new BrowserNetworkClient(rtc.endpoints);
  try {
    await assert.rejects(client.findClosest("11".repeat(32)), /closed/);
    await closesSettled();
    failHello = false;
    const started = performance.now();
    const results = await Promise.all(Array.from({ length: 3 }, () => client.findClosest("11".repeat(32))));
    assert.ok(results.every(result => result.nodes.length === 1));
    assert.ok(performance.now() - started >= 700, "transient retries must observe bootstrap backoff");
    assert.equal(rtc.connections.length, 2, "concurrent callers share a single retry");
    assert.equal(rtc.requests.filter(r => r.method === "hello").length, 2);
  } finally { client.close(); client.free(); await closesSettled(); }
});

test("connect reuses a healthy session and reauthenticates after remote closure", async () => {
  const rtc = mockWebRtc();
  const client = new BrowserNetworkClient(rtc.endpoints);
  try {
    const first = await client.connect(paymentNetwork);
    assert.deepEqual(await client.connect(paymentNetwork), first);
    assert.equal(rtc.requests.filter(r => r.method === "hello").length, 1);
    rtc.connections[0].close();
    await closesSettled();
    assert.deepEqual(await client.connect(paymentNetwork), first);
    assert.equal(rtc.connections.length, 2);
    assert.equal(rtc.connections.filter(c => !c.closed).length, 1);
    assert.equal(rtc.requests.filter(r => r.method === "hello").length, 2);
  } finally { client.close(); client.free(); await closesSettled(); }
});

for (const dataFirst of [false, true]) {
  test(`a slow wrong-network seed revokes both lanes (${dataFirst ? "data" : "control"} HELLO finishes first)`, async () => {
    const view = [0, 2, 3, 4, 5, 6, 7];
    let hellos = 0;
    const rtc = mockWebRtc([
      { view },
      { view, chunk: map.content, payment: { ...paymentNetwork, chain_id: 1 },
        delay: method => method === "hello" ? (++hellos === 1 ? 500 : dataFirst ? 50 : 800) : 0 },
      ...Array.from({ length: 6 }, () => ({ view })),
    ]);
    const client = new BrowserNetworkClient(rtc.endpoints.slice(0, 2));
    try {
      await client.connect(paymentNetwork);
      await assert.rejects(client.openPublicFile(map.address));
      await closesSettled();
      const wrong = rtc.requests.filter(r => r.node === 1);
      assert.equal(wrong.filter(r => r.method === "hello").length, 2, "the race must lease both lanes before rejection");
      assert.ok(wrong.every(r => ["hello", "handshake"].includes(r.method)), "a mismatched seed must never receive GET or discovery requests");
      assert.ok(rtc.connections.filter(c => c.remoteSeed === 2).every(c => c.closed), "rejection closes the whole seed association");
      await client.connect(paymentNetwork);
      await assert.rejects(client.connect({ ...paymentNetwork, chain_id: 1 }), /policy cannot change/);
      assert.equal(rtc.connections.filter(c => c.remoteSeed === 2).length, 1, "rejection survives later bootstrap attempts");
    } finally { client.close(); client.free(); await closesSettled(); }
  });
}


test("connect reauthenticates a bootstrap session evicted from the pool", async () => {
  const rtc = mockWebRtc([{}, {}]);
  await test_bootstrap_eviction(rtc.endpoints);
  await closesSettled();
  assert.deepEqual(rtc.requests.filter(r => r.method === "hello").map(r => r.node), [0, 1, 0]);
  assert.equal(rtc.connections.length, 3);
  assert.ok(rtc.connections.every(c => c.closed));
});

test("closing during transient retry backoff cancels the batch without changing trust", async () => {
  const rtc = mockWebRtc([{ respond(channel, method) {
    if (method === "hello") { channel.close(); return false; }
  } }]);
  const client = new BrowserNetworkClient(rtc.endpoints);
  try {
    await assert.rejects(client.connect(paymentNetwork), /closed/);
    await closesSettled();
    await assert.rejects(client.connect({ ...paymentNetwork, chain_id: 1 }), /policy cannot change/);
    const rejected = assert.rejects(client.connect(paymentNetwork), /closed/);
    await sleep(50);
    client.close();
    await rejected;
    await sleep(1000);
    assert.equal(rtc.connections.length, 1, "closing cancels the delayed retry before it dials");
  } finally { client.close(); client.free(); await closesSettled(); }
});
