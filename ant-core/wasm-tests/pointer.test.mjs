// Pointers from the browser (ADR-0016): the real WASM client, quorum and
// payment code over the mock transport, against mock nodes that keep pointers
// with the node's merge rule.
import { BrowserNetworkClient } from "./client-fixture.mjs";
import assert from "node:assert/strict";
import test from "node:test";
import { parseWebRtcDirectMultiaddr, pointerAddress } from "./pkg/ant_core.js";
import { mockWebRtc, paymentNetwork } from "./mock-webrtc.mjs";

const seed = new Uint8Array(32).fill(7);
const target = (byte) => byte.toString(16).padStart(2, "0").repeat(32);

function wallet() {
  const calls = [];
  return {
    calls,
    async pay(network, quotes) {
      calls.push({ network, quotes });
      return {
        transactionHash: `0x${"ab".repeat(32)}`,
        totalAmount: quotes.reduce((sum, quote) => sum + BigInt(quote.amount), 0n).toString(),
      };
    },
  };
}

const puts = (rtc) => rtc.requests.filter(({ method }) => method === "put_pointer");

test("a created pointer reads back from the close group", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const client = new BrowserNetworkClient(rtc.endpoints);
  const signer = wallet();
  try {
    const written = await client.createPointer(seed, target(1), "chunk", paymentNetwork, signer.pay);
    assert.equal(signer.calls.length, 1, "one state, one payment");
    assert.equal(signer.calls[0].quotes.length, 1);
    assert.equal(written.pointer.address, pointerAddress(seed));
    assert.equal(written.pointer.counter, "0");
    assert.equal(written.storageCostAtto, signer.calls[0].quotes[0].amount);
    assert.ok(puts(rtc).length >= 5, "a pointer write reaches a majority plus one");

    const read = await client.getPointer(written.pointer.address);
    assert.deepEqual(read, written.pointer);
    assert.equal(read.kind, "chunk");
    assert.equal(read.target, target(1));
  } finally {
    client.close();
  }
});

test("an update signs one past what the network serves and replaces it", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const client = new BrowserNetworkClient(rtc.endpoints);
  const signer = wallet();
  try {
    const created = await client.createPointer(seed, target(1), "chunk", paymentNetwork, signer.pay);
    const updated = await client.updatePointer(seed, target(2), "chunk", paymentNetwork, signer.pay);
    assert.equal(updated.pointer.counter, "1");
    assert.notEqual(updated.pointer.stateId, created.pointer.stateId);
    assert.equal(signer.calls.length, 2, "each state is paid for");

    const read = await client.getPointer(created.pointer.address);
    assert.equal(read.counter, "1");
    assert.equal(read.target, target(2));
  } finally {
    client.close();
  }
});

test("an update of a pointer nobody created creates it", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const client = new BrowserNetworkClient(rtc.endpoints);
  try {
    const written = await client.updatePointer(seed, target(3), "chunk", paymentNetwork, wallet().pay);
    assert.equal(written.pointer.counter, "0");
  } finally {
    client.close();
  }
});

test("a chain of pointers resolves to the chunk at its end", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const client = new BrowserNetworkClient(rtc.endpoints);
  const signer = wallet();
  const inner = new Uint8Array(32).fill(8);
  try {
    const last = await client.createPointer(inner, target(9), "chunk", paymentNetwork, signer.pay);
    const first = await client.createPointer(seed, last.pointer.address, "pointer", paymentNetwork, signer.pay);
    assert.equal(first.pointer.kind, "pointer");

    const resolved = await client.resolvePointer(first.pointer.address);
    assert.deepEqual(resolved, { kind: "chunk", kindTag: 0, target: target(9) });
  } finally {
    client.close();
  }
});

test("an address nobody wrote reads as null", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const client = new BrowserNetworkClient(rtc.endpoints);
  try {
    assert.equal(await client.getPointer(target(0x42)), null);
  } finally {
    client.close();
  }
});

test("a pointer only the seeds hold is read when its close group holds none", async () => {
  // Write the pointer on one network to get its record.
  const source = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const writer = new BrowserNetworkClient(source.endpoints);
  let record;
  try {
    await writer.createPointer(seed, target(1), "chunk", paymentNetwork, wallet().pay,
      value => { record = value.record; });
  } finally {
    writer.close();
  }
  // On another, the three nodes farthest from it are the seeds and hold it;
  // the seven nearest, its close group, hold none.
  const rtc = mockWebRtc(Array.from({ length: 10 }, () => ({})));
  const address = pointerAddress(seed);
  const distance = (endpoint) =>
    BigInt(`0x${parseWebRtcDirectMultiaddr(endpoint).peerId}`) ^ BigInt(`0x${address}`);
  const nodes = rtc.endpoints
    .map((endpoint, index) => ({ endpoint, index }))
    .sort((a, b) => (distance(a.endpoint) < distance(b.endpoint) ? -1 : 1));
  const closeGroup = new Set(nodes.slice(0, 7).map(({ index }) => index));
  const bootstrap = nodes.slice(7);
  for (const { index } of bootstrap) rtc.stores[index].set(`pointer:${address}`, record);
  const client = new BrowserNetworkClient(bootstrap.map(({ endpoint }) => endpoint));
  try {
    const read = await client.getPointer(address);
    assert.equal(read?.target, target(1));
    assert.equal(read.counter, "0");
    const asked = rtc.requests.filter(({ method }) => method === "get_pointer");
    assert.ok(asked.some(({ node }) => closeGroup.has(node)), "the close group is asked too");
  } finally {
    client.close();
  }
});

test("a seed the seed policy rejected is not counted among the bootstrap peers", async () => {
  // Write the pointer on one network to get its record.
  const source = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const writer = new BrowserNetworkClient(source.endpoints);
  let record;
  try {
    await writer.createPointer(seed, target(1), "chunk", paymentNetwork, wallet().pay,
      value => { record = value.record; });
  } finally {
    writer.close();
  }
  // On another, the seven nodes nearest the pointer, its close group, hold
  // none. The four farthest are the seeds: one is on another network, one
  // fails every pointer GET and two hold the pointer. Two answers are a
  // quorum of the three seeds left once the rejected one is left out, but not
  // of all four, and the read would then fail.
  const nodes = Array.from({ length: 11 }, () => ({}));
  const rtc = mockWebRtc(nodes);
  const address = pointerAddress(seed);
  const distance = (index) =>
    BigInt(`0x${parseWebRtcDirectMultiaddr(rtc.endpoints[index]).peerId}`) ^ BigInt(`0x${address}`);
  const seeds = nodes.map((_, index) => index).sort((a, b) => (distance(a) < distance(b) ? -1 : 1)).slice(7);
  const [rejected, failing, ...holders] = seeds;
  nodes[rejected].payment = { ...paymentNetwork, chain_id: 1 };
  nodes[failing].respond = (channel, method) => {
    if (method !== "get_pointer") return;
    channel.emit(new ArrayBuffer(0));
    return false;
  };
  for (const index of holders) rtc.stores[index].set(`pointer:${address}`, record);
  const client = new BrowserNetworkClient(seeds.map((index) => rtc.endpoints[index]));
  try {
    await client.connect(paymentNetwork);
    // Let the other seeds' HELLOs, the rejected one's among them, complete.
    await new Promise((resolve) => setTimeout(resolve, 100));
    const read = await client.getPointer(address);
    assert.equal(read?.target, target(1));
    assert.ok(!rtc.requests.some(({ node, method }) => node === rejected && method === "get_pointer"));
  } finally {
    client.close();
  }
});

// Writes the pointer on one network to get its record. On another, of
// nineteen nodes, the seven nearest the pointer are its close group and hold
// none, and the twelve after them, nearest first, are the client's seeds:
// those at the positions in `holding` hold the pointer. Returns the read, and
// whether each seed was sent a pointer GET.
async function readWithTwelveSeeds(holding) {
  const source = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const writer = new BrowserNetworkClient(source.endpoints);
  let record;
  try {
    await writer.createPointer(seed, target(1), "chunk", paymentNetwork, wallet().pay,
      value => { record = value.record; });
  } finally {
    writer.close();
  }
  const rtc = mockWebRtc(Array.from({ length: 19 }, () => ({})));
  const address = pointerAddress(seed);
  const distance = (index) =>
    BigInt(`0x${parseWebRtcDirectMultiaddr(rtc.endpoints[index]).peerId}`) ^ BigInt(`0x${address}`);
  const nodes = rtc.endpoints.map((_, index) => index).sort((a, b) => (distance(a) < distance(b) ? -1 : 1));
  const seeds = nodes.slice(7);
  for (const at of holding) rtc.stores[seeds[at]].set(`pointer:${address}`, record);
  const client = new BrowserNetworkClient(seeds.map((index) => rtc.endpoints[index]));
  try {
    const read = await client.getPointer(address);
    const asked = (node) => rtc.requests.some((request) => request.node === node && request.method === "get_pointer");
    return { read, seeds: seeds.map(asked) };
  } finally {
    client.close();
  }
}

test("a pointer the eighth and ninth nearest of twelve seeds hold is read from them", async () => {
  // Two of the five answers the nine nearest seeds need name it. The three
  // farther seeds are not asked.
  const { read, seeds } = await readWithTwelveSeeds([7, 8]);
  assert.equal(read?.target, target(1));
  assert.deepEqual(seeds.slice(9), [false, false, false]);
});

test("a pointer only seeds outside the nine nearest it hold is not looked for there", async () => {
  // The nine nearest of twelve seeds all answer that they hold none before
  // the pointer reads as absent, and the three farther ones, which hold it,
  // are not asked.
  const { read, seeds } = await readWithTwelveSeeds([9, 10, 11]);
  assert.equal(read, null);
  assert.deepEqual(seeds, [...Array(9).fill(true), false, false, false]);
});

test("a node that does not advertise pointers is never sent one", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, (_, i) => ({ pointers: i !== 0 })));
  const client = new BrowserNetworkClient(rtc.endpoints);
  try {
    const written = await client.createPointer(seed, target(1), "chunk", paymentNetwork, wallet().pay);
    await client.getPointer(written.pointer.address);
    const asked = rtc.requests.filter(({ method }) => method.endsWith("_pointer"));
    assert.ok(asked.length > 0);
    assert.ok(asked.every(({ node }) => node !== 0), "the mock node asserts it too");
  } finally {
    client.close();
  }
});

test("an owner seed of the wrong length is refused before anything is paid", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const client = new BrowserNetworkClient(rtc.endpoints);
  const signer = wallet();
  try {
    await assert.rejects(
      client.createPointer(new Uint8Array(31), target(1), "chunk", paymentNetwork, signer.pay),
      /owner seed must be 32 bytes/,
    );
    assert.throws(() => pointerAddress(new Uint8Array(33)), /owner seed must be 32 bytes/);
    await assert.rejects(
      client.createPointer(seed, target(1), "file", paymentNetwork, signer.pay),
      /unknown pointer target kind/,
    );
    assert.equal(signer.calls.length, 0);
  } finally {
    client.close();
  }
});

test("creating a pointer that exists is refused before anything is paid", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const client = new BrowserNetworkClient(rtc.endpoints);
  const signer = wallet();
  try {
    await client.createPointer(seed, target(1), "chunk", paymentNetwork, signer.pay);
    await assert.rejects(
      client.createPointer(seed, target(2), "chunk", paymentNetwork, signer.pay),
      /already exists at counter 0; update it instead/,
    );
    assert.equal(signer.calls.length, 1, "the refused create paid nothing");
  } finally {
    client.close();
  }
});

test("a paid state handed to onPaid is stored again without paying", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const client = new BrowserNetworkClient(rtc.endpoints);
  const signer = wallet();
  let paid;
  try {
    const written = await client.createPointer(seed, target(1), "chunk", paymentNetwork, signer.pay,
      value => { paid = value; });
    assert.ok(paid.record instanceof Uint8Array && paid.proof instanceof Uint8Array);
    const before = puts(rtc).length;

    const stored = await client.storePaidPointer(paid.record, paid.proof, paymentNetwork);
    assert.deepEqual(stored, written.pointer);
    assert.equal(signer.calls.length, 1, "storing a paid state pays nothing");
    assert.ok(puts(rtc).length > before, "and it is sent again");
  } finally {
    client.close();
  }
});
