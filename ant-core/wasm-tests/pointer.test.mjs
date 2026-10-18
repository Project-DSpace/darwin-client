// Pointers from the browser (ADR-0016): the real WASM client, quorum and
// payment code over the mock transport, against mock nodes that keep pointers
// with the node's merge rule. Pointer writes are off in this build: a page's
// client refuses them, and the write tests run the code underneath on the
// test client (client-fixture.mjs).
import { BrowserNetworkClient, PageClient, PAID_WRITES_OFF } from "./client-fixture.mjs";
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
const refused = (error) => error === PAID_WRITES_OFF;

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

test("a write too few peers can accept is refused before anything is paid", async () => {
  // Mid-rollout: four of the seven advertise pointers, and a write needs five.
  const rtc = mockWebRtc(Array.from({ length: 7 }, (_, i) => ({ pointers: i >= 3 })));
  const client = new BrowserNetworkClient(rtc.endpoints);
  const signer = wallet();
  try {
    await assert.rejects(
      client.createPointer(seed, target(1), "chunk", paymentNetwork, signer.pay),
      /accept pointer writes/,
    );
    await assert.rejects(
      client.updatePointer(seed, target(2), "chunk", paymentNetwork, signer.pay),
      /accept pointer writes/,
    );
    assert.equal(signer.calls.length, 0, "nothing is paid for a write that cannot land");
    assert.equal(puts(rtc).length, 0, "and nothing is sent");
  } finally {
    client.close();
  }
});

test("a write five of seven can accept still goes ahead", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, (_, i) => ({ pointers: i >= 2 })));
  const client = new BrowserNetworkClient(rtc.endpoints);
  const signer = wallet();
  try {
    const written = await client.createPointer(seed, target(1), "chunk", paymentNetwork, signer.pay);
    assert.equal(signer.calls.length, 1);
    assert.deepEqual(await client.getPointer(written.pointer.address), written.pointer);
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

test("one peer claiming the pointer moved on does not end a paid write", async () => {
  // A newer state for the same owner, signed and paid for elsewhere.
  const elsewhere = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const other = new BrowserNetworkClient(elsewhere.endpoints);
  let newer;
  try {
    await other.createPointer(seed, target(1), "chunk", paymentNetwork, wallet().pay);
    await other.updatePointer(seed, target(2), "chunk", paymentNetwork, wallet().pay,
      value => { newer = value.record; });
  } finally {
    other.close();
  }

  const nodes = Array.from({ length: 7 }, () => ({}));
  const rtc = mockWebRtc(nodes);
  let paid;
  const first = new BrowserNetworkClient(rtc.endpoints);
  try {
    await first.createPointer(seed, target(1), "chunk", paymentNetwork, wallet().pay,
      value => { paid = value; });
  } finally {
    first.close();
  }

  // One node now claims the newer state and two cannot be reached, so four
  // hold the paid state: one short of a write quorum.
  rtc.stores[0].set(`pointer:${pointerAddress(seed)}`, newer);
  nodes[5].connectError = "unreachable";
  nodes[6].connectError = "unreachable";
  const client = new BrowserNetworkClient(rtc.endpoints);
  try {
    await assert.rejects(
      client.storePaidPointer(paid.record, paid.proof, paymentNetwork),
      error => /stored on 4 of 5/.test(String(error)) && !/moved/.test(String(error)),
      "one peer's word is a shortfall to retry, not a final answer",
    );
  } finally {
    client.close();
  }

  // Once the group really holds the newer state, the write ends at once.
  for (let i = 0; i < 5; i += 1) rtc.stores[i].set(`pointer:${pointerAddress(seed)}`, newer);
  const again = new BrowserNetworkClient(rtc.endpoints);
  try {
    await assert.rejects(
      again.storePaidPointer(paid.record, paid.proof, paymentNetwork),
      /moved while this update was in flight/,
    );
  } finally {
    again.close();
  }
});

test("an onPaid callback that never settles does not keep a paid state from being stored", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const client = new BrowserNetworkClient(rtc.endpoints);
  const signer = wallet();
  let paid;
  let deadline;
  try {
    const written = await Promise.race([
      client.createPointer(seed, target(1), "chunk", paymentNetwork, signer.pay,
        value => { paid = value; return new Promise(() => {}); }),
      new Promise((_, reject) => deadline = setTimeout(
        () => reject(new Error("the write waited on onPaid")), 10000)),
    ]);
    assert.ok(paid.record instanceof Uint8Array, "the paid state was handed over first");
    assert.equal(signer.calls.length, 1, "and paid for once");
    assert.ok(puts(rtc).length > 0, "then stored");
    assert.deepEqual(await client.getPointer(written.pointer.address), written.pointer);
  } finally {
    clearTimeout(deadline);
    client.close();
  }
});

test("one node refusing while the rest miss a round does not end a paid write", async () => {
  // A paid state, from a network that stored it.
  const elsewhere = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const first = new BrowserNetworkClient(elsewhere.endpoints);
  let paid;
  try {
    await first.createPointer(seed, target(1), "chunk", paymentNetwork, wallet().pay,
      value => { paid = value; });
  } finally {
    first.close();
  }

  // One node refuses every write; the other six drop the answer to their
  // first write, so the first round hears nothing but that refusal.
  const missed = new Set();
  const nodes = Array.from({ length: 7 }, (_, index) => index === 0
    ? { putError: { code: "payment_required", message: "pay up" } }
    : {
      respond: (_channel, method) => {
        if (method !== "put_pointer" || missed.has(index)) return true;
        missed.add(index);
        return false;
      },
    });
  const rtc = mockWebRtc(nodes);
  const client = new BrowserNetworkClient(rtc.endpoints);
  try {
    const stored = await client.storePaidPointer(paid.record, paid.proof, paymentNetwork);
    assert.equal(stored.address, pointerAddress(seed));
    assert.equal(missed.size, 6, "every other node missed the first round");
  } finally {
    client.close();
  }
});

test("nodes that cannot store just then do not end a paid write", async () => {
  const elsewhere = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const first = new BrowserNetworkClient(elsewhere.endpoints);
  let paid;
  try {
    await first.createPointer(seed, target(1), "chunk", paymentNetwork, wallet().pay,
      value => { paid = value; });
  } finally {
    first.close();
  }

  // Two nodes have no room; the other five miss the first round.
  const missed = new Set();
  const nodes = Array.from({ length: 7 }, (_, index) => index < 2
    ? { putError: { code: "storage_full", message: "disk full" } }
    : {
      respond: (_channel, method) => {
        if (method !== "put_pointer" || missed.has(index)) return true;
        missed.add(index);
        return false;
      },
    });
  const rtc = mockWebRtc(nodes);
  const client = new BrowserNetworkClient(rtc.endpoints);
  try {
    const stored = await client.storePaidPointer(paid.record, paid.proof, paymentNetwork);
    assert.equal(stored.address, pointerAddress(seed));
    assert.equal(missed.size, 5);
  } finally {
    client.close();
  }
});

test("a page's transfer is refused before it is paid or sent, and the pointer stays open", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const writer = new BrowserNetworkClient(rtc.endpoints);
  const recipientSeed = new Uint8Array(32).fill(0x55);
  let recipient;
  try {
    await writer.createPointer(seed, target(1), "chunk", paymentNetwork, wallet().pay);
    recipient = await writer.createPointer(recipientSeed, target(2), "chunk",
      paymentNetwork, wallet().pay);
  } finally {
    writer.close();
  }
  const before = puts(rtc).length;
  const client = new PageClient(rtc.endpoints);
  const signer = wallet();
  let handed = false;
  try {
    await assert.rejects(client.transferPointer(seed, recipient.pointer.address, paymentNetwork,
      signer.pay, () => { handed = true; }), refused);
    assert.equal(signer.calls.length, 0, "nothing is paid");
    assert.equal(handed, false, "nothing is handed to onPaid");
    assert.equal(puts(rtc).length, before, "nothing is sent");
    assert.equal((await client.pointerFinality(pointerAddress(seed))).status, "open");
  } finally {
    client.close();
  }
});

test("a paid transfer handed to onPaid is not stored from a page", async () => {
  // A paid transfer, journalled through onPaid by the code underneath.
  const elsewhere = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const first = new BrowserNetworkClient(elsewhere.endpoints);
  const recipientSeed = new Uint8Array(32).fill(0x56);
  let paid;
  try {
    await first.createPointer(seed, target(1), "chunk", paymentNetwork, wallet().pay);
    const recipient = await first.createPointer(recipientSeed, target(2), "chunk",
      paymentNetwork, wallet().pay);
    await first.transferPointer(seed, recipient.pointer.address, paymentNetwork, wallet().pay,
      value => { paid = value; });
  } finally {
    first.close();
  }
  assert.ok(paid, "the paid transfer was handed over");

  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const client = new PageClient(rtc.endpoints);
  try {
    await assert.rejects(client.storePaidPointer(paid.record, paid.proof, paymentNetwork), refused);
    assert.equal(puts(rtc).length, 0, "nothing is sent");
    assert.equal(await client.getPointer(pointerAddress(seed)), null, "nothing is stored");
  } finally {
    client.close();
  }
});

test("a paid state handed to onPaid is not stored again from a page, and still reads", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const writer = new BrowserNetworkClient(rtc.endpoints);
  let paid, written;
  try {
    written = await writer.createPointer(seed, target(1), "chunk", paymentNetwork, wallet().pay,
      value => { paid = value; });
  } finally {
    writer.close();
  }
  assert.ok(paid.record instanceof Uint8Array && paid.proof instanceof Uint8Array);
  const before = puts(rtc).length;
  const client = new PageClient(rtc.endpoints);
  try {
    await assert.rejects(client.storePaidPointer(paid.record, paid.proof, paymentNetwork), refused);
    assert.equal(puts(rtc).length, before, "nothing is sent again");
    assert.deepEqual(await client.getPointer(written.pointer.address), written.pointer);
  } finally {
    client.close();
  }
});

test("reads follow a transfer, which a page itself can't make", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const writer = new BrowserNetworkClient(rtc.endpoints);
  const recipientSeed = new Uint8Array(32).fill(8);
  let recipient, address;
  try {
    recipient = await writer.createPointer(recipientSeed, target(9), "chunk", paymentNetwork, wallet().pay);
    address = (await writer.createPointer(seed, target(1), "chunk", paymentNetwork, wallet().pay)).pointer.address;
    const written = await writer.transferPointer(seed, recipient.pointer.address, paymentNetwork, wallet().pay);
    assert.equal(written.pointer.counter, "18446744073709551615", "signed at the final counter");
  } finally {
    writer.close();
  }

  const client = new PageClient(rtc.endpoints);
  const signer = wallet();
  try {
    const finality = await client.pointerFinality(address);
    assert.equal(finality.status, "final");
    assert.equal(finality.states.length, 1);
    assert.equal(finality.majority.transferredTo, recipient.pointer.address);
    assert.ok(finality.majority.holders >= 5, "the write reached a majority plus one");
    assert.deepEqual(await client.resolvePointer(address), { kind: "chunk", kindTag: 0, target: target(9) });

    // A page can move neither the recipient nor the former pointer.
    const before = puts(rtc).length;
    await assert.rejects(
      client.updatePointer(recipientSeed, target(4), "chunk", paymentNetwork, signer.pay), refused);
    await assert.rejects(
      client.transferPointer(recipientSeed, target(6), paymentNetwork, signer.pay), refused);
    assert.equal(signer.calls.length, 0, "nothing is paid");
    assert.equal(puts(rtc).length, before, "nothing is sent");
    assert.deepEqual(await client.resolvePointer(address), { kind: "chunk", kindTag: 0, target: target(9) });
  } finally {
    client.close();
  }
});

test("an open pointer reports its counter, and a page's transfer is refused before paying", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const writer = new BrowserNetworkClient(rtc.endpoints);
  let written;
  try {
    written = await writer.createPointer(seed, target(1), "chunk", paymentNetwork, wallet().pay);
  } finally {
    writer.close();
  }
  const client = new PageClient(rtc.endpoints);
  const signer = wallet();
  try {
    const finality = await client.pointerFinality(written.pointer.address);
    assert.equal(finality.status, "open");
    assert.equal(finality.counter, "0");
    assert.deepEqual(finality.states, []);

    // Refused before the recipient is even looked up.
    await assert.rejects(
      client.transferPointer(seed, target(0x42), paymentNetwork, signer.pay), refused);
    await assert.rejects(
      client.transferPointer(seed, written.pointer.address, paymentNetwork, signer.pay), refused);
    assert.equal(signer.calls.length, 0, "nothing is paid");
  } finally {
    client.close();
  }
});
