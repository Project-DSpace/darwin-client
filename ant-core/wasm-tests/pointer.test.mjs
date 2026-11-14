// Pointers from the browser (ADR-0016): the real WASM client, quorum and
// payment code over the mock transport, against mock nodes that keep pointers
// with the node's merge rule.
import { BrowserNetworkClient } from "./client-fixture.mjs";
import assert from "node:assert/strict";
import test from "node:test";
import vm from "node:vm";
import { parseWebRtcDirectMultiaddr, pointerAddress, recoverPointerPayment, test_storage_price } from "./pkg/ant_core.js";
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
  // none. The three farthest are the seeds: the nearest of them is on another
  // network, and the two others hold the pointer. Left out, the rejected seed
  // leaves the other two among the nine nearest of what the read knows, and
  // both are asked: a quorum of two. Counted, it would have taken one of
  // those places and failed, and the one holder left would be too few.
  const nodes = Array.from({ length: 10 }, () => ({}));
  const rtc = mockWebRtc(nodes);
  const address = pointerAddress(seed);
  const distance = (index) =>
    BigInt(`0x${parseWebRtcDirectMultiaddr(rtc.endpoints[index]).peerId}`) ^ BigInt(`0x${address}`);
  const seeds = nodes.map((_, index) => index).sort((a, b) => (distance(a) < distance(b) ? -1 : 1)).slice(7);
  const [rejected, ...holders] = seeds;
  nodes[rejected].payment = { ...paymentNetwork, chain_id: 1 };
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

test("a pointer the two seeds nearest past its close group hold is read from them", async () => {
  // The close group's lookup leaves the two nearest seeds among the nine
  // nearest of what the read knows: both are asked, and both name the state.
  // The ten farther seeds are not asked.
  const { read, seeds } = await readWithTwelveSeeds([0, 1]);
  assert.equal(read?.target, target(1));
  assert.deepEqual(seeds, [true, true, ...Array(10).fill(false)]);
});

test("a pointer only seeds past the nine nearest of what the read knows hold is not looked for there", async () => {
  // The two seeds the lookup leaves among the nine nearest answer that they
  // hold none before the pointer reads as absent, and the farther seeds, which
  // hold it, are not asked.
  const { read, seeds } = await readWithTwelveSeeds([2, 3, 4]);
  assert.equal(read, null);
  assert.deepEqual(seeds, [true, true, ...Array(10).fill(false)]);
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
      { onPaid: value => { newer = value.record; } });
  } finally {
    other.close();
  }

  const nodes = Array.from({ length: 7 }, () => ({}));
  const rtc = mockWebRtc(nodes);
  let paid;
  const first = new BrowserNetworkClient(rtc.endpoints);
  try {
    await first.createPointer(seed, target(1), "chunk", paymentNetwork, wallet().pay,
      { onPaid: value => { paid = value; } });
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
        { onPaid: value => { paid = value; return new Promise(() => {}); } }),
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
      { onPaid: value => { paid = value; } });
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
      { onPaid: value => { paid = value; } });
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

test("a transfer whose acknowledgements are all lost is reported as done", async () => {
  // Every node stores the transfer and drops its answer, every round.
  let dropPuts = false;
  const nodes = Array.from({ length: 7 }, () => ({
    respond: (_channel, method) => !(dropPuts && method === "put_pointer"),
  }));
  const rtc = mockWebRtc(nodes);
  const client = new BrowserNetworkClient(rtc.endpoints);
  const recipientSeed = new Uint8Array(32).fill(0x55);
  try {
    await client.createPointer(seed, target(1), "chunk", paymentNetwork, wallet().pay);
    const recipient = await client.createPointer(recipientSeed, target(2), "chunk",
      paymentNetwork, wallet().pay);
    dropPuts = true;
    const signer = wallet();
    const done = await client.transferPointer(seed, recipient.pointer.address, paymentNetwork,
      signer.pay);
    assert.equal(done.pointer.address, pointerAddress(seed));
    assert.equal(signer.calls.length, 1, "paid once");
    const finality = await client.pointerFinality(pointerAddress(seed));
    assert.equal(finality.status, "final");
  } finally {
    client.close();
  }
});

test("a transfer stored again from onPaid is done even if every acknowledgement is lost", async () => {
  // The page journals a paid transfer through onPaid.
  const elsewhere = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const first = new BrowserNetworkClient(elsewhere.endpoints);
  const recipientSeed = new Uint8Array(32).fill(0x56);
  let paid;
  try {
    await first.createPointer(seed, target(1), "chunk", paymentNetwork, wallet().pay);
    const recipient = await first.createPointer(recipientSeed, target(2), "chunk",
      paymentNetwork, wallet().pay);
    await first.transferPointer(seed, recipient.pointer.address, paymentNetwork, wallet().pay,
      { onPaid: value => { paid = value; } });
  } finally {
    first.close();
  }
  assert.ok(paid, "the paid transfer was handed over");

  // Stored again from the journal on a group that stores it and loses every
  // acknowledgement.
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({
    respond: (_channel, method) => method !== "put_pointer",
  })));
  const client = new BrowserNetworkClient(rtc.endpoints);
  try {
    const stored = await client.storePaidPointer(paid.record, paid.proof, paymentNetwork);
    assert.equal(stored.address, pointerAddress(seed));
    assert.equal((await client.pointerFinality(pointerAddress(seed))).status, "final");
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
      { onPaid: value => { paid = value; } });
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

test("a transfer hands the address over for good, and reads follow it", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const client = new BrowserNetworkClient(rtc.endpoints);
  const signer = wallet();
  const recipientSeed = new Uint8Array(32).fill(8);
  try {
    const recipient = await client.createPointer(recipientSeed, target(9), "chunk", paymentNetwork, signer.pay);
    const handed = await client.createPointer(seed, target(1), "chunk", paymentNetwork, signer.pay);
    const address = handed.pointer.address;

    const written = await client.transferPointer(seed, recipient.pointer.address, paymentNetwork, signer.pay);
    assert.equal(written.pointer.address, address, "the address readers use does not change");
    assert.equal(written.pointer.counter, "18446744073709551615", "signed at the final counter");
    assert.equal(written.pointer.kind, "pointer");
    assert.equal(written.pointer.target, recipient.pointer.address);
    assert.equal(signer.calls.length, 3, "the transfer is one paid state");

    const finality = await client.pointerFinality(address);
    assert.equal(finality.status, "final");
    assert.equal(finality.states.length, 1);
    assert.equal(finality.majority.transferredTo, recipient.pointer.address);
    assert.ok(finality.majority.holders >= 5, "the write reached a majority plus one");
    assert.equal(finality.seeds, undefined, "a final pointer is the close group's to report");

    assert.deepEqual(await client.resolvePointer(address), { kind: "chunk", kindTag: 0, target: target(9) });

    // The recipient moves it; the former owner can move nothing.
    await client.updatePointer(recipientSeed, target(4), "chunk", paymentNetwork, signer.pay);
    assert.deepEqual(await client.resolvePointer(address), { kind: "chunk", kindTag: 0, target: target(4) });
    const paid = signer.calls.length;
    await assert.rejects(
      client.updatePointer(seed, target(5), "chunk", paymentNetwork, signer.pay),
      /pointer is final/,
    );
    await assert.rejects(
      client.transferPointer(seed, target(6), paymentNetwork, signer.pay),
      /pointer is final/,
    );
    assert.equal(signer.calls.length, paid, "nothing is paid for a move a final pointer cannot make");
  } finally {
    client.close();
  }
});

test("an open pointer reports its counter, and a transfer nowhere is refused before paying", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const client = new BrowserNetworkClient(rtc.endpoints);
  const signer = wallet();
  try {
    const written = await client.createPointer(seed, target(1), "chunk", paymentNetwork, signer.pay);
    const finality = await client.pointerFinality(written.pointer.address);
    assert.equal(finality.status, "open");
    assert.equal(finality.counter, "0");
    assert.deepEqual(finality.states, []);
    // Before calling it open, the client's seeds were asked too.
    assert.equal(finality.seeds.asked, 7);
    assert.ok(finality.seeds.answered >= 4, `${finality.seeds.answered} answered`);
    assert.equal(finality.seeds.state.stateId, written.pointer.stateId);
    assert.equal(finality.seeds.state.counter, "0");
    assert.equal(finality.seeds.state.final, false);

    await assert.rejects(
      client.transferPointer(seed, target(0x42), paymentNetwork, signer.pay),
      /does not exist/,
    );
    await assert.rejects(
      client.transferPointer(seed, written.pointer.address, paymentNetwork, signer.pay),
      /to itself/,
    );
    assert.equal(signer.calls.length, 1, "only the create was paid for");
  } finally {
    client.close();
  }
});

const transaction = `0x${"ab".repeat(32)}`;
/** A receipt that keys the transaction by the quote it paid. */
const receiptFor = (quote) => ({ transactionHashes: { [quote.quoteHash]: transaction } });

test("onPrepared is awaited before the wallet, and one that fails pays nothing", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const client = new BrowserNetworkClient(rtc.endpoints);
  const signer = wallet();
  const order = [];
  const pay = (...args) => { order.push("wallet"); return signer.pay(...args); };
  try {
    await client.createPointer(seed, target(1), "chunk", paymentNetwork, pay, {
      onPrepared: async checkpoint => {
        const saved = JSON.parse(checkpoint);
        assert.equal(saved.version, 1);
        assert.equal(typeof saved.plan, "string", "the plan's bytes are not spelt out as JSON numbers");
        order.push("prepared");
        await new Promise(resolve => setTimeout(resolve, 20));
        order.push("kept");
      },
    });
    assert.deepEqual(order, ["prepared", "kept", "wallet"], "the wallet waits for the checkpoint");

    const before = puts(rtc).length;
    await assert.rejects(
      client.updatePointer(seed, target(2), "chunk", paymentNetwork, pay, {
        onPrepared: async () => { throw new Error("disk full"); },
      }),
      /onPrepared failed: disk full; payment was not submitted/,
    );
    assert.equal(signer.calls.length, 1, "a checkpoint that was not kept is not paid for");
    assert.equal(puts(rtc).length, before, "and nothing is sent");
  } finally {
    client.close();
  }
});

// Every pointer write takes onPaid in its options, as upstream's API has it,
// or as a bare function, as pages written for earlier releases pass it.
const pointerWrites = {
  createPointer: (client, pay, options) =>
    client.createPointer(seed, target(1), "chunk", paymentNetwork, pay, options),
  updatePointer: async (client, pay, options) => {
    await client.createPointer(seed, target(1), "chunk", paymentNetwork, pay);
    return client.updatePointer(seed, target(2), "chunk", paymentNetwork, pay, options);
  },
  transferPointer: async (client, pay, options) => {
    const recipient = await client.createPointer(new Uint8Array(32).fill(0x57), target(3),
      "chunk", paymentNetwork, pay);
    await client.createPointer(seed, target(1), "chunk", paymentNetwork, pay);
    return client.transferPointer(seed, recipient.pointer.address, paymentNetwork, pay, options);
  },
};
for (const [name, write] of Object.entries(pointerWrites)) {
  for (const form of ["options", "function"]) {
    test(`${name} hands onPaid the paid state, given ${form === "options" ? "{ onPaid }" : "a bare function"}`, async () => {
      const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
      const client = new BrowserNetworkClient(rtc.endpoints);
      const signer = wallet();
      const handed = [];
      const onPaid = value => { handed.push(value); };
      try {
        const written = await write(client, signer.pay, form === "options" ? { onPaid } : onPaid);
        assert.equal(handed.length, 1, "onPaid is called once, for this write");
        assert.ok(handed[0].record instanceof Uint8Array && handed[0].proof instanceof Uint8Array);
        assert.deepEqual(
          await client.storePaidPointer(handed[0].record, handed[0].proof, paymentNetwork),
          written.pointer,
        );
        assert.equal(signer.calls.length, name === "createPointer" ? 1 : name === "updatePointer" ? 2 : 3,
          "one payment for each state written, and none for the state handed back");
      } finally {
        client.close();
      }
    });
  }
}

test("pointer write options are checked before anything is paid", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const client = new BrowserNetworkClient(rtc.endpoints);
  const signer = wallet();
  try {
    for (const [options, error] of [
      [{ onPrepare: () => {} }, /unknown field `onPrepare`/],
      // Checked whatever the object's prototype or realm.
      [Object.assign(Object.create(null), { onPrepare: () => {} }), /unknown field `onPrepare`/],
      [vm.runInNewContext("({ onPrepare: () => {} })"), /unknown field `onPrepare`/],
      [{ onPaid: 5 }, /onPaid must be a function/],
      [{ onSubmission: "x" }, /onSubmission must be a function/],
      [7, /must be an object/],
    ]) {
      await assert.rejects(
        client.createPointer(seed, target(1), "chunk", paymentNetwork, signer.pay, options),
        error,
      );
    }
    assert.equal(signer.calls.length, 0);
  } finally {
    client.close();
  }
});

test("a settlement refusal learned while onPrepared runs stops the payment", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const client = new BrowserNetworkClient(rtc.endpoints);
  const signer = wallet();
  try {
    await assert.rejects(
      client.createPointer(seed, target(1), "chunk", paymentNetwork, signer.pay, {
        onPrepared: () => client.test_refuse_settlement(),
      }),
      /test settlement refusal.*; payment was not submitted/,
    );
    assert.equal(signer.calls.length, 0, "a write this build cannot settle is not paid for");
  } finally {
    client.close();
  }
});

test("recoverPointerPayment rebuilds the paid state from its checkpoint and receipt", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const client = new BrowserNetworkClient(rtc.endpoints);
  const signer = wallet();
  const checkpoints = [];
  let paid;
  const options = { onPrepared: value => { checkpoints.push(value); }, onPaid: value => { paid = value; } };
  try {
    const written = await client.createPointer(seed, target(1), "chunk", paymentNetwork, signer.pay, options);
    const [checkpoint] = checkpoints;
    const quote = signer.calls[0].quotes[0];

    // Other receipt fields, such as totalAmount, are neither needed nor read.
    const recovered = recoverPointerPayment(checkpoint, { ...receiptFor(quote), walletAddress: "0x01" });
    assert.deepEqual(recovered.record, paid.record);
    assert.deepEqual(recovered.proof, paid.proof, "the same proof the write paid for");
    assert.deepEqual(
      await client.storePaidPointer(recovered.record, recovered.proof, paymentNetwork),
      written.pointer,
    );
    assert.equal(signer.calls.length, 1, "recovering pays nothing");

    const single = recoverPointerPayment(checkpoint, { transactionHash: transaction, totalAmount: quote.amount });
    assert.deepEqual(single.proof, paid.proof, "one transaction pays the checkpoint's one quote");
    for (const receipt of [{ transactionHashes: { ["cd".repeat(32)]: transaction } }, {}]) {
      await assert.rejects(
        async () => recoverPointerPayment(checkpoint, receipt),
        /does not pay this checkpoint's quote/,
      );
    }

    const saved = JSON.parse(checkpoint);
    await assert.rejects(
      async () => recoverPointerPayment(JSON.stringify({ ...saved, version: 2, added: true }), receiptFor(quote)),
      /unsupported pointer checkpoint version 2/,
      "a newer checkpoint is reported as such, not as malformed",
    );

    await client.updatePointer(seed, target(2), "chunk", paymentNetwork, signer.pay, options);
    const other = JSON.parse(checkpoints[1]);
    await assert.rejects(
      async () => recoverPointerPayment(JSON.stringify({ ...saved, record: other.record }), receiptFor(quote)),
      /pointer record differs from its payment plan/,
    );
  } finally {
    client.close();
  }
});

// A pointer pays by its size class, as pricing::record_weight has it: 3 × the
// median price × (1/4 + 3/4 × 16 KiB / 4 MiB), rounded up, a pointer record
// being under 16 KiB. Written out here, so a change to the classes fails on
// purpose.
const pointerAmount = medianPrice => {
  const full = 4n * 1024n * 1024n;
  const numerator = full + 3n * 16n * 1024n;
  const denominator = 4n * full;
  return (3n * medianPrice * numerator + denominator - 1n) / denominator;
};

test("a recovered pointer payment is checked against the size-priced band", async () => {
  // The write's wallet is asked for the pointer's size-priced amount, which
  // the browser checks against its quotes' band before paying; the state
  // recovered from the checkpoint carries that same paid proof, and asks the
  // wallet for nothing more.
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const client = new BrowserNetworkClient(rtc.endpoints);
  const signer = wallet();
  const checkpoints = [];
  let paid;
  const options = { onPrepared: value => { checkpoints.push(value); }, onPaid: value => { paid = value; } };
  try {
    const written = await client.createPointer(seed, target(3), "chunk", paymentNetwork, signer.pay, options);
    assert.equal(signer.calls.length, 1);
    const [quote] = signer.calls[0].quotes.filter(q => BigInt(q.amount) > 0n);
    const expected = pointerAmount(BigInt(test_storage_price(0)));
    assert.equal(BigInt(quote.amount), expected, "the pointer's size-priced amount");
    assert.equal(BigInt(written.storageCostAtto), expected);

    const recovered = recoverPointerPayment(checkpoints[0], receiptFor(quote));
    assert.deepEqual(recovered.proof, paid.proof, "the proof of the size-priced payment");
    assert.deepEqual(
      await client.storePaidPointer(recovered.record, recovered.proof, paymentNetwork),
      written.pointer,
    );
    assert.equal(signer.calls.length, 1, "recovering pays nothing");
  } finally {
    client.close();
  }
});

test("onSubmission keeps each broadcast before the wallet goes on, and recovers from it", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const client = new BrowserNetworkClient(rtc.endpoints);
  const order = [];
  // A wallet lost after broadcasting: it reports the transaction, then fails.
  const pay = async (_network, quotes, onSubmission) => {
    await onSubmission({ transactionHash: transaction });
    order.push("wallet resumed");
    throw new Error(`page lost before the receipt for ${quotes.length} quote`);
  };
  let checkpoint;
  let submitted;
  try {
    await assert.rejects(
      client.createPointer(seed, target(1), "chunk", paymentNetwork, pay, {
        onPrepared: value => { checkpoint = value; },
        onSubmission: async value => {
          await new Promise(resolve => setTimeout(resolve, 20));
          submitted = value;
          order.push("kept");
        },
      }),
      /page lost before the receipt/,
    );
    assert.deepEqual(order, ["kept", "wallet resumed"], "the wallet waits for the page to keep it");
    assert.deepEqual(submitted, { transactionHash: transaction });

    const recovered = recoverPointerPayment(checkpoint, submitted);
    const stored = await client.storePaidPointer(recovered.record, recovered.proof, paymentNetwork);
    assert.equal(stored.target, target(1));
    assert.equal((await client.getPointer(stored.address)).counter, "0");
  } finally {
    client.close();
  }
});

test("an onPrepared that never settles fails the write without paying", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const client = new BrowserNetworkClient(rtc.endpoints);
  const signer = wallet();
  try {
    await assert.rejects(
      client.createPointer(seed, target(1), "chunk", paymentNetwork, signer.pay, {
        onPrepared: () => new Promise(() => {}),
      }),
      /onPrepared did not settle within \d+s; payment was not submitted/,
    );
    assert.equal(signer.calls.length, 0);
  } finally {
    client.close();
  }
});

test("a broadcast the page cannot keep does not stop a paid state being stored", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const client = new BrowserNetworkClient(rtc.endpoints);
  const signer = wallet();
  try {
    for (const [counter, onSubmission] of [
      ["0", () => new Promise(() => {})],
      ["1", async () => { throw new Error("quota exceeded"); }],
    ]) {
      const pay = async (network, quotes, reportSubmission) => {
        await reportSubmission({ transactionHash: transaction });
        return signer.pay(network, quotes);
      };
      const write = counter === "0" ? "createPointer" : "updatePointer";
      const written = await client[write](seed, target(Number(counter) + 1), "chunk", paymentNetwork, pay, { onSubmission });
      assert.equal(written.pointer.counter, counter, "stored once paid");
    }
  } finally {
    client.close();
  }
});

test("a write waits for the page to keep a broadcast its wallet did not wait for", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const client = new BrowserNetworkClient(rtc.endpoints);
  let submitted;
  const pay = async (_network, _quotes, reportSubmission) => {
    void reportSubmission({ transactionHash: transaction });
    throw new Error("wallet lost");
  };
  try {
    await assert.rejects(
      client.createPointer(seed, target(1), "chunk", paymentNetwork, pay, {
        onSubmission: async value => {
          await new Promise(resolve => setTimeout(resolve, 20));
          submitted = value;
        },
      }),
      error => {
        assert.deepEqual(submitted, { transactionHash: transaction }, "kept before the write failed");
        assert.match(String(error), /wallet lost/);
        assert.doesNotMatch(String(error), /payment was not submitted/, "the wallet was invoked");
        return true;
      },
    );
  } finally {
    client.close();
  }
});

test("every failure before the wallet says nothing was paid", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const client = new BrowserNetworkClient(rtc.endpoints);
  const signer = wallet();
  try {
    await client.createPointer(seed, target(1), "chunk", paymentNetwork, signer.pay);
    for (const write of [
      () => client.createPointer(seed, target(2), "chunk", paymentNetwork, signer.pay),
      () => client.createPointer(seed.subarray(1), target(2), "chunk", paymentNetwork, signer.pay),
      () => client.updatePointer(seed, target(2), "file", paymentNetwork, signer.pay),
      () => client.updatePointer(seed, target(2), "chunk", {}, signer.pay),
    ]) {
      await assert.rejects(write(), /payment was not submitted$/);
    }
    assert.equal(signer.calls.length, 1);
  } finally {
    client.close();
  }
});
