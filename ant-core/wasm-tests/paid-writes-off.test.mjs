// Uploads and pointer writes from the browser core are off in this build: a
// page's client refuses each one before it asks for a quote, calls the
// page's wallet or any other callback, or sends anything, whatever the
// arguments. Reads still work.
import assert from "node:assert/strict";
import test from "node:test";
import { BrowserNetworkClient as TestClient, PageClient, PAID_WRITES_OFF } from "./client-fixture.mjs";
import { encryptPublicFile, pointerAddress } from "./pkg/ant_core.js";
import { mockWebRtc, paymentNetwork } from "./mock-webrtc.mjs";

const content = new TextEncoder().encode("Browser paid-write refusal fixture. ".repeat(100));
const seed = new Uint8Array(32).fill(7);
const recipientSeed = new Uint8Array(32).fill(8);
const target = byte => byte.toString(16).padStart(2, "0").repeat(32);
const refused = error => error === PAID_WRITES_OFF;

const receipt = (_, quotes) => ({
  transactionHash: `0x${"ab".repeat(32)}`,
  totalAmount: quotes.reduce((sum, quote) => sum + BigInt(quote.amount), 0n).toString(),
});

// Callbacks that note each call, so a test can show none was made.
function spies() {
  const called = [];
  const spy = name => Object.assign(async () => {
    called.push(name);
    throw new Error(`${name} must not be called`);
  }, {
    recover: async () => {
      called.push(`${name}.recover`);
      throw new Error(`${name}.recover must not be called`);
    },
  });
  return { called, spy };
}

function staged() {
  const encrypted = encryptPublicFile(content);
  return {
    encrypted,
    staged: {
      ...encrypted, name: "a.txt", content_type: "text/plain", size: content.length,
      records: encrypted.records.map(record => ({ address: record.address, size: record.content.length })),
    },
  };
}

// A paid pointer state, as a test client's write hands it to `onPaid`, made
// on a network of its own.
async function paidPointerState() {
  const elsewhere = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const writer = new TestClient(elsewhere.endpoints);
  let paid;
  try {
    await writer.createPointer(seed, target(1), "chunk", paymentNetwork, receipt,
      value => { paid = value; });
  } finally {
    writer.close();
  }
  return paid;
}

test("every upload and pointer write a page can call is refused before anything is quoted, paid or sent", async () => {
  const paid = await paidPointerState();
  const { encrypted, staged: file } = staged();
  const rtc = mockWebRtc(Array.from({ length: 16 }, () => ({})));
  const client = new PageClient(rtc.endpoints);
  const { called, spy } = spies();
  const calls = {
    uploadPublicFile: () => client.uploadPublicFile(content, "a.txt", "text/plain", paymentNetwork,
      spy("payForQuotes"), spy("onProgress"), undefined, spy("onCheckpoint")),
    "uploadPublicFile (merkle)": () => client.uploadPublicFile(content, "a.txt", "text/plain",
      paymentNetwork, spy("payForQuotes"), spy("onProgress"), undefined, spy("onCheckpoint"),
      "merkle", spy("payForMerkle")),
    uploadStagedPublicFile: () => client.uploadStagedPublicFile(file, paymentNetwork,
      spy("loadRecord"), spy("payForQuotes"), spy("onProgress"), undefined, spy("onCheckpoint"),
      "single"),
    uploadRecords: () => client.uploadRecords({ records: file.records }, paymentNetwork,
      spy("loadRecord"), spy("payForQuotes"), spy("onProgress"), undefined, spy("onCheckpoint"),
      "auto", spy("payForMerkle")),
    createPointer: () => client.createPointer(seed, target(1), "chunk", paymentNetwork,
      spy("payForQuotes"), spy("onPaid")),
    updatePointer: () => client.updatePointer(seed, target(2), "chunk", paymentNetwork,
      spy("payForQuotes"), spy("onPaid")),
    transferPointer: () => client.transferPointer(seed, pointerAddress(recipientSeed),
      paymentNetwork, spy("payForQuotes"), spy("onPaid")),
    storePaidPointer: () => client.storePaidPointer(paid.record, paid.proof, paymentNetwork),
  };
  try {
    for (const [name, call] of Object.entries(calls)) {
      await assert.rejects(call(), refused, name);
    }
    assert.deepEqual(called, [], "no callback was called");
    assert.deepEqual(rtc.requests, [], "nothing was sent");
    assert.equal(rtc.connections.length, 0, "no node was dialled");
    assert.ok(rtc.stores.every(store => store.size === 0), "nothing was stored");
    assert.ok(encrypted.records.length > 0);
  } finally {
    client.close();
  }
});

test("the refusal comes first, whatever the arguments", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const client = new PageClient(rtc.endpoints);
  const { called, spy } = spies();
  try {
    await assert.rejects(client.uploadPublicFile(content, "a.txt", "text/plain", {},
      spy("payForQuotes")), refused, "a malformed payment network");
    await assert.rejects(client.uploadPublicFile(content, "a.txt", "text/plain", paymentNetwork,
      spy("payForQuotes"), undefined, "not a checkpoint"), refused, "a checkpoint to resume");
    await assert.rejects(client.uploadPublicFile(content, "a.txt", "text/plain", paymentNetwork,
      spy("payForQuotes"), undefined, undefined, undefined, "batch"), refused, "an unknown mode");
    await assert.rejects(client.uploadStagedPublicFile({}, paymentNetwork, spy("loadRecord"),
      spy("payForQuotes")), refused, "a malformed staged file");
    await assert.rejects(client.uploadRecords({ records: [] }, paymentNetwork, spy("loadRecord"),
      spy("payForQuotes")), refused, "an empty batch");
    await assert.rejects(client.createPointer(new Uint8Array(31), target(1), "chunk",
      paymentNetwork, spy("payForQuotes")), refused, "a short owner seed");
    await assert.rejects(client.updatePointer(seed, target(1), "file", paymentNetwork,
      spy("payForQuotes")), refused, "an unknown target kind");
    await assert.rejects(client.transferPointer(seed, "not an address", paymentNetwork,
      spy("payForQuotes")), refused, "a malformed recipient");
    await assert.rejects(client.storePaidPointer(new Uint8Array(3), new Uint8Array(3),
      paymentNetwork), refused, "a malformed record");
    assert.deepEqual(called, []);
    assert.deepEqual(rtc.requests, []);
  } finally {
    client.close();
  }
});

test("a page's client still downloads, range-reads and reads pointers", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));

  // A public file, and a private one whose data map the page holds.
  const { encrypted } = staged();
  const original = new TextEncoder().encode("Private read fixture. ".repeat(500));
  const privateFile = encryptPublicFile(original);
  for (const store of rtc.stores) {
    for (const record of encrypted.records) store.set(record.address, record.content);
    for (const record of privateFile.records.slice(0, -1)) store.set(record.address, record.content);
  }

  // Pointers a test client wrote: a chain, the outer one open.
  const writer = new TestClient(rtc.endpoints);
  let inner, outer;
  try {
    inner = await writer.createPointer(recipientSeed, target(9), "chunk", paymentNetwork, receipt);
    outer = await writer.createPointer(seed, inner.pointer.address, "pointer", paymentNetwork, receipt);
  } finally {
    writer.close();
  }

  const client = new PageClient(rtc.endpoints);
  let reader;
  try {
    const downloaded = await client.downloadPublicFile(encrypted.address, 3);
    assert.deepEqual(downloaded.content, content);
    reader = await client.openPublicFile(encrypted.address);
    assert.deepEqual(await reader.readRange(10, 100), content.slice(10, 110));
    const privateDownload = await client.downloadPrivateFile(
      { data_map: privateFile.records.at(-1).content, name: "private.txt", content_type: "text/plain" }, 3);
    assert.deepEqual(privateDownload.content, original);

    assert.deepEqual(await client.getPointer(outer.pointer.address), outer.pointer);
    assert.deepEqual(await client.resolvePointer(outer.pointer.address),
      { kind: "chunk", kindTag: 0, target: target(9) });
    const finality = await client.pointerFinality(outer.pointer.address);
    assert.equal(finality.status, "open");
    assert.equal(finality.counter, "0");
    assert.equal(await client.getPointer(target(0x42)), null);
  } finally {
    reader?.close();
    client.close();
  }
});
