import assert from "node:assert/strict";
import test from "node:test";
import { BrowserNetworkClient, contentAddress, encryptPublicFile } from "./pkg/ant_core.js";
import { PAID_WRITES_OFF } from "./client-fixture.mjs";
import { mockWebRtc, paymentNetwork } from "./mock-webrtc.mjs";

// Uploads are off in this build: a page's client refuses them before its
// wallet or checkpoint callback is called, so it never has a payment to
// recover. The reconciliation tests below run the code underneath on a
// client a test build lets through (`test_allow_paid_writes`).
const refused = error => error === PAID_WRITES_OFF;

const content = new TextEncoder().encode("Payment recovery regression. ".repeat(100));
const hash = `0x${"ab".repeat(32)}`;
const receipt = quotes => ({
  transactionHash: hash,
  totalAmount: quotes.reduce((sum, quote) => sum + BigInt(quote.amount), 0n).toString(),
});
const merkleReceipt = request => ({
  transactionHash: hash, winnerPoolHash: request.poolHashes[0], totalAmount: request.maximumAmount,
});
const noSingle = () => { throw new Error("unexpected single payment"); };
const notSubmitted = () => ({ status: "notSubmitted", evidence: { walletRequest: "rejected before submission" } });
const reverted = transactionHashes => ({
  status: "reverted", transactionHashes, evidence: { receipts: "verified final reverts by wallet adapter" },
});

function stagedRecords() {
  const encrypted = encryptPublicFile(content);
  const records = encrypted.records.slice(0, -1);
  while (records.length < 287) {
    const bytes = new TextEncoder().encode(`valid record ${records.length}`);
    records.push({ address: contentAddress(bytes), content: bytes });
  }
  records.push(encrypted.records.at(-1));
  return { records, staged: { name: "fixture", content_type: "text/plain", address: encrypted.address,
    records: records.map(record => ({ address: record.address, size: record.content.length })) } };
}

test("a staged Merkle upload is refused before any batch is paid or stored", async () => {
  const rtc = mockWebRtc(Array.from({ length: 16 }, () => ({})));
  const client = new BrowserNetworkClient(rtc.endpoints);
  const { records, staged } = stagedRecords();
  let payments = 0, loads = 0, checkpoint;
  const pay = async (_, request) => { payments++; return merkleReceipt(request); };
  const upload = () => client.uploadStagedPublicFile(staged, paymentNetwork,
    i => { loads++; return records[i].content; }, noSingle, undefined, checkpoint,
    value => { checkpoint = value; }, "merkle", pay);
  try {
    // 288 records would pay as two Merkle batches, 256 + 32; nothing of
    // either is paid, loaded or stored, so a retry has nothing to recover.
    await assert.rejects(upload(), refused);
    await assert.rejects(upload(), refused);
    assert.equal(payments, 0);
    assert.equal(loads, 0);
    assert.equal(checkpoint, undefined, "no payment intent was recorded");
    assert.equal(rtc.requests.length, 0);
  } finally { client.close(); }
});

test("a staged Merkle upload never reaches its payment or its staged bytes", async () => {
  const rtc = mockWebRtc(Array.from({ length: 16 }, () => ({})));
  const client = new BrowserNetworkClient(rtc.endpoints);
  const { staged } = stagedRecords();
  const calls = [];
  try {
    await assert.rejects(client.uploadStagedPublicFile(staged, paymentNetwork, () => {
      calls.push("load");
      throw new Error("staged bytes evicted");
    }, noSingle, undefined, undefined, () => { calls.push("checkpoint"); }, "merkle", async () => {
      calls.push("merkle");
      throw new Error("second payment rejected");
    }), refused);
    assert.deepEqual(calls, []);
  } finally { client.close(); }
});

for (const mode of ["single", "merkle"]) {
  test(`a ${mode} upload is refused before its wallet or checkpoint callback is called`, async () => {
    const rtc = mockWebRtc(Array.from({ length: mode === "single" ? 7 : 16 }, () => ({})));
    const client = new BrowserNetworkClient(rtc.endpoints);
    let checkpoint, calls = 0, checkpoints = 0;
    const pay = async (_, request) => {
      calls++;
      return mode === "single" ? receipt(request) : merkleReceipt(request);
    };
    const upload = () => client.uploadPublicFile(content, "fixture", "text/plain", paymentNetwork,
      mode === "single" ? pay : noSingle, undefined, checkpoint,
      value => { checkpoints++; checkpoint = value; }, mode, mode === "merkle" ? pay : undefined);
    try {
      await assert.rejects(upload(), refused);
      await assert.rejects(upload(), refused);
      assert.equal(calls, 0);
      assert.equal(checkpoints, 0);
      assert.equal(checkpoint, undefined);
      assert.equal(rtc.requests.length, 0);
    } finally { client.close(); }
  });
}

test("reconciliation requires verified failure for every submitted transaction", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const client = new BrowserNetworkClient(rtc.endpoints);
  client.test_allow_paid_writes();
  const secondHash = `0x${"cd".repeat(32)}`;
  let checkpoint, calls = 0, writes = 0;
  const pay = async (_, quotes, submitted) => {
    if (++calls === 1) {
      await submitted({ transactionHash: hash });
      await submitted({ transactionHash: secondHash });
      throw new Error("transactions reverted");
    }
    return receipt(quotes);
  };
  const upload = () => client.uploadPublicFile(content, "fixture", "text/plain", paymentNetwork, pay,
    undefined, checkpoint, value => { checkpoint = value; }, "single");
  try {
    await assert.rejects(upload(), /transactions reverted/);
    const original = checkpoint;
    for (const verify of [
      notSubmitted,
      () => ({ status: "pending", evidence: { timeout: true } }),
      () => reverted([hash]),
      () => ({ status: "reverted", transactionHashes: [hash, secondHash], evidence: {} }),
      () => { throw new Error("RPC unavailable"); },
    ]) {
      await assert.rejects(client.reconcileFailedUploadPayment(checkpoint, verify, () => { writes++; }));
      assert.equal(writes, 0);
      assert.equal(checkpoint, original);
    }
    await assert.rejects(client.reconcileFailedUploadPayment(checkpoint, () => reverted([hash, secondHash]),
      () => { throw new Error("disk full"); }), /disk full/);
    await assert.rejects(upload(), /outcome unknown/);
    assert.equal(calls, 1);
    checkpoint = await client.reconcileFailedUploadPayment(checkpoint, attempt => {
      assert.equal(attempt.submissions.length, 2);
      return reverted([hash, secondHash]);
    }, value => { checkpoint = value; });
    await upload();
    assert.equal(calls, 2);
    await assert.rejects(client.reconcileFailedUploadPayment(checkpoint, notSubmitted, () => {}), /no pending payment/);
  } finally { client.close(); }
});

test("confirmed receipt evidence cannot be cleared as an unsubmitted payment", async () => {
  const rtc = mockWebRtc(Array.from({ length: 7 }, () => ({})));
  const client = new BrowserNetworkClient(rtc.endpoints);
  client.test_allow_paid_writes();
  let checkpoint, writes = 0;
  try {
    await assert.rejects(client.uploadPublicFile(content, "fixture", "text/plain", paymentNetwork,
      async (_, quotes) => ({ ...receipt(quotes), totalAmount: "0" }), undefined, undefined,
      value => { checkpoint = value; }, "single"), /different payment total/);
    await assert.rejects(client.reconcileFailedUploadPayment(checkpoint, notSubmitted, () => { writes++; }),
      /submission evidence exists/);
    assert.equal(writes, 0);
  } finally { client.close(); }
});
