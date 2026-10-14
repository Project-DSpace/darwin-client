// Opt-in check, not run in CI, that a >4 GiB public file streams to disk in real Chromium.
// With `node start-devnet.mjs` running, production bindings in ../wasm-tests/pkg and a release `ant`:
// node large-file.mjs [path to ant, default ../../target/release/ant]
// Uploads the fixture's plaintext natively, then pipes it into the origin private file system.
import { chromium } from "@playwright/test";
import { spawnSync } from "node:child_process";
import { createWriteStream } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

const DEVNET_API = "http://127.0.0.1:35000/api";
const PKG = resolve("../wasm-tests/pkg");
const WRITE_BLOCK_BYTES = 4 * 1024 * 1024;
// A complete in-memory download over this budget must fail before any transfer.
const BUDGET_BYTES = 64 * 1024 * 1024;
const FOUR_GIB = 2 ** 32;
// Bytes read on each side of a probed position.
const PROBE_BYTES = 8;

const ant = resolve(process.argv[2] ?? "../../target/release/ant");
const file = JSON.parse(await readFile("../wasm-tests/fixtures/large-file.json", "utf8"));
const devnet = await (await fetch(`${DEVNET_API}/devnet-manifest.json`)).json();
const { endpoints } = await (await fetch(`${DEVNET_API}/browser-manifest.json`)).json();
const directory = await mkdtemp(join(tmpdir(), "ant-large-file-"));
const server = createServer(async (request, response) => {
  const name = request.url?.split("?")[0];
  if (name === "/") { response.setHeader("Content-Type", "text/html"); response.end("<!doctype html><title>Large file</title>"); return; }
  if (!["/ant_core.js", "/ant_core_bg.wasm"].includes(name)) { response.writeHead(404).end(); return; }
  response.setHeader("Content-Type", name.endsWith(".wasm") ? "application/wasm" : "text/javascript");
  response.end(await readFile(join(PKG, name.slice(1))));
});
let context;
try {
  // The fixture's plaintext, so the native upload must land on the fixture's address.
  const source = join(directory, "large-file.bin");
  const block = Buffer.alloc(WRITE_BLOCK_BYTES, file.byte);
  await pipeline(Readable.from((function* () {
    for (let left = file.size; left > 0; left -= block.length) yield block.subarray(0, Math.min(left, block.length));
  })()), createWriteStream(source));
  const manifest = join(directory, "devnet-manifest.json");
  await writeFile(manifest, JSON.stringify(devnet));
  // A throwaway home keeps the upload out of the real upload history.
  const home = join(directory, "home");
  const upload = spawnSync(ant, ["--json", "--devnet-manifest", manifest, "--allow-loopback", "--evm-network", "local",
    "file", "upload", source, "--public"], { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"],
    env: { ...process.env, HOME: home, XDG_DATA_HOME: home, XDG_CONFIG_HOME: home, SECRET_KEY: devnet.evm.wallet_private_key } });
  if (upload.status !== 0) throw new Error(`ant file upload failed with ${upload.status ?? upload.error}`);
  const uploaded = JSON.parse(upload.stdout);
  await rm(source);

  await new Promise(done => server.listen(0, "127.0.0.1", done));
  // A persistent profile gives the origin private file system a normal disk quota.
  context = await chromium.launchPersistentContext(join(directory, "profile"), { headless: true,
    args: ["--force-fieldtrials=WebRTC-NoSdpMangleUfrag/Enabled/"] });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  const result = await page.evaluate(async ({ endpoint, file, budget, boundary, probe }) => {
    const { default: init, BrowserNetworkClient } = await import("/ant_core.js");
    await init();
    const seconds = since => Math.round(performance.now() - since) / 1000;
    const filled = bytes => bytes.every(value => value === file.byte);
    const client = new BrowserNetworkClient([endpoint]);
    let started = performance.now();
    const reader = await client.openPublicFile(file.address);
    const openSeconds = seconds(started);
    const seek = await reader.readRange(boundary - probe, 2 * probe);

    const root = await navigator.storage.getDirectory();
    const handle = await root.getFileHandle("large-file.bin", { create: true });
    let progressCalls = 0, lastProgress;
    started = performance.now();
    const piped = await reader.pipeTo(await handle.createWritable(),
      { onProgress: written => { progressCalls++; lastProgress = written; } });
    const pipeSeconds = seconds(started);
    const stored = await handle.getFile();
    const around = new Uint8Array(await stored.slice(boundary - probe, boundary + probe).arrayBuffer());
    const tail = new Uint8Array(await stored.slice(stored.size - 2 * probe).arrayBuffer());
    const size = reader.size;
    reader.close();

    let budgetError;
    try { await client.downloadPublicFile(file.address, undefined, undefined, { maxMemoryBytes: budget }); }
    catch (error) { budgetError = String(error); }
    // Informational: whether this browser could hold the whole file in one buffer at all.
    let allocation;
    try { allocation = `allocated ${new Uint8Array(file.size).length} bytes`; }
    catch (error) { allocation = `${error.name}: ${error.message}`; }
    client.close(); client.free();
    await root.removeEntry("large-file.bin");
    return { size, seekFilled: seek.length === 2 * probe && filled(seek), bytesWritten: piped.bytesWritten,
      hash: piped.hash, storedSize: stored.size, storedFilled: filled(around) && filled(tail),
      progressCalls, lastProgress, budgetError, allocation, openSeconds, pipeSeconds };
  }, { endpoint: endpoints[0], file: { address: file.address, size: file.size, byte: file.byte },
    budget: BUDGET_BYTES, boundary: FOUR_GIB, probe: PROBE_BYTES });

  const checks = {
    uploadAddress: uploaded.address === file.address,
    size: result.size === file.size,
    seekAcross4GiB: result.seekFilled,
    bytesWritten: result.bytesWritten === file.size,
    hash: result.hash === file.hash,
    storedSize: result.storedSize === file.size,
    storedBytes: result.storedFilled,
    progress: result.lastProgress === file.size,
    budgetPointsAtPipeTo: result.budgetError?.includes("pipeTo") ?? false,
    noPageErrors: errors.length === 0,
  };
  console.log(JSON.stringify({ browser: context.browser()?.version() ?? chromium.name(),
    uploadSeconds: uploaded.elapsed_secs, result, errors, checks }, null, 2));
  const failed = Object.keys(checks).filter(name => !checks[name]);
  if (failed.length > 0) { console.error(`failed: ${failed.join(", ")}`); process.exitCode = 1; }
} finally {
  await context?.close();
  server.close();
  await rm(directory, { recursive: true, force: true });
}
