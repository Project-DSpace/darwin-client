// Test callers persist checkpoints just as the SDK does; production bindings stay unwrapped.
import { BrowserNetworkClient as RawBrowserNetworkClient } from "./pkg/ant_core.js";

// What a page's client answers when asked for an upload or a pointer write:
// they are off in this build (src/browser/paid_writes.rs).
export const PAID_WRITES_OFF = "uploads and pointer writes from the browser core are off in this " +
  "build: they don't yet carry the payment record, the read-back of paid quotes, or " +
  "per-chunk-only payment. Use the darwin client.";

// The client a page gets: every upload and pointer write is refused.
export { RawBrowserNetworkClient as PageClient };

// The tests of the upload and pointer-write code underneath the exports use
// this client, which a test build lets through; paid-writes-off.test.mjs
// checks that a page's client is refused.
export class BrowserNetworkClient extends RawBrowserNetworkClient {
  constructor(...args) {
    super(...args);
    this.test_allow_paid_writes();
  }
  uploadPublicFile(...args) {
    args[7] ??= value => { this.lastCheckpoint = value; };
    return super.uploadPublicFile(...args);
  }
  uploadStagedPublicFile(...args) {
    args[6] ??= value => { this.lastCheckpoint = value; };
    return super.uploadStagedPublicFile(...args);
  }
  uploadRecords(...args) {
    args[6] ??= value => { this.lastCheckpoint = value; };
    return super.uploadRecords(...args);
  }
}
