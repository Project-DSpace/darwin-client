# ADR-0008: Carried upload state

- **Status:** Proposed
- **Date:** 2026-11-26
- **Decision owners:** Dan
- **Reviewers:** Pending human engineering review
- **Supersedes:** none
- **Superseded by:** none
- **Related:** `ant-core/src/data/client/carried.rs`; `ant-core/src/data/client/upload_state.rs`; ADR-0007

## Context

An upload saves its paid quotes and proofs in its own checkpoint under the client's data
directory, named by a private scope: the network, every content record's address and size, the
envelope choices, and the payer's `checkpoint_scope`. Only the same payer on the same machine
resumes it. When a client that pays for uploads on behalf of others (an outside `UploadPayer`)
stops after a payment and before the upload finishes, no other client can finish that upload
without paying again: the paid quotes exist only in the first client's checkpoint.

`UploadState` is already public and portable. `UploadState::checkpoint` writes it as bytes and
`UploadState::restore` reads them back, checking every quote's signature and identity. What was
missing is a way for an upload to be given a state another client saved, and a way for a payer to
get the state the engine saved.

The two callers differ. An outside payer uploads through `Client::file_upload_with_payer`. The
command line's wallet upload has no payer and calls the engine with none.

## Decision Drivers

- No second payment for a record whose carried proof a storer accepts.
- Payment recovery stays as it is: a saved checkpoint, and a payment attempt pending in it, are
  never replaced or deleted by a carried state.
- A carried record passes every check a resumed record passes: quote signatures and identities,
  the price ceiling, occupied-quote handling, payments in the network's token, merkle refusal.
- Every payment path the engine has is either covered by a carried state or refused in words, and
  a census test pins the list.
- One engine path for both callers, and no change for existing payers.

## Considered Options

1. A trait method alone (`UploadPayer::carried_state`). It does not reach the command line,
   because the wallet path has no payer.
2. An options struct alone. A payer would have to leave `file_upload_with_payer` and repeat its
   payer wiring.
3. A state the payer builds itself with `prepare` and `confirm`. It cannot hold root proofs (the
   engine finds the root wave) and does not know which occupied quotes the engine released, so
   the second client would pay root-paid records again.
4. Refuse a carried state when the upload already has a saved checkpoint. A client that stopped
   after taking a carried state would then pay again, without saying so.
5. Refuse every carried payment attempt not yet confirmed. In the main case (a client stops
   between sending a payment and confirming it) that would also lose the confirmed proofs.
6. Carry the private envelope's salt as well. The salt is not part of the paid state
   `UploadState` holds, so the state carries proofs and payments only, and the second client's
   private envelope gets a salt of its own.
7. Two thin inputs into one engine point, one output from the engine, and a merge into the
   upload's own checkpoint (chosen).

## Decision

We will give the engine one internal input, a carried state as bytes, filled from either of two
public inputs, and one public output:

- `UploadPayer::carried_state`, defaulted to `None`, which the engine asks once per upload, right
  after it opens the upload's own checkpoint.
- `Client::file_upload_carried` with `CarriedUploadOptions` (`#[non_exhaustive]`, built with
  `CarriedUploadOptions::new(state)`), for a wallet upload; `darwin file upload <path> --carried
  <file>` reads the file's raw bytes and calls it.
- `UploadPayer::state_saved`, defaulted to doing nothing, which the engine calls after every save
  of the checkpoint and once when a carried state is taken. It is the only supported source of
  carried bytes.

The engine merges a carried state into the upload's state and never replaces anything: a proof is
added only for a record of this upload whose own state holds none, and only proofs and a payer's
pending payment attempt are taken. Unpaid quotes are not taken; those records are quoted and paid
again through the per-chunk path. A payer's attempt not yet confirmed is settled through the new
payer, which is asked for exactly its plans, as on any resume; a wallet's is refused, since only
the wallet that made it can settle it. A payer's attempt is left out when the upload's own state
already holds it (an earlier run took it from the same state) or proves, has paid again or holds
pending every one of its records, so a payer is never asked again for a payment the upload settled.
When the upload's own state holds some of its records and not the others, the state is refused:
a payment is settled whole, and left out, its other records would be paid again under new quotes. A
proof is not taken for a record the upload marked as paid again and dropped. A state that fails
`UploadState::restore`'s checks, that is a checkpoint's main file without its proofs, that names
none of the upload's records, that holds a Merkle proof or a pending Merkle batch, whose pending
attempt names records outside the upload, meets another attempt already saved, or pays a quote
above the client's price ceiling (`ClientConfig::max_chunk_price`, which a reconciled plan is not
quoted again to meet), is
refused whole with `Error::InvalidData` starting with `CARRIED_STATE_REFUSED`, before anything is
quoted, paid or saved.

`carried.rs` names each payment path once (the per-quote vault, a root wave, a shared wave, a
merkle batch, journaled and pending attempts) and says for each whether a carried state covers it,
settles it through the payer, quotes it again, does not carry it, or refuses it, with the refusal
words. A unit test checks every path, and the engine's refusal text equals the census words.

A carried lock, named only by the network and the records, serialises uploads on one machine that
are given a carried state for the same file. The engine saves the merged state once before any
payment, so a stopped run resumes from its own checkpoint.

`FileUploadResult::carried` (`CarriedOutcome`, serialisable) counts the proofs in the state, those
taken, the records settled through the payer, the records paid again, and the records quoted again.

## Consequences

### Positive

- An upload paid by one client can be finished by another, on another machine, with no second
  payment for the records whose proofs a storer accepts.
- Existing payers and uploads are unchanged: both trait methods are defaulted, and the wallet's
  existing entry points take no carried state.
- Payment recovery is unchanged: a saved checkpoint and its pending attempt are kept whole.

### Negative / Trade-offs

- A private envelope gets a new salt on the second client, so its envelope record is paid once
  more, alone in its payment.
- A price ceiling below the network's quotes stops the upload when a record must be paid again,
  as on any upload.
- A carried state is not bound to a network in its bytes: the carried lock and the upload's own
  checkpoint are named by the network, the state is not.
- Uploads on different machines cannot see each other, so they are not serialised: a state must
  be given to one client at a time, and the newest state handed out is the one to carry.

### Neutral / Operational

- The command line reads the raw bytes `UploadState::checkpoint` writes, with no wrapper. The
  `.msgpack` main file in the data directory holds no proofs and is refused.
- `darwin file upload --merkle` is still refused before the carried file is read.

## Validation

- `carried::tests` in ant-core: every payment path is covered or refused, and each refusal (bad
  signature, main file without proofs, proof under another record's address, Merkle proof or
  batch, wallet journal, wallet pending attempt, root attempt for a payer that does not pay root
  waves, records outside the upload, a state for another file) is refused whole.
- `payer_tests` in ant-core: a saved checkpoint is kept whole, carried proofs are saved before any
  payment, the carried lock serialises two uploads, and `state_saved` is called after each save.
- The `carried` end-to-end group: a second client stores the paid records with no new payment
  (readable, private and root-wave runs), occupied quotes, a pending payment settled by the second
  payer, expired proofs and unpaid quotes paid again and counted, the price ceiling, a saved
  checkpoint kept when a carried state is refused, and the wallet's entry point.
- ant-cli: the census lists the new store and payment sites, and the pinned arguments of `darwin
  file upload` include `carried`.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
