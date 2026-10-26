# Changelog

## 0.4.0

Payments are read from a set of vaults, each by its own address, and a root
vault's payments with the wave they were paid in.

### When root payments may begin

Payments through a root vault may begin at any time after this version, with
no further notice. A reader of an earlier version reads them as unpaid: a
listing or an upload proof paid through a root vault fails its check. Update
every reader of payments to this version, indexers included, before then.

### Changed

- `find_payment`, `verify_listing`, `verify_listing_receipts`, `check_offline`
  and `check_proof` take a `&VaultSet` in place of one vault's address.
  `VaultSet::v2_only(vault)` reads as before;
  `VaultSet::with_root(vault, RootVault { address, token })` also reads a root
  vault's payments, made in `token`.
- `PaymentLog` has a `data` field: the log's data, as the receipt gives it. A
  root vault's wave is read from the data of its `RootPaid` log and of its
  token's transfers, so fill it for every log.
- `PaymentError` has two new variants. `UnknownVault`: the log that would be
  the payment comes from a contract outside the set; such a log used to read as
  `NotPaid`. `UnpaidWave`: a root vault's log would be the payment, but the
  receipt doesn't show its wave whole, transfers included.
- A root vault's log counts as a payment only where the receipt shows its wave
  whole: its payment logs, then its `RootPaid` log naming the wave's key and
  total, then one transfer of the vault's token from the payer to each of the
  wave's payees, of the sum of its payments.
- Searches by quote hash, and by block and log index, cover every vault in the
  set in one `eth_getLogs` (`VaultSet::addresses`).

### Added

- `root`: the tree a root vault records each wave of payments under. `leaf`,
  `pair` and `key`; `Wave`, which checks a wave as the vault does and gives
  its root, key, paths and each payee's sum; `root_from_path` and `leaf_key`,
  the storer's check of a payment's path; `recorded_wave`, which reads a wave
  back from a receipt; `ROOT_PAID_TOPIC`, `TRANSFER_TOPIC`, `LEAF_LIMIT` (512)
  and `MAX_PATH_LEN` (9). It is checked against the vault's own test vectors,
  in `src/root/vectors/`, and `recorded_wave` against a receipt the vault's
  code wrote.

### Unchanged

- The listing format, the upload proof format and the listings protocol's
  messages.

## Earlier versions

0.1.0 to 0.3.1 are described by their tags' commits.
