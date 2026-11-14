# Vendored from Project-DSpace/darwin-listings main (rev a4d5e10bcdc23d6c0693c7d1422f25e1628a8305), unchanged: v0.4.0's code on ant-protocol 6.0.0 and, as a dev-dependency, saorsa-core 0.30.0, with four test loops written as the current stable clippy asks (src/feed_sync.rs, src/walk.rs). darwin-node vendors 2b1cb84, the commit before, which differs only in those test lines.
# Only .github/ is left out. darwin-listings is public again; whether to return to the git dependency is open.
# It is a member of this workspace, so its own tests run under this repository's Cargo.lock (build.yml).
# Git object ids of the vendored copy, which build.yml checks so the copy can't drift unnoticed:
#   src tree:        1898f77ec3710125b61682085f09c9c2d656b029
#   Cargo.toml blob: d6309456d053102e6a59eb7dc534ea79881c9c6d
