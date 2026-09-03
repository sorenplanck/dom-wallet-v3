# DOM Wallet V3 v0.3.3

- Release date: 2026-09-03
- Tag: `wallet-v0.3.3`
- Source branch: `main-v0.4`
- DOM Protocol revision: `6f8a947dee0e54c3421caa295755b1746c178137`

## Highlights

- Adds the DEPC-3 estimated production cost to the Mining screen using live
  difficulty and the canonical next-block subsidy.
- Shows the exact network fee before send confirmation and fails closed when a
  fee cannot be computed.
- Adds deterministic level-1 Bitcoin, EVM, Monero, and Solana accounts derived
  on demand from the Wallet seed without persisting private key material.
- Adds the Swap intent, quote, execution, recovery, refund, resume, and history
  surfaces, backed by durable persist-before-act sessions and the ratified F6
  RFQ/relay protocol.
- Confirms mined transactions by canonical kernel evidence instead of mempool
  transaction hashes.
- Hardens remote input bounds, bearer-token and base-URL validation, wallet
  generation permissions, content security policy, and secret zeroization.
- Adds injected storage-fault coverage for full-disk, read-only, write-protected,
  and interrupted-write failure modes.

## Compatibility and limits

- DOM Mainnet identity remains fixed to chain ID
  `f9831fadabc8a4234beab35fbb6327e84581645f33e9f75ed2ea78e8bcf1165b`.
- Swap execution remains fail-closed unless a compatible interop daemon is
  configured and reachable.
- The application and network remain experimental. DOM initially has no
  monetary value. Do not use real funds.
- Installers are not Authenticode-signed or Apple-notarized and may trigger
  operating-system warnings. Release checksums and Minisign signatures remain
  authoritative for artifact verification.

## Required publication evidence

- The source commit is clean, pushed to `main-v0.4`, and reports `0.3.3` in the
  Rust workspace, frontend package, and Tauri configuration.
- Frontend tests/build, Rust formatting, Clippy, targeted release tests,
  dependency audit, and dependency policy checks pass with locked inputs.
- The GitHub validation workflow produces Linux, Windows, and macOS artifacts
  and their SHA-256 manifests from the exact source commit.
- Updater artifacts and the canonical DOM manifest are signed offline with the
  pinned Minisign release key and verified before `latest.json` is uploaded.
- The GitHub Release is attached to `wallet-v0.3.3`, is neither a draft nor a
  prerelease, and becomes the repository's latest release only after all
  referenced artifacts and signatures are present.
