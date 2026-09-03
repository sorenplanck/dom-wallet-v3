# DOM Wallet V3 v0.3.4

- Release date: 2026-09-03
- Tag: `wallet-v0.3.4`
- Source branch: `main-v0.4`
- DOM Protocol revision: `6f8a947dee0e54c3421caa295755b1746c178137`

## Highlights

- Measures network difficulty from the last 30 canonical mined headers instead
  of projecting the next target from local time and height.
- Shows distinct local and network hashrates on the Mining screen and fails
  closed with `—` while the node is synchronizing or history is insufficient.
- Presents the central DEPC-3 estimated production cost together with its
  existing low/high uncertainty range, without changing any DEPC constants.
- Labels Swap amounts with the selected asset's actual base unit: noms,
  satoshis, lamports, micro-USDT, or piconero.
- Avoids inventing an absolute Swap fee before an external-input quote exists;
  the preview shows only the ratified percentage in that case.
- Calculates and persists the accepted Swap fee from the solver-declared DOM
  leg, preserving the ratified 50/100 bps tiers.

## Compatibility and limits

- DOM Mainnet identity remains fixed to chain ID
  `f9831fadabc8a4234beab35fbb6327e84581645f33e9f75ed2ea78e8bcf1165b`.
- The pinned DOM Protocol revision and consensus rules are unchanged.
- Swap execution remains fail-closed unless a compatible interop daemon is
  configured and reachable.
- The application and network remain experimental. DOM initially has no
  monetary value. Do not use real funds.
- Installers are not Authenticode-signed or Apple-notarized and may trigger
  operating-system warnings. Release checksums and Minisign signatures remain
  authoritative for artifact verification.

## Required publication evidence

- The source commit is clean, pushed to `main-v0.4`, and reports `0.3.4` in the
  Rust workspace, frontend package, and Tauri configuration.
- Workspace tests, frontend tests/build, Rust formatting, Clippy, targeted
  release tests, dependency audit, and dependency policy checks pass.
- The GitHub validation workflow produces Linux, Windows, and macOS artifacts
  and their SHA-256 manifests from the exact source commit.
- Updater artifacts and the canonical DOM manifest are signed offline with the
  pinned Minisign release key and verified before `latest.json` is uploaded.
- The GitHub Release is attached to `wallet-v0.3.4`, is neither a draft nor a
  prerelease, and becomes the repository's latest release only after all
  referenced artifacts and signatures are present.
