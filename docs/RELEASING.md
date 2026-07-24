# Releasing DOM Wallet V3

DOM and DOM Wallet are experimental software. DOM initially has no monetary
value. Do not use real funds. There is no guarantee of fitness, availability,
or absence of defects. Store the 24-word seed phrase securely and never share
it. Installers are unsigned, so operating-system warnings are expected.
No independent security audit is claimed.

## Release identity

- Wallet version: `0.2.2`
- Recommended tag: `wallet-v0.2.2`
- DOM Core revision: `28ba3cefc9fbc913f126336482662528c68a7d8c`
- Final genesis revision: `6a8a6475b36ad68bb760d61cf323126d95cd7416`
- Mainnet chain ID: `f9831fadabc8a4234beab35fbb6327e84581645f33e9f75ed2ea78e8bcf1165b`

## Offline signing and publication

Tag CI validates and packages the exact immutable revision, but never receives a
private key and never publishes a release. Download the validated artifacts,
sign each updater artifact locally with the offline Tauri key, verify every
detached signature against the public key, and only then create the GitHub
pre-release from the matching `wallet-v<version>` tag. Manual installers may be
published without a live updater feed, but `latest.json` must not be published
until every referenced artifact and signature is present and verified.

Wallet V3 uses its embedded DOM Core through `WalletCoreApi`. It creates only
Recovery Capsule v1 outputs, uses Address v1 and recovery Slate v4, and has no
remote HTTP backend or proof-only production output path.

Confirmed Recovery Capsule v1 funds are recoverable from the 24-word BIP-39
phrase plus the canonical chain. Encrypted backup remains additional and
preserves off-chain state such as labels, contacts, pending contexts,
reservations, and preferences.

## Validation build

Run the Actions workflow manually on the intended branch with
`publish_release=false` and `validation_only=false`. This builds unsigned Linux,
Windows, and macOS artifacts and uploads checksums without creating or moving a
tag and without creating a GitHub Release.

## Later release authorization

After all local and CI gates pass and explicit authorization is given, verify
that the clean release commit reports version `0.2.2`, then run:

```bash
git tag -a wallet-v0.2.2 -m "DOM Wallet V3 0.2.2 experimental"
git push origin wallet-v0.2.2
```

Do not run these commands as part of validation. The tag workflow verifies
that the tag version equals the Cargo and frontend versions before packaging or
publication.

## Checksums and diagnostics

Each platform artifact includes a SHA-256 manifest. Verify a downloaded file
with `sha256sum -c SHA256SUMS.txt` from the artifact directory. Diagnostics must
be exported only through the redacted Wallet command; never include a seed
phrase, password, recovery root, private blinding, or wallet database.
