# Releasing DOM Wallet V3

DOM and DOM Wallet are experimental software. DOM initially has no monetary
value. Do not use real funds. There is no guarantee of fitness, availability,
or absence of defects. Store the 24-word seed phrase securely and never share
it. Installers are unsigned, so operating-system warnings are expected.

## Release identity

- Wallet version: `0.1.0`
- Recommended tag: `wallet-v0.1.0`
- DOM Core revision: `6a8a6475b36ad68bb760d61cf323126d95cd7416`
- Mainnet chain ID: `f9831fadabc8a4234beab35fbb6327e84581645f33e9f75ed2ea78e8bcf1165b`
- Testnet identity: `2ab5e6c73607e8bfbbec2d4ce3ea1419cda29ae6892e7f1c24facc465cd65821`
- Regtest chain ID: `22384b4cbfaae306a7bdb23a822442f7e68fb51f65328697a754a9f3abd698e1`

Wallet V3 uses its embedded DOM Core through `WalletCoreApi`. It creates only
Recovery Capsule v1 outputs, uses Address v1 and recovery Slate v4, and has no
remote HTTP backend or proof-only production output path.

## Validation build

Run the Actions workflow manually on the intended branch with
`publish_release=false` and `validation_only=false`. This builds unsigned Linux,
Windows, and macOS artifacts and uploads checksums without creating or moving a
tag and without creating a GitHub Release.

## Later release authorization

After all local and CI gates pass and explicit authorization is given, verify
that the clean release commit reports version `0.1.0`, then run:

```bash
git tag -a wallet-v0.1.0 -m "DOM Wallet 0.1.0"
git push origin wallet-v0.1.0
```

Do not run these commands as part of validation. The tag workflow verifies
that the tag version equals the Cargo and frontend versions before packaging or
publication.

## Checksums and diagnostics

Each platform artifact includes a SHA-256 manifest. Verify a downloaded file
with `sha256sum -c SHA256SUMS.txt` from the artifact directory. Diagnostics must
be exported only through the redacted Wallet command; never include a seed
phrase, password, recovery root, private blinding, or wallet database.
