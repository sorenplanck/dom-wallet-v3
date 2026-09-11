# Releasing DOM Wallet V3

DOM and DOM Wallet are experimental software. DOM initially has no monetary
value. Do not use real funds. There is no guarantee of fitness, availability,
or absence of defects. Store the 24-word seed phrase securely and never share
it. Installers are unsigned, so operating-system warnings are expected.
No independent security audit is claimed.

## Release identity

- Wallet version: `0.4.0`
- Recommended tag: `wallet-v0.4.0`
- DOM Core and embedded node revision: `38dd70536f088a467f2b7175978c5a6ebb4e5bd4`
- Final genesis revision: `6a8a6475b36ad68bb760d61cf323126d95cd7416`
- Mainnet chain ID: `f9831fadabc8a4234beab35fbb6327e84581645f33e9f75ed2ea78e8bcf1165b`

## Offline signing and publication

Tag CI validates and packages the exact immutable revision, but never receives a
private key and never publishes a release. Download the validated artifacts,
sign each updater artifact locally with the offline Minisign release key
(ID `74197A95CA309CF0`, the key pinned in `tauri.conf.json` and `main.rs`),
verify every detached signature against the public key, and only then create
the GitHub release from the matching `wallet-v<version>` tag. Manual installers
may be published without a live updater feed, but `latest.json` must not be
published until every referenced artifact and signature is present and
verified.

The updater consumes the generated updater bundles (`.AppImage`, NSIS
`-setup.exe`, `.app.tar.gz`). CI enables `createUpdaterArtifacts` while passing
`--no-sign`, so it creates the unsigned archives without ever receiving a
signing key. The offline feed flow, per release:

1. `cargo run -p dom-wallet-updater --example feed_tool -- draft <artifacts-dir>
   <version> <wallet-revision>` builds the draft feed with per-platform URLs,
   sizes and SHA-256 digests, plus the unsigned `dom_manifest`.
2. `minisign -Sm <artifact>` for each of the three updater artifacts, then
   `feed_tool finalize` — the first pass injects the artifact signatures and
   emits `dom-manifest-canonical.bin` (the manifest signature covers the
   artifact signatures, so these bytes exist only now).
3. `minisign -Sm dom-manifest-canonical.bin`, then `feed_tool finalize` again
   to produce `latest.json`; `feed_tool verify` re-checks every signature,
   digest, origin and platform against the pinned public key before anything
   is uploaded.
4. Publish the release as **latest** (not a pre-release): the endpoints under
   `releases/latest/download/` only resolve when a non-prerelease release
   exists.

The final feed carries the identical raw Minisign text in both signature
positions: `platforms.*.signature` and `dom_manifest.artifacts[].signature`
must match byte for byte. Wallets 0.3.4 and 0.3.5 reject the whole feed with
`UPDATE_MANIFEST_INVALID` when the two fields differ (they compare the strings
without decoding), so a feed that base64-encodes the `platforms` copy — the
Tauri plugin convention, used by feeds up to and including the original
0.3.6 upload — is unappliable for every installed wallet older than 0.3.6.
The raw text is safe on the Tauri side because the DOM updater downloads and
Minisign-verifies each artifact itself and `Update::install` performs no
signature check of its own. If a published feed ever hits this rejection,
recovery needs no re-signing: base64-decode each `platforms.*.signature` in
`latest.json` back to the raw Minisign text and replace the release asset —
`dom_manifest` and its `manifest_signature` stay untouched.

Wallet V3 uses its embedded DOM Core through `WalletCoreApi` by default and can
use the authenticated remote scan-only source for restore and synchronization.
Transaction construction, submission and mining remain embedded-only. It
creates only Recovery Capsule v1 outputs, uses Address v1 and recovery Slate
v4, and has no proof-only production output path.

Confirmed Recovery Capsule v1 funds are recoverable from the 24-word BIP-39
phrase plus the canonical chain. Encrypted backup remains additional and
preserves off-chain state such as labels, contacts, pending contexts,
reservations, and preferences.

## Validation build

Run the Actions workflow manually on the intended branch with
`validation_only=false` and `release_version=0.3.5`. This builds unsigned Linux,
Windows, and macOS artifacts and uploads checksums without creating or moving a
tag and without creating a GitHub Release.

## Later release authorization

After all local and CI gates pass and explicit authorization is given, verify
that the clean release commit reports version `0.3.5`, then run:

```bash
git tag -a wallet-v0.3.5 -m "DOM Wallet V3 0.3.5 experimental"
git push origin wallet-v0.3.5
```

Do not run these commands as part of validation. The tag workflow verifies
that the tag version equals the Cargo and frontend versions before packaging or
publication.

## Checksums and diagnostics

Each platform artifact includes a SHA-256 manifest. Verify a downloaded file
with `sha256sum -c SHA256SUMS.txt` from the artifact directory. Diagnostics must
be exported only through the redacted Wallet command; never include a seed
phrase, password, recovery root, private blinding, or wallet database.
