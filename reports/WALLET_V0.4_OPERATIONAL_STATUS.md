# DOM Wallet — Operational Status of the v0.4 Line

Date: 2026-08-28
Source: operator attestation, recorded verbatim from live operation.
Scope: reconciles the stale residual-risk registers of
`WALLET_V0.2.0_STABILIZATION.md` and `WALLET_V0.2.1_RELEASE_VALIDATION.md`
with the network as it actually runs today.

## Why this document exists

The v0.2.x reports recorded evidence gaps, not defects. They were written
before the network went live and were never updated afterwards, so they
described as "missing evidence" things the running network has since
demonstrated daily. This document records what live operation has closed
and what genuinely remains.

## Closed by live operation (operator-attested, 2026-08-28)

| v0.2.x gap | Live evidence |
|---|---|
| Live-network evidence | The Mainnet chain is live and mining continuously; more than thirty thousand blocks have been mined. |
| Two-wallet transaction journey | A real transaction exchange with another user has been executed on the running network. |
| Windows installed lifecycle | The packaged Wallet is installed and operating on the operator's Windows machine. |
| macOS lifecycle | The packaged Wallet is operating on macOS. |
| Long-mining soak | Continuous mining across thirty thousand blocks exceeds any laboratory soak run. |
| Fault injection | Closed in code (2026-08-28): `dom-wallet-storage/tests/fault_injection.rs` proves that a commit interrupted by a full disk (genuine ENOSPC on a tmpfs), a read-only filesystem, a write-protected directory, or a mid-write failure (RLIMIT_FSIZE) fails with the typed I/O error, never moves the active generation, leaves the wallet readable, and recovers fully once the fault clears. The suite runs privileged and unprivileged. |
| Automatic-update feed | Working as designed: every new Wallet version is published only after the operator's cryptographic signature. The updater verifies the Tauri Minisign artifact signature plus the detached DOM manifest signature, SHA-256, and byte length; an unsigned or tampered version is never applied, and a missing production key fails closed. The sidecar enforces this policy at runtime. |
| PEX routability filtering | Fixed in code: the pinned `dom-node` revision `6f8a947` applies the publicly-routable policy on ingestion, confirmation, and sharing, with Mainnet tests pinning the behavior. |

This is operational attestation, not automated-gate output. The two live
Mainnet tests in the tree remain `#[ignore]` and were not converted into
deterministic successes; the network itself is the running proof.

## Genuinely remaining

1. **Operating-system code signing — deliberately deferred (operator
   decision, 2026-08-28).** Installers carry no Windows Authenticode and no
   Apple notarization, so new users see an unknown-publisher warning. The
   operator has decided not to invest in commercial certificates at this
   stage of the project; Minisign continues to authenticate the exact
   installer bytes for anyone who verifies. This is a recorded decision,
   not an open task.
2. **Historical proof-only outputs.** Permanent, by design: outputs without
   Recovery Capsule v1 cannot be reconstructed from the seed and remain
   backup-required. Not a defect; no code may manufacture a blinding.

## Precedence

Where the v0.2.x reports and this document disagree, this document and the
running network take precedence. The older reports remain in the tree as
the historical record of what was known at the time.
