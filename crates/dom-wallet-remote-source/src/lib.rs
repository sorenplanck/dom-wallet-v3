//! Remote full-fidelity chain source for Wallet V3.
//!
//! [`RemoteNodeSource`] implements the frozen [`WalletCoreApi`] scanner surface
//! over synchronous HTTP against a remote DOM node, so `CoreChainAdapter` and
//! `SeedRestoreService` consume a remote node exactly like the embedded one:
//!
//! - `GET /chain/scan/full?from&to` (Bearer) serves identity, tip, and V3
//!   block projections (range proofs + recovery capsules) — schema pinned in
//!   `reports/REMOTE_SCAN_V3_SCHEMA.md`, wire `schema_version` 1.
//! - `GET /block/:height` (public) serves canonical headers for
//!   [`WalletCoreApi::canonical_hash_at_height`] and client-side
//!   [`WalletCoreApi::validate_cursor`].
//!
//! # Privacy invariant (do not weaken)
//!
//! This source downloads EVERY block of the requested range with EVERY output,
//! proof, and capsule. Selective per-output or per-commitment queries are
//! forbidden: they would reveal to the remote operator which outputs the
//! wallet cares about. Non-empty `commitment_filters` are rejected locally,
//! before any network traffic, and no endpoint keyed by a commitment is ever
//! called (`get_utxo`/`get_kernel` are deliberately unimplemented).
//!
//! # Error classes (`reports/REMOTE_SCAN_V3_SCHEMA.md` §4)
//!
//! - Retriable (the scan loop retries with backoff; NEVER terminal): HTTP 503
//!   busy → [`WalletCoreError::NodeNotReady`]; HTTP 429 / 5xx gateway /
//!   timeout / connection / DNS / TLS failures →
//!   [`WalletCoreError::TemporaryFailure`].
//! - Terminal: HTTP 401/403 (bad bearer configuration), HTTP 404 (remote node
//!   lacks `/chain/scan/full`), and any wire-schema violation →
//!   [`WalletCoreError::InternalFailure`]; identity drift →
//!   [`WalletCoreError::CursorChainMismatch`]; stable `canonical_gap` code →
//!   [`WalletCoreError::CanonicalGap`].
//!
//! Retry/backoff deliberately does NOT live here — the existing scan loop
//! owns retries. This source only classifies failures correctly.

#![forbid(unsafe_code)]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use dom_consensus::Transaction;
use dom_wallet_core_api::{
    BlockRef, BlockSelector, BlockSummary, ChainIdentity, CoinbaseScanMetadata, CoreNetwork,
    CursorValidation, FeeBreakdown, FeeEstimate, FeeEstimateRequest, FeePolicySnapshot,
    FeeValidation, KernelQueryResult, MempoolPolicySnapshot, ScanBlock, ScanInput, ScanKernel,
    ScanOutput, ScanRequest, ScanResult, ScanStart, SubmissionResult, SubmitTransactionRequest,
    SyncStatus, TransactionIdentifier, TransactionShape, TransactionStatus, TransactionWeight,
    UtxoQueryResult, WalletCoreApi, WalletCoreError, WalletScanCursor,
};
use serde::Deserialize;
use std::fmt;
use std::sync::Mutex;
use std::time::Duration;
use thiserror::Error;

/// TCP connect timeout for every remote request.
pub const REMOTE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Total per-request timeout. The node's own server-side request timeout is
/// 30 s, so a slower answer will never arrive anyway.
pub const REMOTE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// `/chain/scan/full` wire schema version this client understands. Any other
/// version on the wire is a terminal schema violation.
pub const REMOTE_FULL_SCAN_SCHEMA_VERSION: u32 = 1;

/// Server-side clamp of one `/chain/scan/full` page
/// (`MAX_FULL_SCAN_RANGE = MAX_SCAN_RANGE = 1000` in `dom-rpc`). A response
/// spanning more heights than this is a schema violation.
pub const REMOTE_MAX_FULL_SCAN_RANGE: u64 = 1_000;

/// Configuration errors raised while constructing a [`RemoteNodeSource`].
#[derive(Debug, Error)]
pub enum RemoteSourceConfigError {
    /// The base URL failed to parse.
    #[error("invalid remote node base URL: {0}")]
    InvalidBaseUrl(String),
    /// The base URL scheme is not `http`/`https`.
    #[error("remote node base URL must use http or https")]
    UnsupportedScheme,
    /// A bearer token was supplied but is empty after trimming.
    #[error("remote node bearer token must not be empty")]
    EmptyBearerToken,
    /// The HTTP client could not be constructed.
    #[error("failed to build remote HTTP client: {0}")]
    ClientBuild(String),
}

/// Inconsistent tip regression reported by the remote node within one session.
///
/// The observed canonical tip height moved backwards relative to a tip this
/// session already saw. A canonical proof-of-work switch to a lower height is
/// theoretically possible but extremely unusual, so this is surfaced as an
/// alert ("possibly lying remote node") for the consumer to act on — it never
/// aborts a scan by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TipRegression {
    /// Highest tip previously observed in this session.
    pub previous: BlockRef,
    /// Regressed tip reported afterwards.
    pub observed: BlockRef,
}

/// Bearer token wrapper that never leaks the secret through `Debug`.
struct BearerToken(String);

impl fmt::Debug for BearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BearerToken(<redacted>)")
    }
}

#[derive(Debug, Default)]
struct SessionState {
    /// Identity pinned on the first successful response; all later responses
    /// must match it field by field (tip excluded).
    pinned_identity: Option<ChainIdentity>,
    /// Highest tip observed in this session (high-water mark, so repeated
    /// regressions keep being detected against the honest maximum).
    highest_tip: Option<BlockRef>,
    /// First-detected tip regression, kept until the session ends.
    tip_regression: Option<TipRegression>,
}

/// Remote DOM node consumed through the frozen [`WalletCoreApi`] contract.
///
/// Only the scan surface (`chain_identity`, `scan_range`, `scan_next`,
/// `validate_cursor`, `canonical_hash_at_height`) plus derived readiness is
/// served remotely. Submission and fee-policy operations return a stable,
/// non-retriable error: spending stays on the embedded node.
pub struct RemoteNodeSource {
    base_url: String,
    bearer_token: Option<BearerToken>,
    client: reqwest::blocking::Client,
    session: Mutex<SessionState>,
}

impl fmt::Debug for RemoteNodeSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteNodeSource")
            .field("base_url", &self.base_url)
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "<redacted>"),
            )
            .finish_non_exhaustive()
    }
}

impl RemoteNodeSource {
    /// Build a remote source for `base_url` (e.g. `http://127.0.0.1:8645`).
    ///
    /// The bearer token is trimmed (the node writes `~/.dom/rpc_token` with a
    /// trailing newline). Redirects are disabled so the token can never be
    /// replayed to another host.
    pub fn new(
        base_url: &str,
        bearer_token: Option<&str>,
    ) -> Result<Self, RemoteSourceConfigError> {
        let parsed = url::Url::parse(base_url.trim())
            .map_err(|error| RemoteSourceConfigError::InvalidBaseUrl(error.to_string()))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(RemoteSourceConfigError::UnsupportedScheme);
        }
        let bearer_token = match bearer_token {
            None => None,
            Some(raw) => {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Err(RemoteSourceConfigError::EmptyBearerToken);
                }
                Some(BearerToken(trimmed.to_string()))
            }
        };
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(REMOTE_CONNECT_TIMEOUT)
            .timeout(REMOTE_REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| RemoteSourceConfigError::ClientBuild(error.to_string()))?;
        Ok(Self {
            base_url: parsed.as_str().trim_end_matches('/').to_string(),
            bearer_token,
            client,
            session: Mutex::new(SessionState::default()),
        })
    }

    /// Tip regression detected in this session, if any. `Some` means the
    /// remote node reported a canonical tip below a tip it already served —
    /// the consumer decides whether to distrust the node.
    pub fn tip_regression(&self) -> Option<TipRegression> {
        self.lock_session().tip_regression
    }

    /// Highest canonical tip observed from the remote node in this session.
    pub fn last_observed_tip(&self) -> Option<BlockRef> {
        self.lock_session().highest_tip
    }

    fn lock_session(&self) -> std::sync::MutexGuard<'_, SessionState> {
        // A poisoned lock only means another thread panicked mid-update; the
        // state itself stays structurally valid, so recover instead of
        // panicking in production.
        self.session
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn http_get(
        &self,
        path_and_query: &str,
        authenticated: bool,
    ) -> Result<HttpReply, WalletCoreError> {
        let url = format!("{}{}", self.base_url, path_and_query);
        let mut request = self.client.get(url);
        if authenticated {
            if let Some(token) = &self.bearer_token {
                request = request.bearer_auth(&token.0);
            }
        }
        let response = request.send().map_err(map_transport_error)?;
        let status = response.status().as_u16();
        let body = response.text().map_err(map_transport_error)?;
        Ok(HttpReply { status, body })
    }

    /// Fetch and fully validate one `/chain/scan/full` page.
    ///
    /// PRIVACY: the request carries only a height range — never an output or
    /// commitment selector — and the response carries all blocks of the range.
    fn fetch_full_scan(&self, from: u64, to: u64) -> Result<ParsedFullScan, WalletCoreError> {
        let reply = self.http_get(&format!("/chain/scan/full?from={from}&to={to}"), true)?;
        if reply.status != 200 {
            return Err(map_full_scan_status(reply.status, &reply.body));
        }
        parse_full_scan(from, to, &reply.body)
    }

    /// Pin the session identity on first sight; afterwards require every
    /// response to describe the same chain, and track the reported tip.
    fn observe_identity(&self, identity: &ChainIdentity) -> Result<(), WalletCoreError> {
        let mut session = self.lock_session();
        if let Some(pinned) = &session.pinned_identity {
            if !same_immutable_identity(pinned, identity) {
                return Err(WalletCoreError::CursorChainMismatch(
                    "remote node identity drifted within this session".to_string(),
                ));
            }
        } else {
            session.pinned_identity = Some(identity.clone());
        }
        let observed = identity.current_tip;
        match session.highest_tip {
            Some(previous) if observed.height < previous.height => {
                if session.tip_regression.is_none() {
                    session.tip_regression = Some(TipRegression { previous, observed });
                }
            }
            _ => session.highest_tip = Some(observed),
        }
        Ok(())
    }

    fn session_identity_or_probe(&self) -> Result<ChainIdentity, WalletCoreError> {
        if let Some(pinned) = self.lock_session().pinned_identity.clone() {
            return Ok(pinned);
        }
        self.chain_identity()
    }

    /// Fetch the canonical hash at `height` through the public header
    /// endpoint. `404 {"found": false}` means "no canonical block here".
    fn fetch_block_hash(&self, height: u64) -> Result<Option<[u8; 32]>, WalletCoreError> {
        let reply = self.http_get(&format!("/block/{height}"), false)?;
        match reply.status {
            200 => {
                let header: WireBlockHeader = serde_json::from_str(&reply.body)
                    .map_err(|_| schema_violation("BLOCK_HEADER_DECODE"))?;
                if header.height != height {
                    return Err(schema_violation("BLOCK_HEADER_HEIGHT"));
                }
                Ok(Some(decode_hash32(&header.hash, "BLOCK_HEADER_HASH")?))
            }
            404 => Ok(None),
            other => Err(map_block_status(other, &reply.body)),
        }
    }
}

impl WalletCoreApi for RemoteNodeSource {
    fn chain_identity(&self) -> Result<ChainIdentity, WalletCoreError> {
        // Cheap identity probe: `from > to` yields an empty page that still
        // carries identity and tip — one try_lock on the node, no block loads.
        let parsed = self.fetch_full_scan(1, 0)?;
        self.observe_identity(&parsed.identity)?;
        Ok(parsed.identity)
    }

    fn scan_range(&self, request: ScanRequest) -> Result<ScanResult, WalletCoreError> {
        if !request.commitment_filters.is_empty() {
            // PRIVACY: a filtered remote scan would reveal wallet interest in
            // specific commitments. Rejected before any network traffic.
            return Err(WalletCoreError::InvalidScanRequest(
                "remote source is full-scan only: commitment filters are forbidden".to_string(),
            ));
        }
        if request.max_blocks == 0 {
            return Err(WalletCoreError::InvalidScanRequest(
                "max_blocks must be greater than zero".to_string(),
            ));
        }
        let start_height = match &request.start {
            ScanStart::Height(height) => *height,
            ScanStart::Cursor(cursor) => {
                // Mirrors the embedded node: a stale anchor is CursorReorg.
                self.validate_cursor(*cursor)?;
                cursor.next_height
            }
        };
        let span_end = start_height.saturating_add(request.max_blocks - 1);
        let wire_to = match request.stop_height {
            Some(stop) => span_end.min(stop),
            None => span_end,
        };
        let parsed = self.fetch_full_scan(start_height, wire_to)?;
        // Mirrors EmbeddedWalletCoreApi::validate_request_identity.
        if request.network != parsed.identity.network
            || request.chain_id != parsed.identity.chain_id
        {
            return Err(WalletCoreError::CursorChainMismatch(
                "request identity does not match remote node identity".to_string(),
            ));
        }
        self.observe_identity(&parsed.identity)?;

        let tip = parsed.identity.current_tip;
        // The server clamps the page (range cap, tip, response budget) and
        // echoes the effective `to`; continuation follows the effective page,
        // exactly like the embedded scan_range.
        let stop_height = request.stop_height.unwrap_or(tip.height).min(tip.height);
        let continuation = parsed.blocks.last().and_then(|block| {
            (block.height < stop_height).then(|| {
                WalletScanCursor::new(
                    parsed.identity.network,
                    parsed.identity.chain_id,
                    block.height.saturating_add(1),
                    BlockRef {
                        height: block.height,
                        hash: block.block_hash,
                    },
                )
            })
        });
        Ok(ScanResult {
            tip,
            blocks: parsed.blocks,
            continuation,
        })
    }

    fn validate_cursor(
        &self,
        cursor: WalletScanCursor,
    ) -> Result<CursorValidation, WalletCoreError> {
        cursor.validate_shape()?;
        let identity = self.session_identity_or_probe()?;
        if cursor.network_magic != identity.network_magic || cursor.chain_id != identity.chain_id {
            return Err(WalletCoreError::CursorChainMismatch(
                "cursor identity does not match remote node identity".to_string(),
            ));
        }
        // Client-side mirror of the embedded validate_cursor_locked, built on
        // the public header endpoint.
        match self.fetch_block_hash(cursor.anchor_height)? {
            None => Err(WalletCoreError::CursorReorg(
                "cursor anchor height is no longer canonical".to_string(),
            )),
            Some(hash) if hash != cursor.anchor_hash => Err(WalletCoreError::CursorReorg(
                "cursor anchor hash differs from canonical hash".to_string(),
            )),
            Some(_) => Ok(CursorValidation {
                valid: true,
                safe_rescan_anchor: BlockRef {
                    height: cursor.anchor_height,
                    hash: cursor.anchor_hash,
                },
            }),
        }
    }

    fn canonical_hash_at_height(&self, height: u64) -> Result<Option<[u8; 32]>, WalletCoreError> {
        self.fetch_block_hash(height)
    }

    fn get_utxo(&self, _commitment: &[u8; 33]) -> Result<Option<UtxoQueryResult>, WalletCoreError> {
        // PRIVACY: also intentionally unimplemented — a per-commitment lookup
        // against a remote operator leaks wallet interest in that output.
        Err(requires_embedded_node("utxo lookup"))
    }

    fn get_kernel(&self, _excess: &[u8; 33]) -> Result<Option<KernelQueryResult>, WalletCoreError> {
        Err(requires_embedded_node("kernel lookup"))
    }

    fn get_block_summary(
        &self,
        _selector: BlockSelector,
    ) -> Result<Option<BlockSummary>, WalletCoreError> {
        Err(requires_embedded_node("block summary"))
    }

    fn transaction_status(
        &self,
        _id: TransactionIdentifier,
    ) -> Result<TransactionStatus, WalletCoreError> {
        Err(requires_embedded_node("transaction status"))
    }

    fn submit_transaction(
        &self,
        _request: SubmitTransactionRequest,
    ) -> Result<SubmissionResult, WalletCoreError> {
        Err(requires_embedded_node("transaction submission"))
    }

    fn rebroadcast_transaction(
        &self,
        _id: TransactionIdentifier,
    ) -> Result<SubmissionResult, WalletCoreError> {
        Err(requires_embedded_node("transaction rebroadcast"))
    }

    fn query_submission(
        &self,
        _id: TransactionIdentifier,
    ) -> Result<SubmissionResult, WalletCoreError> {
        Err(requires_embedded_node("submission query"))
    }

    fn sync_status(&self) -> Result<SyncStatus, WalletCoreError> {
        // A remote node that answers already serves its canonical chain, so
        // the only states are Ready and Busy (retriable outage).
        match self.chain_identity() {
            Ok(_) => Ok(SyncStatus::Ready),
            Err(WalletCoreError::NodeNotReady(_) | WalletCoreError::TemporaryFailure(_)) => {
                Ok(SyncStatus::Busy)
            }
            Err(error) => Err(error),
        }
    }

    fn is_ready_for_wallet_operations(&self) -> Result<bool, WalletCoreError> {
        match self.chain_identity() {
            Ok(_) => Ok(true),
            Err(WalletCoreError::NodeNotReady(_) | WalletCoreError::TemporaryFailure(_)) => {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    fn mempool_policy_snapshot(&self) -> Result<MempoolPolicySnapshot, WalletCoreError> {
        Err(requires_embedded_node("mempool policy"))
    }

    fn fee_policy_snapshot(&self) -> Result<FeePolicySnapshot, WalletCoreError> {
        Err(requires_embedded_node("fee policy"))
    }

    fn transaction_weight(
        &self,
        _shape: TransactionShape,
    ) -> Result<TransactionWeight, WalletCoreError> {
        Err(requires_embedded_node("transaction weight"))
    }

    fn minimum_fee(&self, _shape: TransactionShape) -> Result<FeeBreakdown, WalletCoreError> {
        Err(requires_embedded_node("minimum fee"))
    }

    fn estimate_fee(&self, _request: FeeEstimateRequest) -> Result<FeeEstimate, WalletCoreError> {
        Err(requires_embedded_node("fee estimation"))
    }

    fn validate_fee(&self, _transaction: &Transaction) -> Result<FeeValidation, WalletCoreError> {
        Err(requires_embedded_node("fee validation"))
    }
}

struct HttpReply {
    status: u16,
    body: String,
}

/// Fully validated `/chain/scan/full` page mapped to the frozen Core types.
struct ParsedFullScan {
    identity: ChainIdentity,
    blocks: Vec<ScanBlock>,
}

/// Stable, non-retriable "this needs the embedded node" error.
///
/// `InternalFailure` maps to `CoreScanError::CoreContract` (terminal) in the
/// wallet, so composition mistakes fail fast instead of retrying forever. The
/// app composition must never wire SUBMIT/FEE services to a remote source.
fn requires_embedded_node(operation: &str) -> WalletCoreError {
    WalletCoreError::InternalFailure(format!(
        "operation requires the embedded node: remote scan source does not serve {operation}"
    ))
}

fn schema_violation(code: &str) -> WalletCoreError {
    WalletCoreError::InternalFailure(format!("remote schema violation: {code}"))
}

/// Transport-level failures (timeout, refused/reset connection, DNS, TLS) are
/// all transient from the wallet's perspective: the scan loop retries with
/// backoff. The error text never contains the bearer token.
fn map_transport_error(error: reqwest::Error) -> WalletCoreError {
    WalletCoreError::TemporaryFailure(format!("remote transport failure: {error}"))
}

/// Map a non-200 `/chain/scan/full` status per the pinned contract.
fn map_full_scan_status(status: u16, body: &str) -> WalletCoreError {
    match status {
        503 => WalletCoreError::NodeNotReady(format!("remote chain busy: {}", body_snippet(body))),
        429 => WalletCoreError::TemporaryFailure("remote rate limited".to_string()),
        401 | 403 => WalletCoreError::InternalFailure(
            "remote unauthorized: check the configured bearer token".to_string(),
        ),
        404 => WalletCoreError::InternalFailure(
            "remote node lacks /chain/scan/full: upgrade the remote node".to_string(),
        ),
        400 => WalletCoreError::InvalidScanRequest(format!(
            "remote rejected scan query: {}",
            body_snippet(body)
        )),
        500 if json_error_code(body).as_deref() == Some("canonical_gap") => {
            WalletCoreError::CanonicalGap(format!("remote {}", body_snippet(body)))
        }
        500..=599 => WalletCoreError::TemporaryFailure(format!(
            "remote server failure {status}: {}",
            body_snippet(body)
        )),
        other => WalletCoreError::InternalFailure(format!(
            "remote returned unexpected status {other}: {}",
            body_snippet(body)
        )),
    }
}

/// Map a non-200/404 public `/block/:height` status.
fn map_block_status(status: u16, body: &str) -> WalletCoreError {
    match status {
        503 => WalletCoreError::NodeNotReady(format!("remote chain busy: {}", body_snippet(body))),
        429 => WalletCoreError::TemporaryFailure("remote rate limited".to_string()),
        500..=599 => WalletCoreError::TemporaryFailure(format!(
            "remote server failure {status}: {}",
            body_snippet(body)
        )),
        other => WalletCoreError::InternalFailure(format!(
            "remote block endpoint returned unexpected status {other}: {}",
            body_snippet(body)
        )),
    }
}

fn body_snippet(body: &str) -> String {
    const LIMIT: usize = 200;
    let trimmed = body.trim();
    if trimmed.len() <= LIMIT {
        trimmed.to_string()
    } else {
        let mut end = LIMIT;
        while !trimmed.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &trimmed[..end])
    }
}

fn json_error_code(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    Some(value.get("code")?.as_str()?.to_string())
}

fn same_immutable_identity(expected: &ChainIdentity, actual: &ChainIdentity) -> bool {
    expected.network == actual.network
        && expected.network_magic == actual.network_magic
        && expected.chain_id == actual.chain_id
        && expected.genesis_hash == actual.genesis_hash
        && expected.protocol_version == actual.protocol_version
        && expected.range_proof_serialization_version == actual.range_proof_serialization_version
        && expected.coinbase_maturity == actual.coinbase_maturity
}

// ── Wire schema (reports/REMOTE_SCAN_V3_SCHEMA.md §3) ───────────────────────

#[derive(Deserialize)]
struct WireFullScan {
    schema_version: u32,
    identity: WireIdentity,
    tip: WireTip,
    from: u64,
    to: u64,
    blocks: Vec<WireBlock>,
}

#[derive(Deserialize)]
struct WireIdentity {
    network: String,
    network_magic: u32,
    chain_id: String,
    genesis_hash: String,
    protocol_version: u32,
    range_proof_serialization_version: u8,
    coinbase_maturity: u64,
}

#[derive(Deserialize)]
struct WireTip {
    height: u64,
    hash: String,
}

#[derive(Deserialize)]
struct WireBlock {
    height: u64,
    block_hash: String,
    previous_block_hash: String,
    timestamp: u64,
    canonical_marker: String,
    protocol_version: u32,
    range_proof_serialization_version: u8,
    total_fees_noms: u64,
    coinbase: WireCoinbase,
    outputs: Vec<WireOutput>,
    inputs: Vec<String>,
    kernels: Vec<WireKernel>,
}

#[derive(Deserialize)]
struct WireCoinbase {
    output_commitment: String,
    explicit_value: u64,
    kernel_excess: String,
}

#[derive(Deserialize)]
struct WireOutput {
    commitment: String,
    range_proof: String,
    recovery_capsule: String,
    recovery_version: u16,
    is_coinbase: bool,
    output_position: u32,
}

#[derive(Deserialize)]
struct WireKernel {
    excess: String,
    features: u8,
    fee: u64,
    lock_height: u64,
}

#[derive(Deserialize)]
struct WireBlockHeader {
    height: u64,
    hash: String,
}

fn decode_hash32(text: &str, code: &str) -> Result<[u8; 32], WalletCoreError> {
    let bytes = hex::decode(text).map_err(|_| schema_violation(code))?;
    bytes.try_into().map_err(|_| schema_violation(code))
}

fn decode_commitment33(text: &str, code: &str) -> Result<[u8; 33], WalletCoreError> {
    let bytes = hex::decode(text).map_err(|_| schema_violation(code))?;
    bytes.try_into().map_err(|_| schema_violation(code))
}

fn decode_network(name: &str) -> Result<CoreNetwork, WalletCoreError> {
    match name {
        "mainnet" => Ok(CoreNetwork::Mainnet),
        "testnet" => Ok(CoreNetwork::Testnet),
        "regtest" => Ok(CoreNetwork::Regtest),
        _ => Err(schema_violation("NETWORK_NAME")),
    }
}

/// Parse and validate one page against the pinned wire contract. Any
/// violation is terminal — a page from an untrusted schema is never partially
/// consumed.
fn parse_full_scan(
    requested_from: u64,
    requested_to: u64,
    body: &str,
) -> Result<ParsedFullScan, WalletCoreError> {
    let wire: WireFullScan =
        serde_json::from_str(body).map_err(|_| schema_violation("JSON_DECODE"))?;
    if wire.schema_version != REMOTE_FULL_SCAN_SCHEMA_VERSION {
        return Err(schema_violation("SCHEMA_VERSION"));
    }

    let network = decode_network(&wire.identity.network)?;
    let identity = ChainIdentity {
        network,
        network_magic: wire.identity.network_magic,
        chain_id: decode_hash32(&wire.identity.chain_id, "CHAIN_ID_HEX")?,
        genesis_hash: decode_hash32(&wire.identity.genesis_hash, "GENESIS_HASH_HEX")?,
        protocol_version: wire.identity.protocol_version,
        range_proof_serialization_version: wire.identity.range_proof_serialization_version,
        coinbase_maturity: wire.identity.coinbase_maturity,
        current_tip: BlockRef {
            height: wire.tip.height,
            hash: decode_hash32(&wire.tip.hash, "TIP_HASH_HEX")?,
        },
    };

    if wire.from != requested_from {
        return Err(schema_violation("FROM_ECHO"));
    }
    // The server only ever clamps the range down, never widens it.
    if wire.to > requested_to {
        return Err(schema_violation("TO_ECHO"));
    }

    if wire.to >= wire.from {
        if wire.to > identity.current_tip.height {
            return Err(schema_violation("TO_BEYOND_TIP"));
        }
        let span = wire.to - wire.from + 1;
        if span > REMOTE_MAX_FULL_SCAN_RANGE {
            return Err(schema_violation("RANGE_TOO_WIDE"));
        }
        let pre_genesis_empty = wire.blocks.is_empty()
            && wire.from == 0
            && identity.current_tip.height == 0
            && identity.current_tip.hash == [0u8; 32];
        if !pre_genesis_empty && wire.blocks.len() as u64 != span {
            return Err(schema_violation("BLOCK_COUNT"));
        }
    } else if !wire.blocks.is_empty() {
        return Err(schema_violation("BLOCKS_OUTSIDE_RANGE"));
    }

    let mut blocks = Vec::with_capacity(wire.blocks.len());
    let mut previous_hash: Option<[u8; 32]> = None;
    for (index, block) in wire.blocks.into_iter().enumerate() {
        let expected_height = wire.from.saturating_add(index as u64);
        if block.height != expected_height {
            return Err(schema_violation("NONCONSECUTIVE_HEIGHT"));
        }
        let block_hash = decode_hash32(&block.block_hash, "BLOCK_HASH_HEX")?;
        let previous_block_hash = decode_hash32(&block.previous_block_hash, "PREVIOUS_HASH_HEX")?;
        let canonical_marker = decode_hash32(&block.canonical_marker, "CANONICAL_MARKER_HEX")?;
        if let Some(expected_previous) = previous_hash {
            if previous_block_hash != expected_previous {
                return Err(schema_violation("PREVIOUS_HASH_CHAIN"));
            }
        }
        previous_hash = Some(block_hash);

        let coinbase = CoinbaseScanMetadata {
            output_commitment: decode_commitment33(
                &block.coinbase.output_commitment,
                "COINBASE_COMMITMENT_HEX",
            )?,
            explicit_value: block.coinbase.explicit_value,
            kernel_excess: decode_commitment33(
                &block.coinbase.kernel_excess,
                "COINBASE_EXCESS_HEX",
            )?,
        };

        // With no filters the projection always leads with the coinbase
        // output at position 0 and contiguous positions afterwards.
        if block.outputs.is_empty() {
            return Err(schema_violation("COINBASE_PROJECTION"));
        }
        let mut outputs = Vec::with_capacity(block.outputs.len());
        for (position, output) in block.outputs.into_iter().enumerate() {
            if output.output_position != position as u32 {
                return Err(schema_violation("OUTPUT_POSITION"));
            }
            let commitment = decode_commitment33(&output.commitment, "OUTPUT_COMMITMENT_HEX")?;
            let is_first = position == 0;
            if output.is_coinbase != is_first
                || (is_first && commitment != coinbase.output_commitment)
            {
                return Err(schema_violation("COINBASE_PROJECTION"));
            }
            let range_proof = BASE64
                .decode(output.range_proof.as_bytes())
                .map_err(|_| schema_violation("RANGE_PROOF_BASE64"))?;
            let recovery_capsule = BASE64
                .decode(output.recovery_capsule.as_bytes())
                .map_err(|_| schema_violation("CAPSULE_BASE64"))?;
            if recovery_capsule.is_empty() != (output.recovery_version == 0) {
                return Err(schema_violation("CAPSULE_VERSION"));
            }
            outputs.push(ScanOutput {
                commitment,
                range_proof,
                recovery_capsule,
                recovery_version: output.recovery_version,
                is_coinbase: output.is_coinbase,
                // Deliberately omitted from the wire: reconstructed from the
                // enclosing block.
                block_height: block.height,
                block_hash,
                output_position: output.output_position,
            });
        }

        let mut inputs = Vec::with_capacity(block.inputs.len());
        for input in &block.inputs {
            inputs.push(ScanInput {
                spent_commitment: decode_commitment33(input, "INPUT_COMMITMENT_HEX")?,
            });
        }
        let mut kernels = Vec::with_capacity(block.kernels.len());
        for kernel in block.kernels {
            kernels.push(ScanKernel {
                excess: decode_commitment33(&kernel.excess, "KERNEL_EXCESS_HEX")?,
                features: kernel.features,
                fee: kernel.fee,
                lock_height: kernel.lock_height,
            });
        }

        blocks.push(ScanBlock {
            height: block.height,
            block_hash,
            previous_block_hash,
            timestamp: block.timestamp,
            canonical_marker,
            outputs,
            inputs,
            kernels,
            coinbase,
            total_fees_noms: block.total_fees_noms,
            protocol_version: block.protocol_version,
            range_proof_serialization_version: block.range_proof_serialization_version,
        });
    }

    Ok(ParsedFullScan { identity, blocks })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread::JoinHandle;

    const TOKEN: &str = "test-token";

    // ── Minimal local HTTP mock (std-only, same raw-socket spirit as the
    //    dom-wallet-updater test servers) ─────────────────────────────────

    struct ReceivedRequest {
        path: String,
        query: String,
        authorization: Option<String>,
    }

    #[derive(Clone)]
    struct CannedResponse {
        status: u16,
        content_type: &'static str,
        body: String,
    }

    impl CannedResponse {
        fn json(status: u16, body: Value) -> Self {
            Self {
                status,
                content_type: "application/json",
                body: body.to_string(),
            }
        }

        fn raw_json(status: u16, body: String) -> Self {
            Self {
                status,
                content_type: "application/json",
                body,
            }
        }

        fn text(status: u16, body: &str) -> Self {
            Self {
                status,
                content_type: "text/plain",
                body: body.to_string(),
            }
        }
    }

    struct MockServer {
        address: SocketAddr,
        hits: Arc<AtomicUsize>,
        shutdown: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
    }

    impl MockServer {
        fn start<F>(handler: F) -> Self
        where
            F: Fn(&ReceivedRequest) -> CannedResponse + Send + Sync + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
            let address = listener.local_addr().expect("mock server address");
            let hits = Arc::new(AtomicUsize::new(0));
            let shutdown = Arc::new(AtomicBool::new(false));
            let worker_hits = Arc::clone(&hits);
            let worker_shutdown = Arc::clone(&shutdown);
            let worker = std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if worker_shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(mut stream) = stream else { continue };
                    let Some(request) = read_request(&mut stream) else {
                        continue;
                    };
                    worker_hits.fetch_add(1, Ordering::SeqCst);
                    write_response(&mut stream, &handler(&request));
                }
            });
            Self {
                address,
                hits,
                shutdown,
                worker: Some(worker),
            }
        }

        fn base_url(&self) -> String {
            format!("http://{}", self.address)
        }

        fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }
    }

    impl Drop for MockServer {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect(self.address);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    fn read_request(stream: &mut TcpStream) -> Option<ReceivedRequest> {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];
        while !buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut chunk).ok()?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.len() > 64 * 1024 {
                break;
            }
        }
        let text = String::from_utf8_lossy(&buffer).into_owned();
        let mut lines = text.lines();
        let request_line = lines.next()?;
        let target = request_line.split_whitespace().nth(1)?;
        let (path, query) = match target.split_once('?') {
            Some((path, query)) => (path.to_string(), query.to_string()),
            None => (target.to_string(), String::new()),
        };
        let mut authorization = None;
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("authorization") {
                    authorization = Some(value.trim().to_string());
                }
            }
        }
        Some(ReceivedRequest {
            path,
            query,
            authorization,
        })
    }

    fn write_response(stream: &mut TcpStream, response: &CannedResponse) {
        let payload = format!(
            "HTTP/1.1 {} MOCK\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            response.status,
            response.content_type,
            response.body.len(),
            response.body
        );
        let _ = stream.write_all(payload.as_bytes());
        let _ = stream.flush();
    }

    // ── Wire fixtures ───────────────────────────────────────────────────

    fn h32(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn h33(byte: u8) -> String {
        hex::encode([byte; 33])
    }

    fn b64_of(bytes: &[u8]) -> String {
        BASE64.encode(bytes)
    }

    fn identity_json() -> Value {
        json!({
            "network": "regtest",
            "network_magic": CoreNetwork::Regtest.magic(),
            "chain_id": h32(0x11),
            "genesis_hash": h32(0x22),
            "protocol_version": 1,
            "range_proof_serialization_version": 1,
            "coinbase_maturity": 1440,
        })
    }

    fn block_json(height: u64, hash_byte: u8, previous: &str) -> Value {
        let coinbase_commitment = h33(0xA0 ^ hash_byte);
        json!({
            "height": height,
            "block_hash": h32(hash_byte),
            "previous_block_hash": previous,
            "timestamp": 1_753_660_800u64 + height,
            "canonical_marker": h32(hash_byte),
            "protocol_version": 1,
            "range_proof_serialization_version": 1,
            "total_fees_noms": 0,
            "coinbase": {
                "output_commitment": coinbase_commitment,
                "explicit_value": 5_000_000_000u64,
                "kernel_excess": h33(0xB0 ^ hash_byte),
            },
            "outputs": [{
                "commitment": coinbase_commitment,
                "range_proof": b64_of(&[7u8; 40]),
                "recovery_capsule": b64_of(&[9u8; 16]),
                "recovery_version": 1,
                "is_coinbase": true,
                "output_position": 0,
            }],
            "inputs": [h33(0xC0 ^ hash_byte)],
            "kernels": [{
                "excess": h33(0xB0 ^ hash_byte),
                "features": 0,
                "fee": 0,
                "lock_height": 0,
            }],
        })
    }

    fn full_scan_json(
        from: u64,
        to: u64,
        tip_height: u64,
        tip_hash_byte: u8,
        blocks: Vec<Value>,
    ) -> Value {
        json!({
            "schema_version": 1,
            "identity": identity_json(),
            "tip": { "height": tip_height, "hash": h32(tip_hash_byte) },
            "from": from,
            "to": to,
            "blocks": blocks,
        })
    }

    fn identity_probe_response(tip_height: u64, tip_hash_byte: u8) -> CannedResponse {
        CannedResponse::json(
            200,
            full_scan_json(1, 0, tip_height, tip_hash_byte, Vec::new()),
        )
    }

    fn source_for(server: &MockServer) -> RemoteNodeSource {
        RemoteNodeSource::new(&server.base_url(), Some(TOKEN)).expect("remote source")
    }

    fn scan_request(start_height: u64, max_blocks: u64) -> ScanRequest {
        ScanRequest {
            network: CoreNetwork::Regtest,
            chain_id: [0x11; 32],
            start: ScanStart::Height(start_height),
            max_blocks,
            stop_height: None,
            commitment_filters: Vec::new(),
        }
    }

    /// The in-memory projection an embedded node produces for the block that
    /// [`block_json`] describes on the wire. Built structurally by hand — NOT
    /// by parsing the same JSON — so the comparison actually proves the wire
    /// format lands on the embedded shape instead of comparing the parser to
    /// itself.
    fn embedded_projection(height: u64, hash_byte: u8, previous_byte: u8) -> ScanBlock {
        ScanBlock {
            height,
            block_hash: [hash_byte; 32],
            previous_block_hash: [previous_byte; 32],
            timestamp: 1_753_660_800 + height,
            canonical_marker: [hash_byte; 32],
            outputs: vec![ScanOutput {
                commitment: [0xA0 ^ hash_byte; 33],
                range_proof: vec![7u8; 40],
                recovery_capsule: vec![9u8; 16],
                recovery_version: 1,
                is_coinbase: true,
                block_height: height,
                block_hash: [hash_byte; 32],
                output_position: 0,
            }],
            inputs: vec![ScanInput {
                spent_commitment: [0xC0 ^ hash_byte; 33],
            }],
            kernels: vec![ScanKernel {
                excess: [0xB0 ^ hash_byte; 33],
                features: 0,
                fee: 0,
                lock_height: 0,
            }],
            coinbase: CoinbaseScanMetadata {
                output_commitment: [0xA0 ^ hash_byte; 33],
                explicit_value: 5_000_000_000,
                kernel_excess: [0xB0 ^ hash_byte; 33],
            },
            total_fees_noms: 0,
            protocol_version: 1,
            range_proof_serialization_version: 1,
        }
    }

    /// Acceptance (a): a remote scan must hand the scan loop EXACTLY what the
    /// embedded node hands it for the same chain. The loop, cursor rules and
    /// recovery all sit above this boundary, so identical projections here are
    /// what makes a remote restore reach the same balance as a local one.
    #[test]
    fn acceptance_a_remote_projection_is_identical_to_the_embedded_one() {
        let blocks = vec![
            block_json(1, 0x31, &h32(0x30)),
            block_json(2, 0x32, &h32(0x31)),
            block_json(3, 0x33, &h32(0x32)),
        ];
        let server = MockServer::start(move |request| {
            if request.path.starts_with("/chain/scan/full") {
                CannedResponse::json(200, full_scan_json(1, 3, 3, 0x33, blocks.clone()))
            } else {
                CannedResponse::json(404, json!({"error": "unexpected path"}))
            }
        });

        let result = source_for(&server)
            .scan_range(scan_request(1, 3))
            .expect("remote scan succeeds");

        let expected = vec![
            embedded_projection(1, 0x31, 0x30),
            embedded_projection(2, 0x32, 0x31),
            embedded_projection(3, 0x33, 0x32),
        ];
        assert_eq!(
            result.blocks, expected,
            "the remote projection diverged from the embedded one"
        );
        assert_eq!(result.tip.height, 3);
        assert_eq!(result.tip.hash, [0x33; 32]);
        // Caught up with the tip: nothing left to continue from.
        assert!(result.continuation.is_none());
    }

    /// Acceptance (c): when the remote node reorganizes under a live scan, the
    /// cursor must be reported invalid — that is the signal the shared
    /// reconciliation path needs to rewind and converge on the canonical chain.
    /// Silently accepting the stale cursor would strand the wallet on a dead
    /// fork with a balance that never corrects itself.
    #[test]
    fn acceptance_c_remote_reorg_invalidates_the_cursor_instead_of_diverging() {
        // The anchor the wallet committed at height 2.
        let anchor = BlockRef {
            height: 2,
            hash: [0x32; 32],
        };
        let cursor = WalletScanCursor::new(CoreNetwork::Regtest, [0x11; 32], 3, anchor);

        // Same height, different block: the chain reorganized under us.
        let reorged = MockServer::start(move |request| {
            if request.path.starts_with("/block/2") {
                CannedResponse::json(200, json!({"height": 2, "hash": h32(0xF2)}))
            } else if request.path.starts_with("/chain/scan/full") {
                CannedResponse::json(200, full_scan_json(1, 0, 9, 0xF9, Vec::new()))
            } else {
                CannedResponse::json(404, json!({"error": "unexpected path"}))
            }
        });

        let validation = source_for(&reorged).validate_cursor(cursor);
        assert!(
            matches!(&validation, Ok(check) if !check.valid) || validation.is_err(),
            "a reorged anchor must never validate: {validation:?}"
        );

        // The unchanged chain still validates, so the check is not simply
        // rejecting everything.
        let intact = MockServer::start(move |request| {
            if request.path.starts_with("/block/2") {
                CannedResponse::json(200, json!({"height": 2, "hash": h32(0x32)}))
            } else if request.path.starts_with("/chain/scan/full") {
                CannedResponse::json(200, full_scan_json(1, 0, 9, 0xF9, Vec::new()))
            } else {
                CannedResponse::json(404, json!({"error": "unexpected path"}))
            }
        });
        let validation = source_for(&intact)
            .validate_cursor(cursor)
            .expect("an intact anchor validates");
        assert!(validation.valid);
    }

    /// Acceptance (d): a busy remote node must never freeze the cursor. Every
    /// busy answer has to come back retriable so the scan loop backs off and
    /// tries again; classifying it as terminal is precisely the frozen-cursor
    /// regression.
    #[test]
    fn acceptance_d_busy_remote_is_retriable_and_the_scan_then_advances() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let server_attempts = Arc::clone(&attempts);
        let server = MockServer::start(move |request| {
            if !request.path.starts_with("/chain/scan/full") {
                return CannedResponse::json(404, json!({"error": "unexpected path"}));
            }
            // The first three attempts find a contended chain lock.
            if server_attempts.fetch_add(1, Ordering::SeqCst) < 3 {
                CannedResponse::json(503, json!({"error": "overloaded: chain busy; retry"}))
            } else {
                CannedResponse::json(
                    200,
                    full_scan_json(1, 1, 1, 0x31, vec![block_json(1, 0x31, &h32(0x30))]),
                )
            }
        });
        let source = source_for(&server);

        for attempt in 0..3 {
            let error = source
                .scan_range(scan_request(1, 1))
                .expect_err("a busy chain must fail this attempt");
            assert!(
                matches!(error, WalletCoreError::NodeNotReady(_)),
                "attempt {attempt} must stay retriable, got {error:?}"
            );
        }

        // Once the lock frees the very same cursor advances — no reset, no
        // manual intervention, no terminal state in between.
        let result = source
            .scan_range(scan_request(1, 1))
            .expect("the scan proceeds once the remote is free");
        assert_eq!(result.blocks.len(), 1);
        assert_eq!(result.blocks[0].height, 1);
        assert_eq!(attempts.load(Ordering::SeqCst), 4);
    }

    fn scan_error_of(response: CannedResponse) -> WalletCoreError {
        let server = MockServer::start(move |_| response.clone());
        let source = source_for(&server);
        source
            .scan_range(scan_request(1, 2))
            .expect_err("scan must fail")
    }

    // ── Tests ───────────────────────────────────────────────────────────

    #[test]
    fn full_scan_page_maps_to_scan_result_and_reconstructs_output_context() {
        let body = full_scan_json(
            1,
            2,
            2,
            0x52,
            vec![
                block_json(1, 0x51, &h32(0x50)),
                block_json(2, 0x52, &h32(0x51)),
            ],
        );
        let server = MockServer::start(move |request| {
            assert_eq!(request.path, "/chain/scan/full");
            assert_eq!(request.query, "from=1&to=2");
            assert_eq!(
                request.authorization.as_deref(),
                Some("Bearer test-token"),
                "scan endpoint must be called with the bearer token"
            );
            CannedResponse::json(200, body.clone())
        });
        let source = source_for(&server);
        let result = source.scan_range(scan_request(1, 2)).expect("scan page");

        assert_eq!(
            result.tip,
            BlockRef {
                height: 2,
                hash: [0x52; 32]
            }
        );
        assert_eq!(result.blocks.len(), 2);
        let first = &result.blocks[0];
        assert_eq!(first.height, 1);
        assert_eq!(first.block_hash, [0x51; 32]);
        assert_eq!(first.previous_block_hash, [0x50; 32]);
        assert_eq!(first.canonical_marker, [0x51; 32]);
        assert_eq!(first.outputs.len(), 1);
        let output = &first.outputs[0];
        // Reconstructed from the enclosing block (omitted from the wire).
        assert_eq!(output.block_height, 1);
        assert_eq!(output.block_hash, [0x51; 32]);
        assert!(output.is_coinbase);
        assert_eq!(output.range_proof, vec![7u8; 40]);
        assert_eq!(output.recovery_capsule, vec![9u8; 16]);
        assert_eq!(output.recovery_version, 1);
        assert_eq!(output.output_position, 0);
        assert_eq!(first.inputs.len(), 1);
        assert_eq!(first.kernels.len(), 1);
        assert_eq!(first.coinbase.explicit_value, 5_000_000_000);
        // Page ends at the tip: no continuation.
        assert!(result.continuation.is_none());
        assert_eq!(
            source.last_observed_tip(),
            Some(BlockRef {
                height: 2,
                hash: [0x52; 32]
            })
        );
        assert!(source.tip_regression().is_none());
    }

    #[test]
    fn server_clamp_is_respected_and_yields_continuation_cursor() {
        // The wallet asks for up to 1000 blocks; the server clamps the page
        // to 2 blocks (budget/tip clamp) and echoes the effective `to`.
        let body = full_scan_json(
            1,
            2,
            5,
            0x55,
            vec![
                block_json(1, 0x51, &h32(0x50)),
                block_json(2, 0x52, &h32(0x51)),
            ],
        );
        let server = MockServer::start(move |request| {
            assert_eq!(request.query, "from=1&to=1000");
            CannedResponse::json(200, body.clone())
        });
        let source = source_for(&server);
        let result = source.scan_range(scan_request(1, 1000)).expect("scan page");
        assert_eq!(result.blocks.len(), 2);
        let continuation = result.continuation.expect("continuation cursor");
        assert_eq!(continuation.next_height, 3);
        assert_eq!(continuation.anchor_height, 2);
        assert_eq!(continuation.anchor_hash, [0x52; 32]);
        assert_eq!(continuation.chain_id, [0x11; 32]);
        assert_eq!(continuation.network_magic, CoreNetwork::Regtest.magic());
    }

    #[test]
    fn busy_503_maps_to_retriable_node_not_ready() {
        let error = scan_error_of(CannedResponse::json(
            503,
            json!({"error": "overloaded: chain busy; retry"}),
        ));
        assert!(
            matches!(error, WalletCoreError::NodeNotReady(_)),
            "busy must stay retriable, got {error:?}"
        );
    }

    #[test]
    fn rate_limited_429_text_body_maps_to_retriable_temporary_failure() {
        // 429 arrives as plain text, not JSON (tower_governor behaviour).
        let error = scan_error_of(CannedResponse::text(429, "Too Many Requests! Wait for 1s"));
        assert!(matches!(error, WalletCoreError::TemporaryFailure(_)));
    }

    #[test]
    fn unauthorized_401_maps_to_terminal_internal_failure() {
        let error = scan_error_of(CannedResponse::text(401, ""));
        match error {
            WalletCoreError::InternalFailure(message) => {
                assert!(message.contains("unauthorized"), "message: {message}");
            }
            other => panic!("401 must be terminal InternalFailure, got {other:?}"),
        }
    }

    #[test]
    fn missing_endpoint_404_maps_to_terminal_upgrade_error() {
        let error = scan_error_of(CannedResponse::text(404, "not found"));
        match error {
            WalletCoreError::InternalFailure(message) => {
                assert!(message.contains("/chain/scan/full"), "message: {message}");
            }
            other => panic!("404 must be terminal InternalFailure, got {other:?}"),
        }
    }

    #[test]
    fn canonical_gap_code_maps_to_canonical_gap_and_plain_500_stays_retriable() {
        let gap = scan_error_of(CannedResponse::json(
            500,
            json!({"error": "canonical gap: missing canonical block at height 7",
                   "code": "canonical_gap"}),
        ));
        assert!(matches!(gap, WalletCoreError::CanonicalGap(_)));

        let plain = scan_error_of(CannedResponse::json(
            500,
            json!({"error": "internal: transient store hiccup"}),
        ));
        assert!(
            matches!(plain, WalletCoreError::TemporaryFailure(_)),
            "uncoded 500 must stay retriable, got {plain:?}"
        );
    }

    #[test]
    fn connection_failure_maps_to_retriable_temporary_failure() {
        // Reserved port with no listener: connection refused.
        let source =
            RemoteNodeSource::new("http://127.0.0.1:1", Some(TOKEN)).expect("remote source");
        let error = source
            .scan_range(scan_request(1, 2))
            .expect_err("connection must fail");
        assert!(matches!(error, WalletCoreError::TemporaryFailure(_)));
    }

    #[test]
    fn commitment_filters_are_rejected_locally_without_any_network_traffic() {
        let server = MockServer::start(|_| CannedResponse::text(500, "must never be reached"));
        let source = source_for(&server);
        let mut request = scan_request(1, 2);
        request.commitment_filters = vec![[0xAB; 33]];
        let error = source
            .scan_range(request)
            .expect_err("filters must be rejected");
        assert!(matches!(error, WalletCoreError::InvalidScanRequest(_)));
        assert_eq!(server.hits(), 0, "privacy: no request may leave the wallet");
    }

    #[test]
    fn schema_divergence_is_terminal_and_never_partially_consumed() {
        let valid_blocks = || {
            vec![
                block_json(1, 0x51, &h32(0x50)),
                block_json(2, 0x52, &h32(0x51)),
            ]
        };

        let mut unknown_version = full_scan_json(1, 2, 2, 0x52, valid_blocks());
        unknown_version["schema_version"] = json!(2);

        let mut nonconsecutive = full_scan_json(1, 2, 2, 0x52, valid_blocks());
        nonconsecutive["blocks"][1]["height"] = json!(3);

        let missing_block = full_scan_json(1, 2, 2, 0x52, vec![block_json(1, 0x51, &h32(0x50))]);

        let mut bad_hex = full_scan_json(1, 2, 2, 0x52, valid_blocks());
        bad_hex["blocks"][0]["block_hash"] = json!("zz");

        let mut broken_chain = full_scan_json(1, 2, 2, 0x52, valid_blocks());
        broken_chain["blocks"][1]["previous_block_hash"] = json!(h32(0x99));

        let mut capsule_mismatch = full_scan_json(1, 2, 2, 0x52, valid_blocks());
        capsule_mismatch["blocks"][0]["outputs"][0]["recovery_version"] = json!(0);

        let mut beyond_tip = full_scan_json(1, 2, 1, 0x51, valid_blocks());
        beyond_tip["tip"]["height"] = json!(1);

        for (case, body) in [
            ("unknown schema_version", unknown_version),
            ("nonconsecutive heights", nonconsecutive),
            ("missing block in range", missing_block),
            ("invalid hex", bad_hex),
            ("broken previous-hash chain", broken_chain),
            ("capsule/version mismatch", capsule_mismatch),
            ("to beyond tip", beyond_tip),
            ("json garbage", json!("not an object")),
        ] {
            let error = scan_error_of(CannedResponse::raw_json(200, body.to_string()));
            match error {
                WalletCoreError::InternalFailure(message) => {
                    assert!(
                        message.contains("remote schema violation"),
                        "case {case}: message {message}"
                    );
                }
                other => panic!("case {case}: expected terminal InternalFailure, got {other:?}"),
            }
        }
    }

    #[test]
    fn tip_regression_is_recorded_for_the_consumer_without_aborting_the_scan() {
        let calls = Arc::new(AtomicUsize::new(0));
        let handler_calls = Arc::clone(&calls);
        let server = MockServer::start(move |_| {
            let call = handler_calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                CannedResponse::json(
                    200,
                    full_scan_json(1, 1, 10, 0x5A, vec![block_json(1, 0x51, &h32(0x50))]),
                )
            } else {
                CannedResponse::json(
                    200,
                    full_scan_json(2, 2, 8, 0x58, vec![block_json(2, 0x52, &h32(0x51))]),
                )
            }
        });
        let source = source_for(&server);
        source.scan_range(scan_request(1, 1)).expect("first page");
        assert!(source.tip_regression().is_none());
        source.scan_range(scan_request(2, 1)).expect("second page");
        let regression = source.tip_regression().expect("regression recorded");
        assert_eq!(regression.previous.height, 10);
        assert_eq!(regression.previous.hash, [0x5A; 32]);
        assert_eq!(regression.observed.height, 8);
        assert_eq!(regression.observed.hash, [0x58; 32]);
        // High-water mark keeps the honest maximum.
        assert_eq!(source.last_observed_tip().map(|tip| tip.height), Some(10));
    }

    #[test]
    fn remote_identity_drift_within_session_is_terminal_chain_mismatch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let handler_calls = Arc::clone(&calls);
        let server = MockServer::start(move |_| {
            let call = handler_calls.fetch_add(1, Ordering::SeqCst);
            let mut body = full_scan_json(1, 1, 5, 0x55, vec![block_json(1, 0x51, &h32(0x50))]);
            if call > 0 {
                // Same network/chain_id (passes the request check) but a
                // different genesis: a node silently swapping chains.
                body["identity"]["genesis_hash"] = json!(h32(0x23));
            }
            CannedResponse::json(200, body)
        });
        let source = source_for(&server);
        source.scan_range(scan_request(1, 1)).expect("first page");
        let error = source
            .scan_range(scan_request(1, 1))
            .expect_err("identity drift must fail");
        assert!(matches!(error, WalletCoreError::CursorChainMismatch(_)));
    }

    #[test]
    fn chain_identity_probes_with_an_empty_page_and_pins_the_session() {
        let server = MockServer::start(|request| {
            assert_eq!(request.path, "/chain/scan/full");
            assert_eq!(request.query, "from=1&to=0");
            identity_probe_response(9, 0x59)
        });
        let source = source_for(&server);
        let identity = source.chain_identity().expect("identity probe");
        assert_eq!(identity.network, CoreNetwork::Regtest);
        assert_eq!(identity.network_magic, CoreNetwork::Regtest.magic());
        assert_eq!(identity.chain_id, [0x11; 32]);
        assert_eq!(identity.genesis_hash, [0x22; 32]);
        assert_eq!(identity.coinbase_maturity, 1440);
        assert_eq!(
            identity.current_tip,
            BlockRef {
                height: 9,
                hash: [0x59; 32]
            }
        );
        assert_eq!(source.last_observed_tip().map(|tip| tip.height), Some(9));
    }

    #[test]
    fn canonical_hash_at_height_maps_found_and_missing_headers() {
        let server = MockServer::start(|request| {
            assert!(
                request.authorization.is_none(),
                "/block is public; the bearer token must not be sent"
            );
            match request.path.as_str() {
                "/block/5" => CannedResponse::json(
                    200,
                    json!({
                        "height": 5,
                        "hash": h32(0x77),
                        "prev_hash": h32(0x76),
                        "timestamp": 1_753_651_200u64,
                        "target": "00ff",
                    }),
                ),
                "/block/6" => CannedResponse::json(404, json!({"found": false})),
                other => panic!("unexpected path {other}"),
            }
        });
        let source = source_for(&server);
        assert_eq!(
            source.canonical_hash_at_height(5).expect("found header"),
            Some([0x77; 32])
        );
        assert_eq!(
            source.canonical_hash_at_height(6).expect("missing header"),
            None
        );
    }

    #[test]
    fn validate_cursor_detects_reorg_through_the_public_header_endpoint() {
        let cursor = WalletScanCursor::new(
            CoreNetwork::Regtest,
            [0x11; 32],
            8,
            BlockRef {
                height: 7,
                hash: [0x66; 32],
            },
        );

        let matching = MockServer::start(|request| match request.path.as_str() {
            "/chain/scan/full" => identity_probe_response(9, 0x59),
            "/block/7" => CannedResponse::json(
                200,
                json!({"height": 7, "hash": h32(0x66), "prev_hash": h32(0x65),
                       "timestamp": 1u64, "target": "00ff"}),
            ),
            other => panic!("unexpected path {other}"),
        });
        let source = source_for(&matching);
        let validation = source.validate_cursor(cursor).expect("valid cursor");
        assert!(validation.valid);
        assert_eq!(validation.safe_rescan_anchor.height, 7);
        assert_eq!(validation.safe_rescan_anchor.hash, [0x66; 32]);
        drop(matching);

        let reorged = MockServer::start(|request| match request.path.as_str() {
            "/chain/scan/full" => identity_probe_response(9, 0x59),
            "/block/7" => CannedResponse::json(
                200,
                json!({"height": 7, "hash": h32(0x67), "prev_hash": h32(0x65),
                       "timestamp": 1u64, "target": "00ff"}),
            ),
            other => panic!("unexpected path {other}"),
        });
        let source = source_for(&reorged);
        let error = source
            .validate_cursor(cursor)
            .expect_err("reorged anchor must fail");
        assert!(matches!(error, WalletCoreError::CursorReorg(_)));
    }

    #[test]
    fn scan_next_validates_the_anchor_and_pages_from_the_cursor() {
        let cursor = WalletScanCursor::new(
            CoreNetwork::Regtest,
            [0x11; 32],
            8,
            BlockRef {
                height: 7,
                hash: [0x66; 32],
            },
        );
        let server = MockServer::start(|request| {
            match (request.path.as_str(), request.query.as_str()) {
                // scan_next trait default: identity probe first.
                ("/chain/scan/full", "from=1&to=0") => identity_probe_response(9, 0x69),
                ("/block/7", _) => CannedResponse::json(
                    200,
                    json!({"height": 7, "hash": h32(0x66), "prev_hash": h32(0x65),
                           "timestamp": 1u64, "target": "00ff"}),
                ),
                ("/chain/scan/full", "from=8&to=9") => CannedResponse::json(
                    200,
                    full_scan_json(
                        8,
                        9,
                        9,
                        0x69,
                        vec![
                            block_json(8, 0x68, &h32(0x66)),
                            block_json(9, 0x69, &h32(0x68)),
                        ],
                    ),
                ),
                (path, query) => panic!("unexpected request {path}?{query}"),
            }
        });
        let source = source_for(&server);
        let result = source.scan_next(cursor, 2).expect("cursor page");
        assert_eq!(
            result
                .blocks
                .iter()
                .map(|block| block.height)
                .collect::<Vec<_>>(),
            vec![8, 9]
        );
        assert!(result.continuation.is_none(), "page reached the tip");
    }

    #[test]
    fn operations_outside_the_scan_surface_are_terminal_embedded_only_errors() {
        // No server needed: these must fail without any network traffic.
        let source =
            RemoteNodeSource::new("http://127.0.0.1:1", Some(TOKEN)).expect("remote source");
        let errors = [
            source.get_utxo(&[0xAB; 33]).map(|_| ()).unwrap_err(),
            source.get_kernel(&[0xAB; 33]).map(|_| ()).unwrap_err(),
            source
                .get_block_summary(BlockSelector::Height(1))
                .map(|_| ())
                .unwrap_err(),
            source
                .transaction_status(TransactionIdentifier::TxHash([0; 32]))
                .map(|_| ())
                .unwrap_err(),
            source
                .rebroadcast_transaction(TransactionIdentifier::TxHash([0; 32]))
                .map(|_| ())
                .unwrap_err(),
            source
                .query_submission(TransactionIdentifier::TxHash([0; 32]))
                .map(|_| ())
                .unwrap_err(),
            source.mempool_policy_snapshot().map(|_| ()).unwrap_err(),
            source.fee_policy_snapshot().map(|_| ()).unwrap_err(),
            source.fee_policy().map(|_| ()).unwrap_err(),
            source
                .transaction_weight(TransactionShape {
                    input_count: 1,
                    output_count: 1,
                    kernel_count: 1,
                })
                .map(|_| ())
                .unwrap_err(),
        ];
        for error in errors {
            match error {
                WalletCoreError::InternalFailure(message) => {
                    assert!(
                        message.contains("requires the embedded node"),
                        "message: {message}"
                    );
                }
                other => panic!("expected terminal InternalFailure, got {other:?}"),
            }
        }
    }

    #[test]
    fn debug_output_redacts_the_bearer_token() {
        let source =
            RemoteNodeSource::new("http://127.0.0.1:1", Some("super-secret")).expect("source");
        let debug = format!("{source:?}");
        assert!(!debug.contains("super-secret"), "debug: {debug}");
        assert!(debug.contains("<redacted>"), "debug: {debug}");
    }

    #[test]
    fn constructor_rejects_bad_configuration() {
        assert!(matches!(
            RemoteNodeSource::new("not a url", None),
            Err(RemoteSourceConfigError::InvalidBaseUrl(_))
        ));
        assert!(matches!(
            RemoteNodeSource::new("ftp://example.com", None),
            Err(RemoteSourceConfigError::UnsupportedScheme)
        ));
        assert!(matches!(
            RemoteNodeSource::new("http://127.0.0.1:1", Some("  \n")),
            Err(RemoteSourceConfigError::EmptyBearerToken)
        ));
        // The node writes the token file with a trailing newline; trim it.
        let source = RemoteNodeSource::new("http://127.0.0.1:1/", Some("token-value\n"))
            .expect("trimmed token");
        assert_eq!(
            source.bearer_token.as_ref().map(|token| token.0.as_str()),
            Some("token-value")
        );
        assert_eq!(source.base_url, "http://127.0.0.1:1");
    }

    #[test]
    fn scan_past_the_tip_returns_an_empty_page_without_continuation() {
        let server = MockServer::start(|request| {
            // from beyond the tip: server clamps to an empty page (to < from).
            assert_eq!(request.query, "from=10&to=11");
            CannedResponse::json(200, full_scan_json(10, 5, 5, 0x55, Vec::new()))
        });
        let source = source_for(&server);
        let result = source.scan_range(scan_request(10, 2)).expect("empty page");
        assert!(result.blocks.is_empty());
        assert!(result.continuation.is_none());
        assert_eq!(result.tip.height, 5);
    }
}
