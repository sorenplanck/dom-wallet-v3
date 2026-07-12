//! Opt-in configuration gate for the headless live node lifecycle runner.
//!
//! This module deliberately contains no transaction construction or network
//! submission.  The binary invokes the ordinary `WalletService` APIs only
//! after this gate has accepted the exact operator acknowledgement.

use dom_wallet_domain::{Network, NetworkIdentity, NodeConfiguration};
use std::env;
use std::fs;
use std::path::PathBuf;

pub const ENABLE_TOKEN: &str = "I_UNDERSTAND_THIS_SUBMITS_A_LIVE_DOM_TRANSACTION";
pub const REQUIRED_VARIABLES: [&str; 9] = [
    "DOM_LIVE_E2E_RPC_URL",
    "DOM_LIVE_E2E_NETWORK",
    "DOM_LIVE_E2E_CHAIN_ID",
    "DOM_LIVE_E2E_GENESIS_HASH",
    "DOM_LIVE_E2E_WALLET_A_DIR",
    "DOM_LIVE_E2E_WALLET_A_PASSWORD_FILE",
    "DOM_LIVE_E2E_WALLET_B_DIR",
    "DOM_LIVE_E2E_WALLET_B_PASSWORD_FILE",
    "DOM_LIVE_E2E_AMOUNT_NOMS",
];

pub struct LiveE2eConfig {
    pub rpc_url: String,
    pub identity: NetworkIdentity,
    pub wallet_a_dir: PathBuf,
    pub wallet_a_password_file: PathBuf,
    pub wallet_b_dir: PathBuf,
    pub wallet_b_password_file: PathBuf,
    pub amount: u64,
    pub mutation_enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LiveE2eConfigError {
    Missing(Vec<&'static str>),
    Invalid,
    UnsafeSecretFile,
}

pub fn load_from_environment() -> Result<LiveE2eConfig, LiveE2eConfigError> {
    let missing = REQUIRED_VARIABLES
        .iter()
        .copied()
        .filter(|name| env::var_os(name).is_none())
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(LiveE2eConfigError::Missing(missing));
    }
    let rpc_url = required("DOM_LIVE_E2E_RPC_URL")?;
    // URL credentials must never be accepted because they can leak through
    // diagnostics produced by third-party HTTP stacks.
    if !(rpc_url.starts_with("https://") || rpc_url.starts_with("http://"))
        || rpc_url
            .split_once("://")
            .is_some_and(|(_, authority)| authority.contains('@'))
    {
        return Err(LiveE2eConfigError::Invalid);
    }
    let network = match required("DOM_LIVE_E2E_NETWORK")?.as_str() {
        "PRIVATE_TESTNET" => Network::PrivateTestnet,
        "PUBLIC_TESTNET" => Network::PublicTestnet,
        "MAINNET" => Network::Mainnet,
        _ => return Err(LiveE2eConfigError::Invalid),
    };
    let identity = NetworkIdentity {
        network,
        chain_id: parse_fixed_hash(&required("DOM_LIVE_E2E_CHAIN_ID")?)?,
        genesis_id: parse_fixed_hash(&required("DOM_LIVE_E2E_GENESIS_HASH")?)?,
    };
    let amount = required("DOM_LIVE_E2E_AMOUNT_NOMS")?
        .parse::<u64>()
        .ok()
        .filter(|amount| *amount > 0)
        .ok_or(LiveE2eConfigError::Invalid)?;
    Ok(LiveE2eConfig {
        rpc_url,
        identity,
        wallet_a_dir: PathBuf::from(required("DOM_LIVE_E2E_WALLET_A_DIR")?),
        wallet_a_password_file: PathBuf::from(required("DOM_LIVE_E2E_WALLET_A_PASSWORD_FILE")?),
        wallet_b_dir: PathBuf::from(required("DOM_LIVE_E2E_WALLET_B_DIR")?),
        wallet_b_password_file: PathBuf::from(required("DOM_LIVE_E2E_WALLET_B_PASSWORD_FILE")?),
        amount,
        mutation_enabled: env::var("DOM_LIVE_E2E_ENABLE").ok().as_deref() == Some(ENABLE_TOKEN),
    })
}

impl LiveE2eConfig {
    pub fn node_configuration(&self) -> NodeConfiguration {
        NodeConfiguration {
            endpoint_url: self.rpc_url.clone(),
            expected_identity: self.identity.clone(),
            source_identity: "dom-live-node".into(),
            api_compatibility_version: 1,
            connect_timeout_ms: 5_000,
            request_timeout_ms: 15_000,
            poll_interval_ms: 1_000,
            retry_ceiling: 3,
            max_backoff_ms: 30_000,
            stable_success_threshold: 2,
            tls_required: self.rpc_url.starts_with("https://"),
            credential_reference: None,
        }
    }

    pub fn validate_secret_files(&self) -> Result<(), LiveE2eConfigError> {
        validate_secret_file(&self.wallet_a_password_file)?;
        validate_secret_file(&self.wallet_b_password_file)
    }
}

fn required(name: &'static str) -> Result<String, LiveE2eConfigError> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or(LiveE2eConfigError::Invalid)
}

fn parse_fixed_hash(value: &str) -> Result<[u8; 32], LiveE2eConfigError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(LiveE2eConfigError::Invalid);
    }
    let bytes = hex::decode(value).map_err(|_| LiveE2eConfigError::Invalid)?;
    let hash: [u8; 32] = bytes.try_into().map_err(|_| LiveE2eConfigError::Invalid)?;
    if hash == [0; 32] {
        return Err(LiveE2eConfigError::Invalid);
    }
    Ok(hash)
}

fn validate_secret_file(path: &PathBuf) -> Result<(), LiveE2eConfigError> {
    let metadata = fs::metadata(path).map_err(|_| LiveE2eConfigError::UnsafeSecretFile)?;
    if !metadata.is_file() {
        return Err(LiveE2eConfigError::UnsafeSecretFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(LiveE2eConfigError::UnsafeSecretFile);
        }
    }
    Ok(())
}
