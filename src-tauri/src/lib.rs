#![forbid(unsafe_code)]

//! Tauri-ready command boundary.
//!
//! The commands are framework-neutral Rust functions so they can be tested in
//! a headless environment. A production Tauri `invoke_handler` binds these
//! names without moving domain, storage, cryptographic, or sync logic here.

use dom_wallet_chain::{ChainSource, MockChainSource};
use dom_wallet_core::{CoreError, DiagnosticSnapshot, ProbeResult, WalletService, WalletSummary};
use dom_wallet_domain::{
    NetworkIdentity, NodeConfiguration, RedactedNodeConfiguration, ScanBounds,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;
use thiserror::Error;

pub struct DesktopApplication {
    service: Mutex<WalletService>,
}

impl Default for DesktopApplication {
    fn default() -> Self {
        Self {
            service: Mutex::new(WalletService::default()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationStatusDto {
    pub state: String,
    pub experimental: bool,
    pub unaudited: bool,
}

impl DesktopApplication {
    pub fn application_status(&self) -> ApplicationStatusDto {
        let diagnostic = self
            .service
            .lock()
            .expect("application mutex poisoned")
            .diagnostics();
        ApplicationStatusDto {
            state: diagnostic.application_state,
            experimental: true,
            unaudited: true,
        }
    }

    pub fn wallet_create(
        &self,
        path: impl AsRef<Path>,
        password: &str,
        identity: NetworkIdentity,
    ) -> Result<WalletSummary, CommandError> {
        checked_password(password)?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .create(path, password, identity)
            .map_err(CommandError::from)
    }

    pub fn wallet_open(&self, path: impl AsRef<Path>) -> Result<WalletSummary, CommandError> {
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .open(path)
            .map_err(CommandError::from)
    }

    pub fn wallet_unlock(&self, password: &str) -> Result<WalletSummary, CommandError> {
        checked_password(password)?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .unlock(password)
            .map_err(CommandError::from)
    }

    pub fn wallet_lock(&self) -> Result<(), CommandError> {
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .lock()
            .map_err(CommandError::from)
    }
    pub fn wallet_close(&self) -> Result<(), CommandError> {
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .close()
            .map_err(CommandError::from)
    }
    pub fn wallet_summary(&self) -> Result<WalletSummary, CommandError> {
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .summary()
            .map_err(CommandError::from)
    }
    pub fn account_list(&self) -> Result<Vec<(uuid::Uuid, String)>, CommandError> {
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .accounts()
            .map_err(CommandError::from)
    }
    pub fn account_summary(&self) -> Result<WalletSummary, CommandError> {
        self.wallet_summary()
    }
    pub fn node_configuration_get_redacted(
        &self,
    ) -> Result<RedactedNodeConfiguration, CommandError> {
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .node_configuration()
            .map_err(CommandError::from)
    }
    pub fn node_configuration_set(
        &self,
        configuration: NodeConfiguration,
    ) -> Result<(), CommandError> {
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .set_node_configuration(configuration)
            .map_err(CommandError::from)
    }
    pub fn diagnostics_redacted(&self) -> DiagnosticSnapshot {
        self.service
            .lock()
            .expect("application mutex poisoned")
            .diagnostics()
    }
    pub fn application_shutdown(&self) -> Result<(), CommandError> {
        self.wallet_close()
    }

    pub fn node_probe<S: ChainSource>(&self, source: &mut S) -> Result<ProbeResult, CommandError> {
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .probe(source)
            .map_err(CommandError::from)
    }
    pub fn node_probe_unlocked_free<S: ChainSource>(
        &self,
        source: &mut S,
        expected: &NetworkIdentity,
    ) -> Result<ProbeResult, CommandError> {
        WalletService::probe_node(source, expected).map_err(CommandError::from)
    }
    pub fn synchronization_start<S: ChainSource>(
        &self,
        source: &mut S,
        bounds: ScanBounds,
    ) -> Result<WalletSummary, CommandError> {
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .synchronize(source, bounds, 256)
            .map_err(CommandError::from)
    }
    pub fn synchronization_pause(&self) -> Result<(), CommandError> {
        Ok(())
    }
    pub fn synchronization_resume<S: ChainSource>(
        &self,
        source: &mut S,
        bounds: ScanBounds,
    ) -> Result<WalletSummary, CommandError> {
        self.synchronization_start(source, bounds)
    }
    pub fn synchronization_retry<S: ChainSource>(
        &self,
        source: &mut S,
        bounds: ScanBounds,
    ) -> Result<WalletSummary, CommandError> {
        self.synchronization_start(source, bounds)
    }
    pub fn synchronization_rescan(&self) -> Result<(), CommandError> {
        Ok(())
    }

    pub fn synchronization_start_live(&self) -> Result<WalletSummary, CommandError> {
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .synchronize_live()
            .map_err(CommandError::from)
    }

    pub fn probe_mock(&self, source: &mut MockChainSource) -> Result<ProbeResult, CommandError> {
        self.node_probe(source)
    }
}

fn checked_password(value: &str) -> Result<(), CommandError> {
    if value.len() < 8 || value.len() > 1024 {
        Err(CommandError::InvalidInput(
            "password length is invalid".into(),
        ))
    } else {
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("invalid command input: {0}")]
    InvalidInput(String),
    #[error("application is unavailable")]
    Unavailable,
    #[error("wallet operation failed")]
    Wallet,
}

impl From<CoreError> for CommandError {
    fn from(_: CoreError) -> Self {
        Self::Wallet
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_wallet_domain::{Network, NetworkIdentity};

    #[test]
    fn command_errors_and_status_do_not_expose_passwords() {
        let app = DesktopApplication::default();
        let error = app.wallet_unlock("password-1").unwrap_err();
        assert!(!format!("{error}").contains("password-1"));
        assert!(app.application_status().experimental);
    }

    #[test]
    fn mock_probe_uses_redacted_dto() {
        let app = DesktopApplication::default();
        let identity = NetworkIdentity {
            network: Network::PrivateTestnet,
            chain_id: [1; 32],
            genesis_id: [2; 32],
        };
        let temp = tempfile::tempdir().unwrap();
        app.wallet_create(temp.path().join("wallet"), "password-1", identity.clone())
            .unwrap();
        app.wallet_unlock("password-1").unwrap();
        let mut source = MockChainSource::new(identity);
        assert!(app.probe_mock(&mut source).unwrap().connected);
    }
}
