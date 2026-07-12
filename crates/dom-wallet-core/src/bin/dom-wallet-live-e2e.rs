#![forbid(unsafe_code)]

//! Headless two-phase live lifecycle runner.  `PREFLIGHT` performs only node
//! reads and ordinary wallet open/unlock/configuration/synchronization.  It
//! cannot create a transaction. `EXECUTE` repeats that preflight and requires
//! the exact acknowledgement token before calling the transaction engine.

use dom_wallet_core::live_e2e::{
    load_from_environment, LiveE2eConfig, LiveE2eConfigError, LiveE2eMode,
};
use dom_wallet_core::{FundingPreflight, WalletService};
use std::env;
use std::fs;
use std::thread;
use std::time::{Duration, Instant};

struct ReadyWallets {
    sender: WalletService,
    recipient: WalletService,
    password_a: String,
    password_b: String,
}

#[derive(Default)]
struct PreflightResult {
    node_probe: bool,
    node_identity: bool,
    node_capabilities: bool,
    wallet_a_opened: bool,
    wallet_a_synchronized: bool,
    wallet_a_funding: Option<FundingPreflight>,
    wallet_b_opened: bool,
    wallet_b_synchronized: bool,
    block_producer_observed: bool,
    ready: Option<ReadyWallets>,
}

impl PreflightResult {
    fn passed(&self) -> bool {
        self.node_probe
            && self.node_identity
            && self.node_capabilities
            && self.wallet_a_opened
            && self.wallet_a_synchronized
            && self
                .wallet_a_funding
                .as_ref()
                .is_some_and(|funding| funding.fundable)
            && self.wallet_b_opened
            && self.wallet_b_synchronized
            && self.block_producer_observed
    }
}

fn main() {
    let config = match load_from_environment() {
        Ok(config) => config,
        Err(LiveE2eConfigError::Missing(names)) => {
            println!("PREFLIGHT_VERDICT=BLOCKED_MISSING_ENV");
            for name in names {
                println!("MISSING={name}");
            }
            return;
        }
        Err(LiveE2eConfigError::InvalidMode) => {
            println!("PREFLIGHT_VERDICT=BLOCKED_INVALID_MODE");
            return;
        }
        Err(_) => {
            println!("PREFLIGHT_VERDICT=BLOCKED_INVALID_CONFIGURATION");
            return;
        }
    };
    let mut preflight = run_preflight(&config);
    print_preflight(&preflight);
    if config.mode == LiveE2eMode::Preflight {
        return;
    }
    if !config.execute_authorized() {
        println!("EXECUTE_VERDICT=BLOCKED_ENABLE_TOKEN");
        return;
    }
    if !preflight.passed() {
        if preflight
            .wallet_a_funding
            .as_ref()
            .is_some_and(|funding| !funding.fundable)
        {
            println!("EXECUTE_VERDICT=WALLET_A_FUNDING_REQUIRED");
        } else if !preflight.block_producer_observed
            && preflight.wallet_a_synchronized
            && preflight.wallet_b_synchronized
        {
            println!("EXECUTE_VERDICT=BLOCK_PRODUCER_REQUIRED");
        } else {
            println!("EXECUTE_VERDICT=BLOCKED_PREFLIGHT");
        }
        return;
    }
    let Some(ready) = preflight.ready.take() else {
        println!("EXECUTE_VERDICT=BLOCKED_PREFLIGHT");
        return;
    };
    execute(config, ready);
}

fn run_preflight(config: &LiveE2eConfig) -> PreflightResult {
    let mut result = PreflightResult::default();
    if config.validate_secret_files().is_err() {
        return result;
    }
    let node_configuration = config.node_configuration();
    if WalletService::probe_live_configuration(&node_configuration).is_err() {
        return result;
    }
    result.node_probe = true;
    result.node_identity = true;
    if WalletService::verify_live_node_capabilities(&node_configuration).is_err() {
        return result;
    }
    result.node_capabilities = true;
    let Some(password_a) = read_secret(&config.wallet_a_password_file) else {
        return result;
    };
    let Some(password_b) = read_secret(&config.wallet_b_password_file) else {
        return result;
    };
    let mut sender = WalletService::default();
    if sender.open(&config.wallet_a_dir).is_err() || sender.unlock(&password_a).is_err() {
        return result;
    }
    result.wallet_a_opened = true;
    if sender
        .set_node_configuration(node_configuration.clone())
        .is_err()
        || sender.synchronize_live().is_err()
    {
        return result;
    }
    result.wallet_a_synchronized = true;
    let funding = match sender.preflight_funding(config.amount) {
        Ok(funding) => funding,
        Err(_) => return result,
    };
    result.wallet_a_funding = Some(funding);
    let mut recipient = WalletService::default();
    // PREFLIGHT is intentionally unable to create a wallet. A missing Wallet
    // B is an operator prerequisite, never permission to mutate disk here.
    if recipient.open(&config.wallet_b_dir).is_err() {
        return result;
    }
    if recipient.unlock(&password_b).is_err() {
        return result;
    }
    result.wallet_b_opened = true;
    if recipient
        .set_node_configuration(node_configuration.clone())
        .is_err()
        || recipient.synchronize_live().is_err()
    {
        return result;
    }
    result.wallet_b_synchronized = true;
    result.block_producer_observed = observe_tip_progress(&node_configuration);
    result.ready = Some(ReadyWallets {
        sender,
        recipient,
        password_a,
        password_b,
    });
    result
}

fn print_preflight(result: &PreflightResult) {
    println!("NODE_PREFLIGHT={}", status(result.node_probe));
    println!("NODE_IDENTITY_VERIFIED={}", status(result.node_identity));
    println!(
        "NODE_CAPABILITIES_VERIFIED={}",
        status(result.node_capabilities)
    );
    println!("WALLET_A_OPENED={}", status(result.wallet_a_opened));
    println!(
        "WALLET_A_SYNCHRONIZED={}",
        status(result.wallet_a_synchronized)
    );
    println!(
        "WALLET_A_FUNDING_SUFFICIENT={}",
        status(
            result
                .wallet_a_funding
                .as_ref()
                .is_some_and(|funding| funding.fundable)
        )
    );
    println!("WALLET_B_OPENED={}", status(result.wallet_b_opened));
    println!(
        "WALLET_B_SYNCHRONIZED={}",
        status(result.wallet_b_synchronized)
    );
    println!(
        "BLOCK_PRODUCER_OBSERVED={}",
        status(result.block_producer_observed)
    );
    println!(
        "PREFLIGHT_VERDICT={}",
        if result.passed() { "PASS" } else { "FAIL" }
    );
    println!(
        "NEXT_OPERATOR_ACTION={}",
        if result.passed() {
            "Set DOM_LIVE_E2E_MODE=EXECUTE and the exact enable token to continue."
        } else if result
            .wallet_a_funding
            .as_ref()
            .is_some_and(|funding| !funding.fundable)
        {
            "Fund Wallet A with a mature locally-described output."
        } else if result.wallet_a_synchronized && result.wallet_b_synchronized {
            "Connect an external block producer and rerun PREFLIGHT."
        } else {
            "Correct the redacted preflight failure and rerun PREFLIGHT."
        }
    );
}

fn execute(config: LiveE2eConfig, mut ready: ReadyWallets) {
    let created = match ready.sender.transaction_send_create(config.amount, None) {
        Ok(created) => created,
        Err(_) => {
            println!("EXECUTE_VERDICT=WALLET_A_FUNDING_REQUIRED");
            return;
        }
    };
    let Some(slate_id) = created.slate_id else {
        println!("EXECUTE_VERDICT=BLOCKED_INTERNAL_STATE");
        return;
    };
    let request = match ready.sender.slate_request_export(slate_id) {
        Ok(value) => value,
        Err(_) => {
            println!("EXECUTE_VERDICT=BLOCKED_REQUEST_EXPORT");
            return;
        }
    };
    if ready.recipient.slate_request_import(&request.text).is_err()
        || ready.recipient.slate_response_create(slate_id).is_err()
    {
        println!("EXECUTE_VERDICT=BLOCKED_RESPONSE_CREATE");
        return;
    }
    let response = match ready.recipient.slate_response_export(slate_id) {
        Ok(value) => value,
        Err(_) => {
            println!("EXECUTE_VERDICT=BLOCKED_RESPONSE_EXPORT");
            return;
        }
    };
    if ready.sender.slate_response_import(&response.text).is_err()
        || ready.sender.transaction_finalize(slate_id).is_err()
    {
        println!("EXECUTE_VERDICT=BLOCKED_FINALIZATION");
        return;
    }
    if ready.sender.transaction_submit(slate_id).is_err() {
        println!("EXECUTE_VERDICT=SUBMISSION_UNCERTAIN_OR_REJECTED");
        return;
    }
    let _ = ready.sender.transaction_observe_mempool(slate_id);
    let timeout = bounded_seconds("DOM_LIVE_E2E_CONFIRMATION_TIMEOUT_SECS", 120);
    let poll = bounded_seconds("DOM_LIVE_E2E_POLL_INTERVAL_SECS", 2);
    let deadline = Instant::now() + Duration::from_secs(timeout);
    while Instant::now() < deadline {
        let _ = ready.sender.transaction_observe_mempool(slate_id);
        if ready.sender.synchronize_live().is_ok()
            && matches!(
                ready.sender.transaction_detail_redacted(slate_id).map(|value| value.state),
                Ok(state) if state == "CONFIRMED"
            )
        {
            let _ = ready.recipient.synchronize_live();
            let _ = ready.sender.close();
            let _ = ready.recipient.close();
            if restart_and_confirm(&config, slate_id, &ready.password_a, &ready.password_b) {
                println!("EXECUTE_VERDICT=CONFIRMED_AND_RESTARTED");
            } else {
                println!("EXECUTE_VERDICT=CONFIRMED_RESTART_RECONCILIATION_FAILED");
            }
            return;
        }
        thread::sleep(Duration::from_secs(poll));
    }
    println!("EXECUTE_VERDICT=SUBMITTED_NOT_YET_CONFIRMED");
}

fn restart_and_confirm(
    config: &LiveE2eConfig,
    slate_id: uuid::Uuid,
    password_a: &str,
    password_b: &str,
) -> bool {
    let mut sender = WalletService::default();
    let mut recipient = WalletService::default();
    sender.open(&config.wallet_a_dir).is_ok()
        && sender.unlock(password_a).is_ok()
        && sender
            .set_node_configuration(config.node_configuration())
            .is_ok()
        && sender.synchronize_live().is_ok()
        && recipient.open(&config.wallet_b_dir).is_ok()
        && recipient.unlock(password_b).is_ok()
        && recipient
            .set_node_configuration(config.node_configuration())
            .is_ok()
        && recipient.synchronize_live().is_ok()
        && matches!(
            sender.transaction_detail_redacted(slate_id).map(|value| value.state),
            Ok(state) if state == "CONFIRMED"
        )
        && matches!(
            recipient.transaction_detail_redacted(slate_id).map(|value| value.state),
            Ok(state) if state == "CONFIRMED"
        )
}

fn observe_tip_progress(configuration: &dom_wallet_domain::NodeConfiguration) -> bool {
    let Ok(before) = WalletService::probe_live_configuration(configuration) else {
        return false;
    };
    thread::sleep(Duration::from_secs(bounded_seconds(
        "DOM_LIVE_E2E_BLOCK_PRODUCER_OBSERVATION_SECS",
        15,
    )));
    let Ok(after) = WalletService::probe_live_configuration(configuration) else {
        return false;
    };
    before.tip_height != after.tip_height || before.tip_hash != after.tip_hash
}

fn read_secret(path: &std::path::Path) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .filter(|value| !value.is_empty())
}

fn bounded_seconds(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (1..=3_600).contains(value))
        .unwrap_or(default)
}

fn status(value: bool) -> &'static str {
    if value {
        "PASS"
    } else {
        "FAIL"
    }
}
