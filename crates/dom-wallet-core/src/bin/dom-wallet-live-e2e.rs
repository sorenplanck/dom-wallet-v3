#![forbid(unsafe_code)]

//! Headless, opt-in live-node lifecycle runner. It cannot submit unless the
//! exact acknowledgement token is present, and it never prints secrets,
//! transaction bytes, slate transport, or endpoint values.

use dom_wallet_core::live_e2e::{load_from_environment, LiveE2eConfigError};
use dom_wallet_core::WalletService;
use std::env;
use std::fs;
use std::thread;
use std::time::{Duration, Instant};

fn main() {
    let config = match load_from_environment() {
        Ok(config) => config,
        Err(LiveE2eConfigError::Missing(names)) => {
            println!("LIVE_EXECUTION=BLOCKED_MISSING_ENV");
            for name in names {
                println!("MISSING={name}");
            }
            return;
        }
        Err(_) => {
            println!("LIVE_EXECUTION=BLOCKED_INVALID_CONFIGURATION");
            return;
        }
    };
    if !config.mutation_enabled {
        println!("LIVE_EXECUTION=DRY_RUN_ONLY");
        return;
    }
    if config.validate_secret_files().is_err() {
        println!("LIVE_EXECUTION=BLOCKED_UNSAFE_SECRET_FILE");
        return;
    }
    if WalletService::probe_live_configuration(&config.node_configuration()).is_err() {
        println!("LIVE_EXECUTION=BLOCKED_NODE_PREFLIGHT");
        return;
    }
    let password_a = match read_secret(&config.wallet_a_password_file) {
        Some(value) => value,
        None => {
            println!("LIVE_EXECUTION=BLOCKED_UNSAFE_SECRET_FILE");
            return;
        }
    };
    let password_b = match read_secret(&config.wallet_b_password_file) {
        Some(value) => value,
        None => {
            println!("LIVE_EXECUTION=BLOCKED_UNSAFE_SECRET_FILE");
            return;
        }
    };
    let mut sender = WalletService::default();
    let mut recipient = WalletService::default();
    if sender.open(&config.wallet_a_dir).is_err()
        || sender.unlock(&password_a).is_err()
        || sender
            .set_node_configuration(config.node_configuration())
            .is_err()
        || sender.synchronize_live().is_err()
    {
        println!("LIVE_EXECUTION=BLOCKED_WALLET_A_PREFLIGHT");
        return;
    }
    if recipient.open(&config.wallet_b_dir).is_err()
        && (env::var("DOM_LIVE_E2E_ALLOW_CREATE_WALLET_B")
            .ok()
            .as_deref()
            != Some("YES")
            || recipient
                .create(&config.wallet_b_dir, &password_b, config.identity.clone())
                .is_err())
    {
        println!("LIVE_EXECUTION=BLOCKED_WALLET_B_PREFLIGHT");
        return;
    }
    if recipient.unlock(&password_b).is_err()
        || recipient
            .set_node_configuration(config.node_configuration())
            .is_err()
        || recipient.synchronize_live().is_err()
    {
        println!("LIVE_EXECUTION=BLOCKED_WALLET_B_PREFLIGHT");
        return;
    }

    // The core transaction engine performs selection before writing any intent;
    // insufficient funds therefore exits before input reservation.
    let created = match sender.transaction_send_create(config.amount, None) {
        Ok(created) => created,
        Err(_) => {
            println!("LIVE_EXECUTION=WALLET_A_FUNDING_REQUIRED");
            return;
        }
    };
    let Some(slate_id) = created.slate_id else {
        println!("LIVE_EXECUTION=BLOCKED_INTERNAL_STATE");
        return;
    };
    let request = match sender.slate_request_export(slate_id) {
        Ok(value) => value,
        Err(_) => {
            println!("LIVE_EXECUTION=BLOCKED_REQUEST_EXPORT");
            return;
        }
    };
    if recipient.slate_request_import(&request.text).is_err()
        || recipient.slate_response_create(slate_id).is_err()
    {
        println!("LIVE_EXECUTION=BLOCKED_RESPONSE_CREATE");
        return;
    }
    let response = match recipient.slate_response_export(slate_id) {
        Ok(value) => value,
        Err(_) => {
            println!("LIVE_EXECUTION=BLOCKED_RESPONSE_EXPORT");
            return;
        }
    };
    if sender.slate_response_import(&response.text).is_err()
        || sender.transaction_finalize(slate_id).is_err()
    {
        println!("LIVE_EXECUTION=BLOCKED_FINALIZATION");
        return;
    }
    if sender.transaction_submit(slate_id).is_err() {
        // Core has already persisted the uncertainty-safe state. The runner
        // never cancels, releases reservations, or rebuilds a transaction.
        println!("LIVE_EXECUTION=SUBMISSION_UNCERTAIN_OR_REJECTED");
        return;
    }
    let _ = sender.transaction_observe_mempool(slate_id);
    let timeout = bounded_seconds("DOM_LIVE_E2E_CONFIRMATION_TIMEOUT_SECS", 120);
    let poll = bounded_seconds("DOM_LIVE_E2E_POLL_INTERVAL_SECS", 2);
    let deadline = Instant::now() + Duration::from_secs(timeout);
    while Instant::now() < deadline {
        let _ = sender.transaction_observe_mempool(slate_id);
        if sender.synchronize_live().is_ok()
            && matches!(
                sender.transaction_detail_redacted(slate_id).map(|value| value.state),
                Ok(state) if state == "CONFIRMED"
            )
        {
            let _ = recipient.synchronize_live();
            let _ = sender.close();
            let _ = recipient.close();
            let mut reopened_sender = WalletService::default();
            let mut reopened_recipient = WalletService::default();
            if reopened_sender.open(&config.wallet_a_dir).is_err()
                || reopened_sender.unlock(&password_a).is_err()
                || reopened_sender
                    .set_node_configuration(config.node_configuration())
                    .is_err()
                || reopened_sender.synchronize_live().is_err()
                || reopened_recipient.open(&config.wallet_b_dir).is_err()
                || reopened_recipient.unlock(&password_b).is_err()
                || reopened_recipient
                    .set_node_configuration(config.node_configuration())
                    .is_err()
                || reopened_recipient.synchronize_live().is_err()
                || !matches!(
                    reopened_sender.transaction_detail_redacted(slate_id).map(|value| value.state),
                    Ok(state) if state == "CONFIRMED"
                )
                || !matches!(
                    reopened_recipient.transaction_detail_redacted(slate_id).map(|value| value.state),
                    Ok(state) if state == "CONFIRMED"
                )
            {
                println!("LIVE_EXECUTION=CONFIRMED_RESTART_RECONCILIATION_FAILED");
                return;
            }
            println!("LIVE_EXECUTION=CONFIRMED_AND_RESTARTED");
            return;
        }
        thread::sleep(Duration::from_secs(poll));
    }
    println!("LIVE_EXECUTION=SUBMITTED_NOT_YET_CONFIRMED");
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
