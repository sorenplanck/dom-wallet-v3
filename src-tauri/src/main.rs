#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use dom_wallet_tauri_shell::{DesktopApplication, UpdateControl};
use dom_wallet_updater::{
    validate_download, validate_wallet_manifest, verify_wallet_manifest_signature,
    MinisignVerifier, UpdateError, WalletDecision, WalletManifest, WalletPolicy,
    WalletUpdaterState, MAX_INITIAL_JITTER_SECONDS, UPDATE_INTERVAL_SECONDS,
    WALLET_UPDATE_ENDPOINT,
};
use std::{
    fs::{self, OpenOptions},
    net::TcpListener,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tauri::Manager;
use tauri_plugin_updater::UpdaterExt;

const UPDATE_PUBLIC_KEY: Option<&str> = option_env!("DOM_UPDATE_PUBLIC_KEY");

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn initialize_file_logging(app: &tauri::App) {
    let file = app.path().app_log_dir().ok().and_then(|directory| {
        fs::create_dir_all(&directory).ok()?;
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(directory.join("dom-wallet-v3.log"))
            .ok()
    });
    if let Some(file) = file {
        let _ = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing_subscriber::filter::LevelFilter::INFO)
            .with_writer(Mutex::new(file))
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing_subscriber::filter::LevelFilter::INFO)
            .try_init();
    }
}

fn ensure_mainnet_node(
    handle: &tauri::AppHandle,
    app: &DesktopApplication,
) -> Result<dom_wallet_tauri_shell::EmbeddedNodeStatusDto, dom_wallet_tauri_shell::CommandErrorDto>
{
    if let Ok(status) = app.embedded_node_status() {
        if status.network.is_some() {
            return Ok(status);
        }
    }
    let data_directory = handle
        .path()
        .app_data_dir()
        .map_err(|_| dom_wallet_tauri_shell::CommandErrorDto {
            code: "APP_DATA_DIRECTORY_UNAVAILABLE".into(),
            category: "PLATFORM".into(),
            message: "The platform application data directory is unavailable.".into(),
            retryable: false,
        })?
        .join("mainnet")
        .join("node");
    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|_| dom_wallet_tauri_shell::CommandErrorDto {
            code: "LOCAL_LISTENER_UNAVAILABLE".into(),
            category: "NODE".into(),
            message: "A private local node listener could not be reserved.".into(),
            retryable: true,
        })?;
    let address = listener
        .local_addr()
        .map_err(|_| dom_wallet_tauri_shell::CommandErrorDto {
            code: "LOCAL_LISTENER_UNAVAILABLE".into(),
            category: "NODE".into(),
            message: "A private local node listener could not be reserved.".into(),
            retryable: true,
        })?;
    drop(listener);
    app.embedded_node_start_mainnet(data_directory, address)
        .map_err(Into::into)
}

#[tauri::command]
fn native_bridge_status() -> dom_wallet_tauri_shell::NativeBridgeStatusDto {
    dom_wallet_tauri_shell::native_bridge_status()
}

#[tauri::command]
fn get_build_info() -> dom_wallet_tauri_shell::BuildInfoDto {
    dom_wallet_tauri_shell::get_build_info()
}

#[tauri::command]
fn update_status(
    updater: tauri::State<'_, UpdateControl>,
) -> dom_wallet_tauri_shell::UpdateStatusDto {
    updater.snapshot()
}

#[tauri::command]
async fn check_updates_now(handle: tauri::AppHandle) -> dom_wallet_tauri_shell::UpdateStatusDto {
    perform_update_cycle(handle, true).await
}

#[tauri::command]
async fn check_node_now(handle: tauri::AppHandle) -> dom_wallet_tauri_shell::UpdateStatusDto {
    perform_update_cycle(handle, false).await
}

async fn perform_update_cycle(
    handle: tauri::AppHandle,
    allow_wallet_install: bool,
) -> dom_wallet_tauri_shell::UpdateStatusDto {
    let updater_state = handle.state::<UpdateControl>();
    if !updater_state.begin_check(unix_seconds()) {
        return updater_state.snapshot();
    }
    let Some(public_key) = UPDATE_PUBLIC_KEY.filter(|key| !key.trim().is_empty()) else {
        updater_state.finish_check_without_key();
        return updater_state.snapshot();
    };
    let result = check_wallet_update(&handle, public_key, allow_wallet_install).await;
    if let Err(error) = result {
        tracing::warn!(code = %error, "signed update check failed");
        updater_state.fail_wallet_check(error_code(error));
    }
    updater_state.snapshot()
}

async fn check_wallet_update(
    handle: &tauri::AppHandle,
    public_key: &str,
    allow_install: bool,
) -> Result<(), UpdateError> {
    let endpoint = WALLET_UPDATE_ENDPOINT
        .parse()
        .map_err(|_| UpdateError::ManifestInvalid)?;
    let updater = handle
        .updater_builder()
        .pubkey(public_key)
        .endpoints(vec![endpoint])
        .map_err(|_| UpdateError::CheckFailed)?
        .timeout(Duration::from_secs(20))
        .configure_client(|client| {
            client.redirect(reqwest13::redirect::Policy::custom(|attempt| {
                if attempt.previous().len() >= 5 {
                    return attempt.stop();
                }
                if dom_wallet_updater::validate_release_url(attempt.url()).is_ok() {
                    attempt.follow()
                } else {
                    attempt.stop()
                }
            }))
        })
        .build()
        .map_err(|_| UpdateError::CheckFailed)?;
    let Some(update) = updater
        .check()
        .await
        .map_err(|_| UpdateError::CheckFailed)?
    else {
        handle
            .state::<UpdateControl>()
            .finish_network_check(None, None);
        return Ok(());
    };
    let manifest_value = update
        .raw_json
        .get("dom_manifest")
        .cloned()
        .ok_or(UpdateError::ManifestInvalid)?;
    let manifest: WalletManifest =
        serde_json::from_value(manifest_value).map_err(|_| UpdateError::ManifestInvalid)?;
    let verifier = MinisignVerifier::from_base64(public_key)?;
    verify_wallet_manifest_signature(&manifest, &verifier)?;
    let policy = WalletPolicy {
        installed_version: env!("CARGO_PKG_VERSION"),
        update_channel: dom_wallet_updater::UPDATE_CHANNEL,
        target: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        network: "mainnet",
        wallet_schema: 2,
    };
    let decision = validate_wallet_manifest(&manifest, &policy, time::OffsetDateTime::now_utc())?;
    if manifest.version != update.version
        || manifest.artifact.url.as_str() != update.download_url.as_str()
        || manifest.artifact.signature != update.signature
    {
        return Err(UpdateError::ManifestInvalid);
    }
    let WalletDecision::Available(version) = decision else {
        handle
            .state::<UpdateControl>()
            .finish_network_check(None, None);
        return Ok(());
    };
    if !allow_install {
        handle
            .state::<UpdateControl>()
            .finish_network_check(Some(version.to_string()), None);
        return Ok(());
    }
    let state = handle.state::<UpdateControl>();
    state.set_wallet_download_state(WalletUpdaterState::Downloading, Some(0));
    let bytes = update
        .download(
            |_chunk, _total| {},
            || tracing::info!("signed Wallet update download completed"),
        )
        .await
        .map_err(|_| UpdateError::SignatureInvalid)?;
    state.set_wallet_download_state(WalletUpdaterState::Verifying, Some(100));
    validate_download(&bytes, &manifest.artifact)?;
    let application = handle.state::<DesktopApplication>();
    if !application
        .update_safe_point_available()
        .map_err(|_| UpdateError::BusyCriticalOperation)?
    {
        state.defer_wallet_install(version.to_string());
        return Ok(());
    }
    state.set_wallet_download_state(WalletUpdaterState::Installing, Some(100));
    application
        .application_shutdown()
        .map_err(|_| UpdateError::WalletPersistFailed)?;
    if update.install(bytes).is_err() {
        tracing::error!("Wallet installer failed; restarting the current signed version");
        handle.restart();
    }
    state.set_wallet_download_state(WalletUpdaterState::Restarting, Some(100));
    handle.restart();
}

fn error_code(error: UpdateError) -> &'static str {
    match error {
        UpdateError::CheckFailed => "UPDATE_CHECK_FAILED",
        UpdateError::ManifestInvalid => "UPDATE_MANIFEST_INVALID",
        UpdateError::SignatureInvalid => "UPDATE_SIGNATURE_INVALID",
        UpdateError::HashMismatch => "UPDATE_HASH_MISMATCH",
        UpdateError::SizeMismatch => "UPDATE_SIZE_MISMATCH",
        UpdateError::UnsupportedPlatform => "UPDATE_UNSUPPORTED_PLATFORM",
        UpdateError::DowngradeRejected => "UPDATE_DOWNGRADE_REJECTED",
        UpdateError::ChannelInvalid => "UPDATE_CHANNEL_INVALID",
        UpdateError::Expired => "UPDATE_MANIFEST_EXPIRED",
        UpdateError::OriginRejected => "UPDATE_ORIGIN_REJECTED",
        UpdateError::BusyCriticalOperation => "UPDATE_BUSY_CRITICAL_OPERATION",
        _ => "UPDATE_INSTALL_FAILED",
    }
}

#[tauri::command]
fn application_status(
    app: tauri::State<'_, DesktopApplication>,
) -> dom_wallet_tauri_shell::ApplicationStatusDto {
    app.application_status()
}
#[tauri::command]
fn wallet_create_recoverable(
    handle: tauri::AppHandle,
    app: tauri::State<'_, DesktopApplication>,
    path: String,
    password: String,
) -> Result<dom_wallet_tauri_shell::RecoveryCreateDto, dom_wallet_tauri_shell::CommandErrorDto> {
    ensure_mainnet_node(&handle, &app)?;
    app.wallet_create_recoverable(path, &password)
        .map_err(Into::into)
}
#[tauri::command]
fn wallet_restore_from_mnemonic(
    handle: tauri::AppHandle,
    app: tauri::State<'_, DesktopApplication>,
    path: String,
    password: String,
    mnemonic: String,
) -> Result<dom_wallet_tauri_shell::RecoveryResultDto, dom_wallet_tauri_shell::CommandErrorDto> {
    ensure_mainnet_node(&handle, &app)?;
    app.wallet_restore_from_mnemonic(path, &password, &mnemonic)
        .map_err(Into::into)
}
#[tauri::command]
fn wallet_backup_export(
    app: tauri::State<'_, DesktopApplication>,
    destination: String,
    backup_password: String,
) -> Result<dom_wallet_core::BackupStatus, dom_wallet_tauri_shell::CommandErrorDto> {
    app.wallet_backup_export(destination, &backup_password)
        .map_err(Into::into)
}
#[tauri::command]
fn wallet_backup_import(
    handle: tauri::AppHandle,
    app: tauri::State<'_, DesktopApplication>,
    destination: String,
    backup_path: String,
    backup_password: String,
    password: String,
) -> Result<dom_wallet_core::WalletSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    ensure_mainnet_node(&handle, &app)?;
    app.wallet_backup_import(destination, backup_path, &backup_password, &password)
        .map_err(Into::into)
}
#[tauri::command]
fn wallet_recovery_phrase_confirm(
    app: tauri::State<'_, DesktopApplication>,
    password: String,
) -> Result<(), dom_wallet_tauri_shell::CommandErrorDto> {
    app.wallet_recovery_phrase_confirm(&password)
        .map_err(Into::into)
}
#[tauri::command]
fn wallet_open(
    handle: tauri::AppHandle,
    app: tauri::State<'_, DesktopApplication>,
    path: String,
) -> Result<dom_wallet_core::WalletSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    ensure_mainnet_node(&handle, &app)?;
    app.wallet_open(path).map_err(Into::into)
}
#[tauri::command]
fn wallet_unlock(
    app: tauri::State<'_, DesktopApplication>,
    password: String,
) -> Result<dom_wallet_core::WalletSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.wallet_unlock(&password).map_err(Into::into)
}
#[tauri::command]
fn wallet_lock(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<(), dom_wallet_tauri_shell::CommandErrorDto> {
    app.wallet_lock().map_err(Into::into)
}
#[tauri::command]
fn wallet_close(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<(), dom_wallet_tauri_shell::CommandErrorDto> {
    app.wallet_close().map_err(Into::into)
}
#[tauri::command]
fn wallet_summary(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_core::WalletSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.wallet_summary().map_err(Into::into)
}
#[tauri::command]
fn account_list(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<Vec<(uuid::Uuid, String)>, dom_wallet_tauri_shell::CommandErrorDto> {
    app.account_list().map_err(Into::into)
}
#[tauri::command]
fn account_summary(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_core::WalletSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.account_summary().map_err(Into::into)
}
#[tauri::command]
fn embedded_node_start(
    handle: tauri::AppHandle,
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::EmbeddedNodeStatusDto, dom_wallet_tauri_shell::CommandErrorDto>
{
    ensure_mainnet_node(&handle, &app)
}
#[tauri::command]
fn embedded_node_stop(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::EmbeddedNodeStatusDto, dom_wallet_tauri_shell::CommandErrorDto>
{
    app.embedded_node_stop().map_err(Into::into)
}
#[tauri::command]
fn embedded_node_status(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::EmbeddedNodeStatusDto, dom_wallet_tauri_shell::CommandErrorDto>
{
    app.embedded_node_status().map_err(Into::into)
}
#[tauri::command]
fn node_network_status(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::NodeNetworkStatusDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.node_network_status().map_err(Into::into)
}
#[tauri::command]
fn node_peer_status(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::NodePeerStatusDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.node_peer_status().map_err(Into::into)
}
#[tauri::command]
fn wallet_sync_status(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::WalletSyncStatusDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.wallet_sync_status().map_err(Into::into)
}
#[tauri::command]
fn wallet_sync_start(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_core::WalletSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.synchronization_start_live().map_err(Into::into)
}
#[tauri::command]
fn wallet_sync_pause(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<(), dom_wallet_tauri_shell::CommandErrorDto> {
    app.synchronization_pause().map_err(Into::into)
}
#[tauri::command]
fn wallet_sync_resume(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_core::WalletSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.synchronization_resume_live().map_err(Into::into)
}
#[tauri::command]
fn wallet_sync_retry(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_core::WalletSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.synchronization_resume_live().map_err(Into::into)
}
#[tauri::command]
fn wallet_rescan(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_core::WalletSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.synchronization_rescan().map_err(Into::into)
}
#[tauri::command]
fn mining_status(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::MiningStatusDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.mining_status().map_err(Into::into)
}
#[tauri::command]
fn mining_config_get(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::MiningConfigDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.mining_config_get().map_err(Into::into)
}
#[tauri::command]
fn mining_config_set(
    app: tauri::State<'_, DesktopApplication>,
    enabled: bool,
    cpu_threads: usize,
) -> Result<dom_wallet_tauri_shell::MiningConfigDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.mining_config_set(enabled, cpu_threads)
        .map_err(Into::into)
}
#[tauri::command]
fn mining_start(
    app: tauri::State<'_, DesktopApplication>,
    confirmed: bool,
) -> Result<dom_wallet_tauri_shell::MiningStatusDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.mining_start(confirmed).map_err(Into::into)
}
#[tauri::command]
fn mining_stop(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::MiningStatusDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.mining_stop().map_err(Into::into)
}
#[tauri::command]
fn diagnostics_redacted(
    app: tauri::State<'_, DesktopApplication>,
) -> dom_wallet_core::DiagnosticSnapshot {
    app.diagnostics_redacted()
}
#[tauri::command]
fn synchronization_pause(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<(), dom_wallet_tauri_shell::CommandErrorDto> {
    app.synchronization_pause().map_err(Into::into)
}
#[tauri::command]
fn synchronization_start(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_core::WalletSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.synchronization_start_live().map_err(Into::into)
}
#[tauri::command]
fn synchronization_resume(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_core::WalletSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.synchronization_resume_live().map_err(Into::into)
}
#[tauri::command]
fn synchronization_retry(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_core::WalletSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.synchronization_start_live().map_err(Into::into)
}
#[tauri::command]
fn synchronization_rescan(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_core::WalletSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.synchronization_rescan().map_err(Into::into)
}
#[tauri::command]
fn application_shutdown(
    window: tauri::Window,
    app: tauri::State<'_, DesktopApplication>,
) -> Result<(), dom_wallet_tauri_shell::CommandErrorDto> {
    app.application_shutdown()
        .map_err(dom_wallet_tauri_shell::CommandErrorDto::from)?;
    window.app_handle().exit(0);
    Ok(())
}

#[tauri::command]
fn transaction_fee_estimate(
    app: tauri::State<'_, DesktopApplication>,
    amount: u64,
    selected_input_count: u32,
    change_output: bool,
) -> Result<dom_wallet_core::FeeEstimate, dom_wallet_tauri_shell::CommandErrorDto> {
    app.transaction_fee_estimate(amount, selected_input_count, change_output)
        .map_err(Into::into)
}
#[tauri::command]
fn wallet_address_validate(
    app: tauri::State<'_, DesktopApplication>,
    address: String,
) -> Result<String, dom_wallet_tauri_shell::CommandErrorDto> {
    app.wallet_address_validate(&address).map_err(Into::into)
}
#[tauri::command]
fn transaction_send_create(
    app: tauri::State<'_, DesktopApplication>,
    amount: u64,
    requested_fee: Option<u64>,
    expires_at_height: u64,
) -> Result<dom_wallet_core::TransactionSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.transaction_send_create(amount, requested_fee, expires_at_height)
        .map_err(Into::into)
}
#[tauri::command]
fn slate_request_export(
    app: tauri::State<'_, DesktopApplication>,
    slate_id: uuid::Uuid,
) -> Result<dom_wallet_core::SlateExport, dom_wallet_tauri_shell::CommandErrorDto> {
    app.slate_request_export(slate_id).map_err(Into::into)
}
#[tauri::command]
fn slate_request_import(
    app: tauri::State<'_, DesktopApplication>,
    text: String,
) -> Result<dom_wallet_core::TransactionSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.slate_request_import(&text).map_err(Into::into)
}
#[tauri::command]
fn slate_response_create(
    app: tauri::State<'_, DesktopApplication>,
    slate_id: uuid::Uuid,
) -> Result<dom_wallet_core::TransactionSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.slate_response_create(slate_id).map_err(Into::into)
}
#[tauri::command]
fn slate_response_export(
    app: tauri::State<'_, DesktopApplication>,
    slate_id: uuid::Uuid,
) -> Result<dom_wallet_core::SlateExport, dom_wallet_tauri_shell::CommandErrorDto> {
    app.slate_response_export(slate_id).map_err(Into::into)
}
#[tauri::command]
fn slate_response_import(
    app: tauri::State<'_, DesktopApplication>,
    text: String,
) -> Result<dom_wallet_core::TransactionSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.slate_response_import(&text).map_err(Into::into)
}
#[tauri::command]
fn slate_summary_redacted(
    app: tauri::State<'_, DesktopApplication>,
    slate_id: uuid::Uuid,
) -> Result<dom_wallet_core::TransactionSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.slate_summary_redacted(slate_id).map_err(Into::into)
}
#[tauri::command]
fn transaction_finalize(
    app: tauri::State<'_, DesktopApplication>,
    slate_id: uuid::Uuid,
) -> Result<dom_wallet_core::TransactionSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.transaction_finalize(slate_id).map_err(Into::into)
}
#[tauri::command]
fn transaction_submit(
    app: tauri::State<'_, DesktopApplication>,
    slate_id: uuid::Uuid,
) -> Result<dom_wallet_tauri_shell::SubmissionResultDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.transaction_submit(slate_id).map_err(Into::into)
}
#[tauri::command]
fn transaction_retry_submission(
    app: tauri::State<'_, DesktopApplication>,
    slate_id: uuid::Uuid,
) -> Result<dom_wallet_tauri_shell::SubmissionResultDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.transaction_retry_submission(slate_id)
        .map_err(Into::into)
}
#[tauri::command]
fn transaction_reconcile_submission(
    app: tauri::State<'_, DesktopApplication>,
    slate_id: uuid::Uuid,
) -> Result<dom_wallet_tauri_shell::SubmissionResultDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.transaction_reconcile_submission(slate_id)
        .map_err(Into::into)
}
#[tauri::command]
fn transaction_cancel(
    app: tauri::State<'_, DesktopApplication>,
    slate_id: uuid::Uuid,
    confirm_exported: bool,
) -> Result<dom_wallet_core::TransactionSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.transaction_cancel(slate_id, confirm_exported)
        .map_err(Into::into)
}
#[tauri::command]
fn transaction_list(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<Vec<dom_wallet_core::TransactionSummary>, dom_wallet_tauri_shell::CommandErrorDto> {
    app.transaction_list().map_err(Into::into)
}
#[tauri::command]
fn transaction_detail_redacted(
    app: tauri::State<'_, DesktopApplication>,
    slate_id: uuid::Uuid,
) -> Result<dom_wallet_core::TransactionSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.slate_summary_redacted(slate_id).map_err(Into::into)
}
#[tauri::command]
fn slate_qr_encode(
    app: tauri::State<'_, DesktopApplication>,
    slate_id: uuid::Uuid,
    response: bool,
) -> Result<dom_wallet_tauri_shell::SlateQrExportDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.slate_qr_encode(slate_id, response).map_err(Into::into)
}
#[tauri::command]
fn slate_qr_decode_frame(
    app: tauri::State<'_, DesktopApplication>,
    frame: String,
) -> Result<dom_wallet_tauri_shell::SlateQrReassemblyDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.slate_qr_decode_frame(&frame).map_err(Into::into)
}
#[tauri::command]
fn slate_qr_reassembly_status(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::SlateQrReassemblyDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.slate_qr_reassembly_status().map_err(Into::into)
}
#[tauri::command]
fn slate_qr_reassembly_clear(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<(), dom_wallet_tauri_shell::CommandErrorDto> {
    app.slate_qr_reassembly_clear().map_err(Into::into)
}

fn application_builder() -> tauri::Builder<tauri::Wry> {
    tauri::Builder::default()
        .plugin(
            tauri_plugin_updater::Builder::new()
                .pubkey(UPDATE_PUBLIC_KEY.unwrap_or(""))
                .build(),
        )
        .manage(UpdateControl::new(
            UPDATE_PUBLIC_KEY.is_some_and(|key| !key.trim().is_empty()),
        ))
        .manage(DesktopApplication::default())
        .setup(|app| {
            initialize_file_logging(app);
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let jitter = unix_seconds() % (MAX_INITIAL_JITTER_SECONDS + 1);
                tokio::time::sleep(Duration::from_secs(jitter)).await;
                loop {
                    let _ = perform_update_cycle(handle.clone(), true).await;
                    tokio::time::sleep(Duration::from_secs(UPDATE_INTERVAL_SECONDS)).await;
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            native_bridge_status,
            get_build_info,
            update_status,
            check_updates_now,
            check_node_now,
            application_status,
            wallet_create_recoverable,
            wallet_restore_from_mnemonic,
            wallet_backup_export,
            wallet_backup_import,
            wallet_recovery_phrase_confirm,
            wallet_open,
            wallet_unlock,
            wallet_lock,
            wallet_close,
            wallet_summary,
            account_list,
            account_summary,
            embedded_node_start,
            embedded_node_stop,
            embedded_node_status,
            node_network_status,
            node_peer_status,
            wallet_sync_status,
            wallet_sync_start,
            wallet_sync_pause,
            wallet_sync_resume,
            wallet_sync_retry,
            wallet_rescan,
            mining_status,
            mining_config_get,
            mining_config_set,
            mining_start,
            mining_stop,
            synchronization_start,
            synchronization_pause,
            synchronization_resume,
            synchronization_retry,
            synchronization_rescan,
            diagnostics_redacted,
            application_shutdown,
            transaction_fee_estimate,
            wallet_address_validate,
            transaction_send_create,
            slate_request_export,
            slate_request_import,
            slate_response_create,
            slate_response_export,
            slate_response_import,
            slate_summary_redacted,
            transaction_finalize,
            transaction_submit,
            transaction_retry_submission,
            transaction_reconcile_submission,
            transaction_cancel,
            transaction_list,
            transaction_detail_redacted,
            slate_qr_encode,
            slate_qr_decode_frame,
            slate_qr_reassembly_status,
            slate_qr_reassembly_clear,
        ])
}

fn main() {
    let Ok(app) = application_builder().build(tauri::generate_context!()) else {
        std::process::exit(1);
    };
    app.run(|handle, event| {
        if matches!(event, tauri::RunEvent::Resumed) {
            let handle = handle.clone();
            tauri::async_runtime::spawn(async move {
                let _ = perform_update_cycle(handle, true).await;
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packaged_entrypoint_constructs_the_registered_builder() {
        let _builder = application_builder();
        assert_eq!(dom_wallet_tauri_shell::COMMAND_NAMES.len(), 61);
        assert!(dom_wallet_tauri_shell::COMMAND_NAMES.contains(&"native_bridge_status"));
        assert!(dom_wallet_tauri_shell::COMMAND_NAMES.contains(&"check_updates_now"));
        assert!(dom_wallet_tauri_shell::COMMAND_NAMES.contains(&"embedded_node_stop"));
    }
}
