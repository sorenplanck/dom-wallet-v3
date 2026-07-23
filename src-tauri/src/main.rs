#![forbid(unsafe_code)]

use dom_wallet_tauri_shell::DesktopApplication;
use std::{
    fs::{self, OpenOptions},
    net::TcpListener,
    sync::Mutex,
};
use tauri::Manager;

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
        .setup(|app| {
            initialize_file_logging(app);
            Ok(())
        })
        .manage(DesktopApplication::default())
        .invoke_handler(tauri::generate_handler![
            native_bridge_status,
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
    application_builder()
        .run(tauri::generate_context!())
        .unwrap_or_else(|_| std::process::exit(1));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packaged_entrypoint_constructs_the_registered_builder() {
        let _builder = application_builder();
        assert_eq!(dom_wallet_tauri_shell::COMMAND_NAMES.len(), 57);
        assert!(dom_wallet_tauri_shell::COMMAND_NAMES.contains(&"native_bridge_status"));
        assert!(dom_wallet_tauri_shell::COMMAND_NAMES.contains(&"embedded_node_stop"));
    }
}
