#![forbid(unsafe_code)]

use dom_wallet_tauri_shell::DesktopApplication;
use tauri::Manager;

#[tauri::command]
fn application_status(
    app: tauri::State<'_, DesktopApplication>,
) -> dom_wallet_tauri_shell::ApplicationStatusDto {
    app.application_status()
}
#[tauri::command]
fn wallet_create_recoverable(
    app: tauri::State<'_, DesktopApplication>,
    path: String,
    password: String,
) -> Result<dom_wallet_tauri_shell::RecoveryCreateDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.wallet_create_recoverable(path, &password)
        .map_err(Into::into)
}
#[tauri::command]
fn wallet_restore_from_mnemonic(
    app: tauri::State<'_, DesktopApplication>,
    path: String,
    password: String,
    mnemonic: String,
) -> Result<dom_wallet_tauri_shell::RecoveryResultDto, dom_wallet_tauri_shell::CommandErrorDto> {
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
    app: tauri::State<'_, DesktopApplication>,
    destination: String,
    backup_path: String,
    backup_password: String,
    password: String,
) -> Result<dom_wallet_core::WalletSummary, dom_wallet_tauri_shell::CommandErrorDto> {
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
    app: tauri::State<'_, DesktopApplication>,
    path: String,
) -> Result<dom_wallet_core::WalletSummary, dom_wallet_tauri_shell::CommandErrorDto> {
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
    app: tauri::State<'_, DesktopApplication>,
    request: dom_wallet_tauri_shell::EmbeddedNodeStartDto,
) -> Result<dom_wallet_tauri_shell::EmbeddedNodeStatusDto, dom_wallet_tauri_shell::CommandErrorDto>
{
    app.embedded_node_start(request).map_err(Into::into)
}
#[tauri::command]
fn embedded_node_status(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::EmbeddedNodeStatusDto, dom_wallet_tauri_shell::CommandErrorDto>
{
    app.embedded_node_status().map_err(Into::into)
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
    app.synchronization_start_live().map_err(Into::into)
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
) -> Result<(), dom_wallet_tauri_shell::CommandErrorDto> {
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
    sender_address: String,
    receiver_address: String,
    expires_at_height: u64,
) -> Result<dom_wallet_core::TransactionSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.transaction_send_create(
        amount,
        requested_fee,
        &sender_address,
        &receiver_address,
        expires_at_height,
    )
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

fn main() {
    tauri::Builder::default()
        .manage(DesktopApplication::default())
        .invoke_handler(tauri::generate_handler![
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
            embedded_node_status,
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
            slate_qr_reassembly_clear
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|_| std::process::exit(1));
}
