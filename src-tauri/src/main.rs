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
fn wallet_create(
    app: tauri::State<'_, DesktopApplication>,
    path: String,
    password: String,
    identity: dom_wallet_domain::NetworkIdentity,
) -> Result<dom_wallet_core::WalletSummary, String> {
    app.wallet_create(path, &password, identity)
        .map_err(|e| e.to_string())
}
#[tauri::command]
fn wallet_open(
    app: tauri::State<'_, DesktopApplication>,
    path: String,
) -> Result<dom_wallet_core::WalletSummary, String> {
    app.wallet_open(path).map_err(|e| e.to_string())
}
#[tauri::command]
fn wallet_unlock(
    app: tauri::State<'_, DesktopApplication>,
    password: String,
) -> Result<dom_wallet_core::WalletSummary, String> {
    app.wallet_unlock(&password).map_err(|e| e.to_string())
}
#[tauri::command]
fn wallet_lock(app: tauri::State<'_, DesktopApplication>) -> Result<(), String> {
    app.wallet_lock().map_err(|e| e.to_string())
}
#[tauri::command]
fn wallet_close(app: tauri::State<'_, DesktopApplication>) -> Result<(), String> {
    app.wallet_close().map_err(|e| e.to_string())
}
#[tauri::command]
fn wallet_summary(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_core::WalletSummary, String> {
    app.wallet_summary().map_err(|e| e.to_string())
}
#[tauri::command]
fn account_list(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<Vec<(uuid::Uuid, String)>, String> {
    app.account_list().map_err(|e| e.to_string())
}
#[tauri::command]
fn account_summary(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_core::WalletSummary, String> {
    app.account_summary().map_err(|e| e.to_string())
}
#[tauri::command]
fn node_configuration_get_redacted(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_domain::RedactedNodeConfiguration, String> {
    app.node_configuration_get_redacted()
        .map_err(|e| e.to_string())
}
#[tauri::command]
fn node_configuration_set(
    app: tauri::State<'_, DesktopApplication>,
    configuration: dom_wallet_domain::NodeConfiguration,
) -> Result<(), String> {
    app.node_configuration_set(configuration)
        .map_err(|e| e.to_string())
}
#[tauri::command]
fn diagnostics_redacted(
    app: tauri::State<'_, DesktopApplication>,
) -> dom_wallet_core::DiagnosticSnapshot {
    app.diagnostics_redacted()
}
#[tauri::command]
fn synchronization_pause(app: tauri::State<'_, DesktopApplication>) -> Result<(), String> {
    app.synchronization_pause().map_err(|e| e.to_string())
}
#[tauri::command]
fn synchronization_start(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_core::WalletSummary, String> {
    app.synchronization_start_live().map_err(|e| e.to_string())
}
#[tauri::command]
fn synchronization_resume(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_core::WalletSummary, String> {
    app.synchronization_start_live().map_err(|e| e.to_string())
}
#[tauri::command]
fn synchronization_retry(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_core::WalletSummary, String> {
    app.synchronization_start_live().map_err(|e| e.to_string())
}
#[tauri::command]
fn synchronization_rescan(app: tauri::State<'_, DesktopApplication>) -> Result<(), String> {
    app.synchronization_rescan().map_err(|e| e.to_string())
}
#[tauri::command]
fn node_probe() -> Result<(), String> {
    Err("node probe requires a redacted, explicit node configuration and is not available from this screen".into())
}
#[tauri::command]
fn application_shutdown(
    window: tauri::Window,
    app: tauri::State<'_, DesktopApplication>,
) -> Result<(), String> {
    app.application_shutdown().map_err(|e| e.to_string())?;
    window.app_handle().exit(0);
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .manage(DesktopApplication::default())
        .invoke_handler(tauri::generate_handler![
            application_status,
            wallet_create,
            wallet_open,
            wallet_unlock,
            wallet_lock,
            wallet_close,
            wallet_summary,
            account_list,
            account_summary,
            node_configuration_get_redacted,
            node_configuration_set,
            node_probe,
            synchronization_start,
            synchronization_pause,
            synchronization_resume,
            synchronization_retry,
            synchronization_rescan,
            diagnostics_redacted,
            application_shutdown
        ])
        .run(tauri::generate_context!())
        .expect("failed to run DOM Wallet V3 native runtime");
}
