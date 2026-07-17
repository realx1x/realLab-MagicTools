mod app_lifecycle;
mod bridge;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .setup(|app| {
            app_lifecycle::setup(app)?;
            bridge::setup(app)
        })
        .invoke_handler(tauri::generate_handler![
            bridge::supervisor_connection_state,
            bridge::supervisor_forward_rpc,
            bridge::supervisor_cancel_request,
            bridge::supervisor_reset_connection,
            app_lifecycle::desktop_lifecycle_snapshot,
            app_lifecycle::desktop_acknowledge_navigation,
            app_lifecycle::desktop_complete_exit,
            app_lifecycle::desktop_cancel_exit,
        ])
        .build(tauri::generate_context!())
        .expect("failed to build the Tauri application");
    app.run(app_lifecycle::handle_run_event);
}
