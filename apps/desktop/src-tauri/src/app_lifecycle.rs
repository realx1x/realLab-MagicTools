use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, RunEvent, State, WindowEvent};

const MAIN_WINDOW_LABEL: &str = "main";
const TRAY_ID: &str = "magictools-main";
const MENU_SHOW: &str = "magictools-show";
const MENU_LAUNCH_PROFILES: &str = "magictools-open-launch-profiles";
const MENU_SETTINGS: &str = "magictools-open-settings";
const MENU_QUIT: &str = "magictools-quit";
const NAVIGATE_EVENT: &str = "desktop://navigate-requested";
const EXIT_EVENT: &str = "desktop://exit-requested";
const NONCE_BYTES: usize = 32;
const NONCE_HEX_BYTES: usize = NONCE_BYTES * 2;

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum DesktopRoute {
    LaunchProfiles,
    Settings,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
enum ExitRequestSource {
    System,
    Tray,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NavigationRequest {
    nonce: String,
    route: DesktopRoute,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExitRequest {
    nonce: String,
    source: ExitRequestSource,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LifecycleSnapshot {
    pending_exit: Option<ExitRequest>,
    pending_navigation: Option<NavigationRequest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NonceRequest {
    nonce: String,
}

#[derive(Default)]
struct LifecycleInner {
    exit_authorized: bool,
    pending_exit: Option<ExitRequest>,
    pending_navigation: Option<NavigationRequest>,
}

#[derive(Default)]
pub(crate) struct AppLifecycleState {
    inner: Mutex<LifecycleInner>,
}

impl AppLifecycleState {
    fn lock(&self) -> MutexGuard<'_, LifecycleInner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn snapshot(&self) -> LifecycleSnapshot {
        let inner = self.lock();
        LifecycleSnapshot {
            pending_exit: inner.pending_exit.clone(),
            pending_navigation: inner.pending_navigation.clone(),
        }
    }

    fn begin_navigation(&self, route: DesktopRoute) -> NavigationRequest {
        let request = NavigationRequest {
            nonce: generate_nonce(),
            route,
        };
        self.lock().pending_navigation = Some(request.clone());
        request
    }

    fn acknowledge_navigation(&self, nonce: &str) -> bool {
        if !valid_nonce(nonce) {
            return false;
        }
        let mut inner = self.lock();
        if inner
            .pending_navigation
            .as_ref()
            .is_some_and(|request| request.nonce == nonce)
        {
            inner.pending_navigation = None;
            true
        } else {
            false
        }
    }

    fn begin_exit(&self, source: ExitRequestSource) -> Option<ExitRequest> {
        let mut inner = self.lock();
        if inner.exit_authorized {
            return None;
        }
        if let Some(request) = &inner.pending_exit {
            return Some(request.clone());
        }
        let request = ExitRequest {
            nonce: generate_nonce(),
            source,
        };
        inner.pending_exit = Some(request.clone());
        Some(request)
    }

    fn authorize_exit(&self, nonce: &str) -> bool {
        if !valid_nonce(nonce) {
            return false;
        }
        let mut inner = self.lock();
        if inner
            .pending_exit
            .as_ref()
            .is_some_and(|request| request.nonce == nonce)
        {
            inner.pending_exit = None;
            inner.exit_authorized = true;
            true
        } else {
            false
        }
    }

    fn cancel_exit(&self, nonce: &str) -> bool {
        if !valid_nonce(nonce) {
            return false;
        }
        let mut inner = self.lock();
        if inner
            .pending_exit
            .as_ref()
            .is_some_and(|request| request.nonce == nonce)
        {
            inner.pending_exit = None;
            true
        } else {
            false
        }
    }

    fn exit_authorized(&self) -> bool {
        self.lock().exit_authorized
    }
}

pub(crate) fn setup(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    if !app.manage(AppLifecycleState::default()) {
        return Err("desktop lifecycle state was already initialized".into());
    }

    let show = MenuItem::with_id(app, MENU_SHOW, "Show MagicTools", true, None::<&str>)?;
    let launch_profiles = MenuItem::with_id(
        app,
        MENU_LAUNCH_PROFILES,
        "Open Launch Profiles",
        true,
        None::<&str>,
    )?;
    let settings = MenuItem::with_id(app, MENU_SETTINGS, "Open Settings", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, MENU_QUIT, "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &launch_profiles, &settings, &quit])?;
    let icon = app
        .default_window_icon()
        .cloned()
        .ok_or("the configured application icon is unavailable")?;

    TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon)
        .menu(&menu)
        .show_menu_on_left_click(false)
        .tooltip("MagicTools")
        .on_menu_event(handle_tray_menu_event)
        .on_tray_icon_event(|tray, event| {
            if matches!(
                event,
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                }
            ) {
                show_main_window(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

#[tauri::command]
pub(crate) fn desktop_lifecycle_snapshot(
    lifecycle: State<'_, AppLifecycleState>,
) -> LifecycleSnapshot {
    lifecycle.snapshot()
}

#[tauri::command]
pub(crate) fn desktop_acknowledge_navigation(
    request: NonceRequest,
    lifecycle: State<'_, AppLifecycleState>,
) -> bool {
    lifecycle.acknowledge_navigation(&request.nonce)
}

#[tauri::command]
pub(crate) fn desktop_complete_exit(
    request: NonceRequest,
    app: AppHandle,
    lifecycle: State<'_, AppLifecycleState>,
) -> bool {
    if !lifecycle.authorize_exit(&request.nonce) {
        return false;
    }
    app.exit(0);
    true
}

#[tauri::command]
pub(crate) fn desktop_cancel_exit(
    request: NonceRequest,
    lifecycle: State<'_, AppLifecycleState>,
) -> bool {
    lifecycle.cancel_exit(&request.nonce)
}

pub(crate) fn handle_run_event(app: &AppHandle, event: RunEvent) {
    match event {
        RunEvent::WindowEvent {
            label,
            event: WindowEvent::CloseRequested { api, .. },
            ..
        } => {
            api.prevent_close();
            if let Some(window) = app.get_webview_window(&label) {
                let _ = window.hide();
            }
        }
        RunEvent::ExitRequested { api, .. } => {
            let Some(lifecycle) = app.try_state::<AppLifecycleState>() else {
                api.prevent_exit();
                return;
            };
            if lifecycle.exit_authorized() {
                return;
            }
            api.prevent_exit();
            let _ = request_exit(app, &lifecycle, ExitRequestSource::System);
        }
        _ => {}
    }
}

fn handle_tray_menu_event(app: &AppHandle, event: tauri::menu::MenuEvent) {
    match event.id().as_ref() {
        MENU_SHOW => show_main_window(app),
        MENU_LAUNCH_PROFILES => request_navigation(app, DesktopRoute::LaunchProfiles),
        MENU_SETTINGS => request_navigation(app, DesktopRoute::Settings),
        MENU_QUIT => {
            if let Some(lifecycle) = app.try_state::<AppLifecycleState>() {
                let _ = request_exit(app, &lifecycle, ExitRequestSource::Tray);
            }
        }
        _ => {}
    }
}

fn request_navigation(app: &AppHandle, route: DesktopRoute) {
    let Some(lifecycle) = app.try_state::<AppLifecycleState>() else {
        return;
    };
    let request = lifecycle.begin_navigation(route);
    show_main_window(app);
    let _ = app.emit(NAVIGATE_EVENT, request);
}

fn request_exit(
    app: &AppHandle,
    lifecycle: &AppLifecycleState,
    source: ExitRequestSource,
) -> Result<(), String> {
    let request = lifecycle.begin_exit(source);
    let Some(request) = request else {
        return Ok(());
    };
    show_main_window(app);
    app.emit(EXIT_EVENT, request)
        .map_err(|_| "failed to emit the desktop exit request".to_owned())
}

fn show_main_window(app: &AppHandle) {
    let Some(window) = app.get_webview_window(MAIN_WINDOW_LABEL) else {
        return;
    };
    let _ = window.show();
    let _ = window.unminimize();
    let _ = window.set_focus();
}

fn generate_nonce() -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let random = protocol::new_client_hello().client_nonce;
    let mut nonce = String::with_capacity(NONCE_HEX_BYTES);
    for byte in random {
        nonce.push(char::from(HEX[usize::from(byte >> 4)]));
        nonce.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    nonce
}

fn valid_nonce(value: &str) -> bool {
    value.len() == NONCE_HEX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
