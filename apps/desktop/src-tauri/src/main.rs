// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    load_env_for_oauth_config();
    appsdesktop::run();
}

fn load_env_for_oauth_config() {
    #[cfg(debug_assertions)]
    if let Err(e) = dotenvy::dotenv() {
        // Using eprintln as tracing might not be initialized yet.
        eprintln!("[WARN] Failed to load .env file: {e}");
    }
}
